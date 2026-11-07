"""Run an already-gated read query in a short read-only PostgreSQL session.

psycopg's async mode does not work on the Windows Proactor event loop, so the
blocking driver runs in a worker thread. ``statement_timeout`` and
``connect_timeout`` bound how long that thread can live after a cancellation.
"""

import asyncio
import datetime as dt
import decimal
import logging
import math
from dataclasses import dataclass
from typing import Any, Protocol, cast

import psycopg

from agent_gateway.brokers.output import BrokerError, redact, secret_fragments
from agent_gateway.brokers.sql.models import SqlDatabaseAttributes

APPLICATION_NAME = "agent-gateway"
MAX_ERROR_LENGTH = 300

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class QueryOutput:
    columns: list[str]
    # JSON-safe values, one list per row in column order.
    rows: list[list[Any]]


class SqlRunner(Protocol):
    async def run(self, attrs: SqlDatabaseAttributes, password: str, sql: str) -> QueryOutput:
        """Run one gated query and return every row it produced."""
        ...


def jsonable(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, decimal.Decimal):
        if not value.is_finite():
            return str(value)
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dt.datetime | dt.date | dt.time):
        return value.isoformat()
    if isinstance(value, bytes | bytearray | memoryview):
        return "\\x" + bytes(value).hex()
    if isinstance(value, list | tuple):
        return [jsonable(item) for item in cast(list[Any], value)]
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    # UUID, interval, network, and range types: their text form.
    return str(value)


def database_error(exc: psycopg.Error, password: str) -> str:
    """The database's own primary message: names columns and types, never the DSN."""
    primary = exc.diag.message_primary or "unknown error"
    message = redact(primary.splitlines()[0], secret_fragments([password]))[:MAX_ERROR_LENGTH]
    return (
        f"database error {exc.sqlstate}: {message}"
        if exc.sqlstate
        else f"database error: {message}"
    )


class PsycopgRunner:
    async def run(self, attrs: SqlDatabaseAttributes, password: str, sql: str) -> QueryOutput:
        return await asyncio.to_thread(self._run, attrs, password, sql)

    @staticmethod
    def _run(attrs: SqlDatabaseAttributes, password: str, sql: str) -> QueryOutput:
        options = (
            f"-c default_transaction_read_only=on -c statement_timeout={attrs.statement_timeout_ms}"
        )
        try:
            conn = psycopg.connect(
                host=attrs.host,
                port=attrs.port,
                dbname=attrs.dbname,
                user=attrs.username,
                password=password,
                options=options,
                connect_timeout=attrs.connect_timeout_seconds,
                sslmode=attrs.sslmode,
                application_name=APPLICATION_NAME,
            )
        except psycopg.Error as exc:
            # libpq never echoes the password; the detail stays in the server log.
            log.warning(
                "sql connect to %s:%s/%s failed: %s", attrs.host, attrs.port, attrs.dbname, exc
            )
            raise BrokerError("could not connect to the database") from exc

        with conn:
            conn.read_only = True
            with conn.cursor() as cur:
                try:
                    cur.execute(sql.encode())
                    rows = cur.fetchall()
                except psycopg.errors.QueryCanceled as exc:
                    raise BrokerError(
                        "query canceled: statement timeout of "
                        f"{attrs.statement_timeout_ms} ms exceeded"
                    ) from exc
                except psycopg.Error as exc:
                    raise BrokerError(database_error(exc, password)) from exc
                columns = [column.name for column in cur.description or []]
        return QueryOutput(columns, [[jsonable(value) for value in row] for row in rows])
