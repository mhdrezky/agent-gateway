"""Read the tables of a ``sql_database`` resource for its catalog (SPEC §11.6, `agw sync`).

Runs as the resource's own login in a read-only session, and lists only the tables, views,
and materialised views of ``schema_name`` that this login may ``SELECT`` (the whole relation,
or some of its columns), with only the columns it may select: the catalog is what an admin
can usefully grant, and never names a column the login cannot read. Names that are not
plain lower-case identifiers are left out, because ``allowed_tables`` cannot hold them.

The engine is picked from ``attributes.engine``. Only PostgreSQL exists today; T-SQL gets
its own ``Introspector`` in ``INTROSPECTORS`` (e.g. from ``INFORMATION_SCHEMA.COLUMNS`` and
``sys.extended_properties``) next to its gate dialect and driver.
"""

import asyncio
import logging
import re
from collections.abc import Callable, Mapping
from typing import Any

import psycopg
from pydantic import ValidationError

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.sql.models import IDENTIFIER_PATTERN, SqlDatabaseAttributes
from agent_gateway.brokers.sql.runner import connect_read_only, database_error
from agent_gateway.modules.catalog.models import CatalogColumn, CatalogTable, SourceCatalog
from agent_gateway.modules.catalog.ports import SourceUnavailableError
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.resources.models import Resource, ResourceType

log = logging.getLogger(__name__)

_IDENTIFIER = re.compile(IDENTIFIER_PATTERN)

# Tables (ordinary, partitioned parents, foreign), views, and materialised views; never
# partitions on their own. A relation counts when the login may SELECT it, or at least one
# of its columns (a column-level grant, e.g. every column but a password hash); only the
# columns it may SELECT are listed, so a withheld column never shows up. One row per
# column; a relation without visible columns has one NULL row.
POSTGRES_COLUMNS = """
SELECT c.relname,
       coalesce(obj_description(c.oid, 'pg_class'), ''),
       a.attname,
       format_type(a.atttypid, a.atttypmod),
       NOT a.attnotnull,
       coalesce(col_description(c.oid, a.attnum), '')
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_attribute a
       ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
      AND has_column_privilege(c.oid, a.attnum, 'SELECT')
WHERE n.nspname = %s
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND NOT c.relispartition
  AND (has_table_privilege(c.oid, 'SELECT') OR has_any_column_privilege(c.oid, 'SELECT'))
ORDER BY c.relname, a.attnum
"""

type Introspector = Callable[[SqlDatabaseAttributes, str], list[CatalogTable]]


def tables_from_rows(rows: list[tuple[Any, ...]]) -> list[CatalogTable]:
    """Group ``POSTGRES_COLUMNS`` rows into tables, skipping names a grant cannot hold."""
    tables: dict[str, tuple[str, list[CatalogColumn]]] = {}
    skipped: set[str] = set()
    for name, comment, column, type_, nullable, column_comment in rows:
        if not _IDENTIFIER.fullmatch(name):
            skipped.add(name)
            continue
        _, columns = tables.setdefault(name, (comment, []))
        if column is not None:
            columns.append(
                CatalogColumn(
                    name=column, type=type_, nullable=bool(nullable), comment=column_comment
                )
            )
    if skipped:
        log.info("sql catalog: %d table(s) with names allowed_tables cannot hold", len(skipped))
    return [
        CatalogTable(name=name, comment=comment, columns=tuple(columns))
        for name, (comment, columns) in sorted(tables.items())
    ]


def postgres_tables(attrs: SqlDatabaseAttributes, password: str) -> list[CatalogTable]:
    conn = connect_read_only(attrs, password)
    with conn, conn.cursor() as cur:
        try:
            cur.execute(POSTGRES_COLUMNS, (attrs.schema_name,))
            rows = cur.fetchall()
        except psycopg.Error as exc:
            raise BrokerError(database_error(exc, password)) from exc
    return tables_from_rows(rows)


INTROSPECTORS: Mapping[str, Introspector] = {"postgres": postgres_tables}


class SqlCatalogSource:
    """``CatalogSource`` for ``sql_database``: tables and columns of the resource's schema."""

    def __init__(self, introspectors: Mapping[str, Introspector] | None = None) -> None:
        self._introspectors = dict(introspectors or INTROSPECTORS)

    @property
    def resource_type(self) -> ResourceType:
        return ResourceType.SQL_DATABASE

    async def read(self, resource: Resource, credential: SecretPayload | None) -> SourceCatalog:
        try:
            attrs = SqlDatabaseAttributes.model_validate(resource.attributes)
        except ValidationError:
            raise SourceUnavailableError("sql_database resource attributes are invalid") from None
        if credential is None or credential.type is not CredentialType.BASIC_AUTH:
            raise SourceUnavailableError("sql_database resource needs a basic_auth credential")
        introspect = self._introspectors.get(attrs.engine)
        if introspect is None:
            raise SourceUnavailableError(f"no catalog reader for engine {attrs.engine}")
        try:
            tables = await asyncio.to_thread(introspect, attrs, credential.reveal())
        except BrokerError as exc:
            raise SourceUnavailableError(str(exc)) from None
        return SourceCatalog(tables=tuple(tables))
