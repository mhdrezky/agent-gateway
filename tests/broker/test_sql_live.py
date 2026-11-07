"""SQL broker against a real Postgres container. See README.md in this folder."""

import os
from typing import Any

import pytest

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.sql import SqlBroker
from agent_gateway.brokers.sql.models import QueryParams, SqlDatabaseAttributes
from agent_gateway.brokers.sql.runner import PsycopgRunner
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.resources.models import ResourceType
from tests.unit.broker_support import make_ctx

pytestmark = pytest.mark.broker

REQUIRED = ["AGW_TEST_SQL_HOST", "AGW_TEST_SQL_PORT"]
# Fixed by tests/broker/sql/init.sql.
READER = "agw_reader"
READER_PASSWORD = "reader-pa55-for-tests"


@pytest.fixture
def env() -> dict[str, str]:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        pytest.skip(f"missing {', '.join(missing)}")
    return {name: os.environ[name] for name in REQUIRED}


def _attributes(env: dict[str, str], **overrides: Any) -> dict[str, Any]:
    return {
        "host": env["AGW_TEST_SQL_HOST"],
        "port": int(env["AGW_TEST_SQL_PORT"]),
        "dbname": "sales",
        "username": READER,
        "schema_name": "sample",
        "allowed_tables": ["product"],
        "row_cap": 10,
        "sslmode": "disable",
        **overrides,
    }


def _ctx(env: dict[str, str], password: str = READER_PASSWORD, **overrides: Any) -> Any:
    credential = SecretPayload(CredentialType.BASIC_AUTH, password)
    return make_ctx(ResourceType.SQL_DATABASE, _attributes(env, **overrides), credential)


async def _query(env: dict[str, str], sql: str, **overrides: Any) -> Any:
    return await SqlBroker().query(_ctx(env, **overrides), QueryParams(sql=sql))


async def test_rows_are_json_safe(env: dict[str, str]) -> None:
    result = await _query(
        env, "SELECT id, name, price, added_on, tags, attrs FROM product ORDER BY id LIMIT 2"
    )
    assert result.ok, result.error
    assert result.data == {
        "columns": ["id", "name", "price", "added_on", "tags", "attrs"],
        "rows": [
            [1, "product 1", 1.25, "2026-01-02", ["t1"], {"n": 1}],
            [2, "product 2", 2.5, "2026-01-03", ["t2"], {"n": 2}],
        ],
        "row_count": 2,
        "limited": False,
    }


async def test_row_cap_sets_limited(env: dict[str, str]) -> None:
    result = await _query(env, "SELECT id FROM product ORDER BY id")
    assert result.ok, result.error
    assert result.data["row_count"] == 10
    assert result.data["rows"][-1] == [10]
    assert result.data["limited"] is True


async def test_aggregate_is_not_limited(env: dict[str, str]) -> None:
    result = await _query(env, "SELECT count(*) AS n FROM product")
    assert result.ok, result.error
    assert result.data["rows"] == [[25]]
    assert result.data["limited"] is False


async def test_tables_are_pinned_to_the_resource_schema(env: dict[str, str]) -> None:
    # public.product holds a decoy row; the gate rewrites product to sample.product.
    result = await _query(env, "SELECT name FROM product WHERE id = 1")
    assert result.data["rows"] == [["product 1"]]


async def test_gate_denies_table_outside_allowlist(env: dict[str, str]) -> None:
    result = await _query(env, "SELECT email FROM customer")
    assert not result.ok
    assert result.error is not None
    assert "'customer' not in your allowed set" in result.error


async def test_database_error_is_reported_safely(env: dict[str, str]) -> None:
    result = await _query(env, "SELECT no_such_column FROM product")
    assert result.error == 'database error 42703: column "no_such_column" does not exist'


async def test_wrong_password_is_a_generic_connect_error(env: dict[str, str]) -> None:
    result = await _query(env, "SELECT id FROM product", password="wrong-password-123")
    assert result.error == "could not connect to the database"
    assert "wrong-password" not in result.model_dump_json()


async def test_session_is_read_only_without_the_gate(env: dict[str, str]) -> None:
    # The reader login may INSERT; the session must refuse it anyway.
    attrs = SqlDatabaseAttributes.model_validate(_attributes(env))
    with pytest.raises(BrokerError, match=r"^database error 25006: cannot execute INSERT"):
        await PsycopgRunner().run(
            attrs,
            READER_PASSWORD,
            "INSERT INTO sample.product (id, name, price, added_on) VALUES (99, 'x', 1, now())",
        )


async def test_statement_timeout_cancels_the_query(env: dict[str, str]) -> None:
    attrs = SqlDatabaseAttributes.model_validate(_attributes(env, statement_timeout_ms=200))
    with pytest.raises(BrokerError, match="statement timeout of 200 ms exceeded"):
        await PsycopgRunner().run(attrs, READER_PASSWORD, "SELECT pg_sleep(3)")
