"""SQL broker against a real Postgres container. See README.md in this folder."""

import dataclasses
import os
from typing import Any

import psycopg
import pytest

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.sql import SqlBroker
from agent_gateway.brokers.sql.introspect import SqlCatalogSource
from agent_gateway.brokers.sql.models import QueryParams, SqlDatabaseAttributes
from agent_gateway.brokers.sql.runner import PsycopgRunner
from agent_gateway.common.clock import SystemClock
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.modules.audit.models import Actor, ActorType
from agent_gateway.modules.catalog.models import CatalogSnapshot
from agent_gateway.modules.catalog.ports import SourceUnavailableError
from agent_gateway.modules.catalog.service import CatalogService
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.modules.resources.registry import StoredResourceRegistry
from tests.fakes.audit import FakeAuditLog
from tests.fakes.credentials import FakeCredentialStore
from tests.fakes.storage import InMemoryCollection
from tests.unit.broker_support import make_ctx

CLI_ACTOR = Actor(type=ActorType.ADMIN, id="cli")

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


# ---- catalog (agw sync, SPEC §11.6) ---------------------------------------------------------

OWNER = ("agw_owner", "owner-only-for-tests")


def _resource(env: dict[str, str], **overrides: Any) -> Resource:
    return Resource(
        id="res_sample",
        type=ResourceType.SQL_DATABASE,
        name="sample",
        attributes=_attributes(env, **overrides),
    )


async def _read(env: dict[str, str], **overrides: Any) -> dict[str, Any]:
    found = await SqlCatalogSource().read(
        _resource(env, **overrides), SecretPayload(CredentialType.BASIC_AUTH, READER_PASSWORD)
    )
    return {t.name: t for t in found.tables or ()}


def _owner_sql(env: dict[str, str], sql: str) -> None:
    with psycopg.connect(
        host=env["AGW_TEST_SQL_HOST"],
        port=int(env["AGW_TEST_SQL_PORT"]),
        dbname="sales",
        user=OWNER[0],
        password=OWNER[1],
        sslmode="disable",
        autocommit=True,
    ) as conn:
        conn.execute(sql.encode())


async def test_catalog_reads_tables_columns_and_comments(env: dict[str, str]) -> None:
    tables = await _read(env)
    # Only what the reader may SELECT in the resource's schema, with names a grant can hold:
    # not public.product, not sample.hidden (no grant), not sample."MixedCase".
    assert {"product", "customer"} <= set(tables)
    assert not {"hidden", "MixedCase"} & set(tables)
    product = tables["product"]
    assert product.comment == "Products for sale"
    assert [(c.name, c.type, c.nullable, c.comment) for c in product.columns] == [
        ("id", "integer", False, ""),
        ("name", "text", False, ""),
        ("price", "numeric(10,2)", False, "Unit price"),
        ("added_on", "date", False, ""),
        ("tags", "text[]", False, ""),
        ("attrs", "jsonb", False, ""),
    ]
    assert [c.name for c in tables["customer"].columns] == ["id", "email"]


async def test_catalog_of_another_schema_is_empty(env: dict[str, str]) -> None:
    assert await _read(env, schema_name="nothing_here") == {}


async def test_catalog_read_with_a_wrong_password_is_safe(env: dict[str, str]) -> None:
    with pytest.raises(SourceUnavailableError, match=r"^could not connect to the database$"):
        await SqlCatalogSource().read(
            _resource(env), SecretPayload(CredentialType.BASIC_AUTH, "wrong-password-123")
        )


async def test_sync_flags_a_dropped_table_and_the_broker_refuses_it(env: dict[str, str]) -> None:
    _owner_sql(env, "DROP TABLE IF EXISTS sample.sync_probe")
    _owner_sql(env, "CREATE TABLE sample.sync_probe (id integer)")
    try:
        credential = SecretPayload(CredentialType.BASIC_AUTH, READER_PASSWORD)
        credentials = FakeCredentialStore()
        stored = await credentials.create("reader", credential)
        resources = StoredResourceRegistry(
            InMemoryCollection[Resource](), {ResourceType.SQL_DATABASE: SqlDatabaseAttributes}
        )
        resource = await resources.create(
            ResourceType.SQL_DATABASE,
            "sample",
            attributes=_attributes(env, allowed_tables=["product", "sync_probe"]),
            credential_id=stored.id,
        )
        catalog = CatalogService(
            snapshots=InMemoryCollection[CatalogSnapshot](),
            resources=resources,
            credentials=credentials,
            sources=[SqlCatalogSource()],
            actions=[],
            registry=InMemoryActionRegistry(),
            audit=FakeAuditLog(),
            clock=SystemClock(),
        )
        first = await catalog.sync(CLI_ACTOR, resource.id)
        assert "sync_probe" in first.snapshot.table_names()

        broker = SqlBroker(removed_tables=catalog.removed_tables)
        ctx = dataclasses.replace(
            make_ctx(ResourceType.SQL_DATABASE, resource.attributes, credential),
            resource=resource,
        )
        ok = await broker.query(ctx, QueryParams(sql="SELECT count(*) FROM sync_probe"))
        assert ok.ok, ok.error

        _owner_sql(env, "DROP TABLE sample.sync_probe")
        second = await catalog.sync(CLI_ACTOR, resource.id)
        assert second.snapshot.removed == ("sync_probe",)
        assert (await catalog.state(resource)).pending_review is True
        refused = await broker.query(ctx, QueryParams(sql="SELECT count(*) FROM sync_probe"))
        assert refused.error is not None
        assert "'sync_probe' not in your allowed set" in refused.error
    finally:
        _owner_sql(env, "DROP TABLE IF EXISTS sample.sync_probe")
