import asyncio
import datetime as dt
import decimal
import json
import uuid
from typing import Any

import pytest

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.sql import SqlBroker
from agent_gateway.brokers.sql.models import QueryParams, SqlDatabaseAttributes
from agent_gateway.brokers.sql.runner import QueryOutput, jsonable
from agent_gateway.common.errors import InvalidParamsError
from agent_gateway.config import Settings
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.modules.credentials.models import REDACTED, CredentialType, SecretPayload
from agent_gateway.modules.resources.models import ResourceType
from agent_gateway.runtime import default_brokers
from tests.fakes.registry import FakeActionRegistry
from tests.unit.broker_support import make_ctx

PASSWORD = SecretPayload(CredentialType.BASIC_AUTH, "db-pa55word-very-secret")


def sql_attributes(**overrides: Any) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "host": "db.internal",
        "dbname": "sales",
        "username": "agw_reader",
        "schema_name": "sample",
        "allowed_tables": ["purchase_order", "product"],
        "row_cap": 3,
    }
    attrs.update(overrides)
    return attrs


class RecordingRunner:
    def __init__(self, output: QueryOutput | None = None, error: Exception | None = None) -> None:
        self.output = output or QueryOutput(["id"], [])
        self.error = error
        self.calls: list[tuple[SqlDatabaseAttributes, str, str]] = []

    async def run(self, attrs: SqlDatabaseAttributes, password: str, sql: str) -> QueryOutput:
        self.calls.append((attrs, password, sql))
        if self.error is not None:
            raise self.error
        return self.output


def _ctx(**kwargs: Any) -> Any:
    attrs = kwargs.pop("attrs", sql_attributes())
    return make_ctx(ResourceType.SQL_DATABASE, attrs, kwargs.pop("credential", PASSWORD), **kwargs)


async def _query(runner: RecordingRunner, sql: str, **kwargs: Any) -> Any:
    return await SqlBroker(runner).query(_ctx(**kwargs), QueryParams(sql=sql))


def test_registers_sql_query_as_low_risk() -> None:
    registry = InMemoryActionRegistry()
    SqlBroker(RecordingRunner()).register(registry)
    [registered] = registry.all()
    assert registered.definition.id == "sql.query"
    assert registered.definition.broker == "sql"
    assert registered.definition.risk is RiskLevel.LOW
    assert registered.definition.resource_type is ResourceType.SQL_DATABASE
    assert not registered.definition.privileged


def test_resource_attribute_schema() -> None:
    model = SqlBroker().resource_attribute_models()[ResourceType.SQL_DATABASE]
    parsed = model.model_validate(sql_attributes())
    assert isinstance(parsed, SqlDatabaseAttributes)
    assert parsed.engine == "postgres"
    assert parsed.port == 5432
    assert parsed.statement_timeout_ms == 15000
    with pytest.raises(ValueError, match="Extra inputs"):
        model.model_validate(sql_attributes(password="x"))
    with pytest.raises(ValueError, match="engine"):
        model.model_validate(sql_attributes(engine="mssql"))
    with pytest.raises(ValueError, match="allowed_tables"):
        model.model_validate(sql_attributes(allowed_tables=[]))
    with pytest.raises(ValueError, match="allowed_tables"):
        model.model_validate(sql_attributes(allowed_tables=["public.product"]))
    with pytest.raises(ValueError, match="host"):
        model.model_validate(sql_attributes(host="db host; rm"))
    with pytest.raises(ValueError, match="statement_timeout_ms"):
        model.model_validate(sql_attributes(statement_timeout_ms=60000))


def test_params_forbid_extra_fields() -> None:
    registry = FakeActionRegistry()
    SqlBroker().register(registry)
    assert registry.validate_params("sql.query", {"sql": "SELECT 1"}) == QueryParams(sql="SELECT 1")
    with pytest.raises(InvalidParamsError, match="Extra inputs"):
        registry.validate_params("sql.query", {"sql": "SELECT 1", "max_rows": 5})
    with pytest.raises(InvalidParamsError, match="sql"):
        registry.validate_params("sql.query", {"sql": ""})


async def test_gated_sql_and_password_reach_the_runner() -> None:
    runner = RecordingRunner(QueryOutput(["doc_no"], [["PO-1"], ["PO-2"]]))
    result = await _query(runner, "SELECT doc_no FROM purchase_order")
    assert result.ok
    assert result.data == {
        "columns": ["doc_no"],
        "rows": [["PO-1"], ["PO-2"]],
        "row_count": 2,
        "limited": False,
    }
    assert not result.truncated
    [(attrs, password, sql)] = runner.calls
    assert attrs.dbname == "sales"
    assert password == PASSWORD.reveal()
    assert sql == "SELECT * FROM (SELECT doc_no FROM sample.purchase_order) AS q LIMIT 4"


async def test_probe_row_sets_limited_and_is_dropped() -> None:
    runner = RecordingRunner(QueryOutput(["id"], [[1], [2], [3], [4]]))
    result = await _query(runner, "SELECT id FROM product")
    assert result.ok
    assert result.data["rows"] == [[1], [2], [3]]
    assert result.data["row_count"] == 3
    assert result.data["limited"] is True
    assert not result.truncated


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM product",
        "SELECT * FROM customer",
        "SELECT 1 FROM product; SELECT 2 FROM product",
        "SELECT pg_sleep(10) FROM product",
    ],
)
async def test_denied_query_never_reaches_the_database(sql: str) -> None:
    runner = RecordingRunner()
    result = await _query(runner, sql)
    assert not result.ok
    assert result.error
    assert runner.calls == []


async def test_denial_names_the_allowed_tables() -> None:
    result = await _query(RecordingRunner(), "SELECT * FROM customer")
    assert result.error == (
        "table 'customer' not in your allowed set. Tables you can query: product, "
        "purchase_order. Use only these — do not query, join, or reference any other table."
    )


@pytest.mark.parametrize(
    "credential",
    [
        None,
        SecretPayload(CredentialType.API_TOKEN, "tok"),
        SecretPayload(CredentialType.SSH_PRIVATE_KEY, "k"),
    ],
)
async def test_needs_basic_auth_credential(credential: SecretPayload | None) -> None:
    runner = RecordingRunner()
    result = await _query(runner, "SELECT id FROM product", credential=credential)
    assert result.error == "sql_database resource needs a basic_auth credential"
    assert runner.calls == []


async def test_invalid_resource_attributes() -> None:
    runner = RecordingRunner()
    result = await _query(runner, "SELECT id FROM product", attrs={"host": "x"})
    assert result.error == "sql_database resource attributes are invalid"
    assert runner.calls == []


async def test_wrong_resource_type() -> None:
    ctx = make_ctx(ResourceType.SSH_HOST, sql_attributes(), PASSWORD)
    result = await SqlBroker(RecordingRunner()).query(ctx, QueryParams(sql="SELECT 1"))
    assert result.error == "resource is not a sql_database"


async def test_output_redacts_password() -> None:
    secret = PASSWORD.reveal()
    runner = RecordingRunner(
        QueryOutput([f"col_{secret}"], [[f"value {secret}"], [{"nested": [secret]}]])
    )
    result = await _query(runner, "SELECT id FROM product")
    dumped = result.model_dump_json()
    assert secret not in dumped
    assert result.data["rows"][0] == [f"value {REDACTED}"]
    assert result.data["rows"][1] == [{"nested": [REDACTED]}]


async def test_rows_dropped_to_fit_output_limit() -> None:
    rows = [["x" * 600] for _ in range(10)]
    runner = RecordingRunner(QueryOutput(["blob"], rows))
    attrs = sql_attributes(row_cap=10)
    result = await _query(runner, "SELECT id FROM product", attrs=attrs, output_limit_bytes=2048)
    assert result.ok
    assert result.truncated
    assert result.data["limited"] is False
    assert result.data["row_count"] == len(result.data["rows"]) == 3
    size = len(json.dumps(result.data, ensure_ascii=False, separators=(",", ":")).encode())
    assert size <= 2048


async def test_single_row_larger_than_limit_returns_no_rows() -> None:
    runner = RecordingRunner(QueryOutput(["blob"], [["y" * 5000]]))
    result = await _query(runner, "SELECT id FROM product", output_limit_bytes=1024)
    assert result.ok
    assert result.truncated
    assert result.data["rows"] == []
    assert result.data["row_count"] == 0


async def test_runner_error_message_is_safe() -> None:
    runner = RecordingRunner(error=BrokerError("could not connect to the database"))
    result = await _query(runner, "SELECT id FROM product")
    assert not result.ok
    assert result.error == "could not connect to the database"
    assert result.data == {}


async def test_unexpected_error_is_wrapped(caplog: pytest.LogCaptureFixture) -> None:
    runner = RecordingRunner(error=RuntimeError("host=db password=db-pa55word-very-secret"))
    result = await _query(runner, "SELECT id FROM product")
    assert result.error == "sql.query failed"
    assert "db-pa55word" not in result.model_dump_json()
    assert "RuntimeError" in caplog.text


async def test_timeout() -> None:
    class SlowRunner(RecordingRunner):
        async def run(self, attrs: SqlDatabaseAttributes, password: str, sql: str) -> QueryOutput:
            await asyncio.sleep(5)
            return self.output

    ctx = _ctx(timeout_seconds=1)
    broker = SqlBroker(SlowRunner())
    result = await asyncio.wait_for(broker.query(ctx, QueryParams(sql="SELECT id FROM product")), 3)
    assert result.error == "sql.query timed out"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (True, True),
        (7, 7),
        ("text", "text"),
        (1.5, 1.5),
        (float("nan"), "nan"),
        (float("inf"), "inf"),
        (decimal.Decimal("12.00"), 12),
        (decimal.Decimal("12.50"), 12.5),
        (decimal.Decimal("NaN"), "NaN"),
        (dt.date(2026, 11, 7), "2026-11-07"),
        (dt.datetime(2026, 11, 7, 12, 0, tzinfo=dt.UTC), "2026-11-07T12:00:00+00:00"),
        (dt.time(8, 30), "08:30:00"),
        (dt.timedelta(hours=2), "2:00:00"),
        (uuid.UUID(int=1), "00000000-0000-0000-0000-000000000001"),
        (b"\xde\xad", "\\xdead"),
        (memoryview(b"\x01"), "\\x01"),
        ([decimal.Decimal("1"), None], [1, None]),
        ({"a": [dt.date(2026, 1, 2)]}, {"a": ["2026-01-02"]}),
    ],
)
def test_jsonable(value: Any, expected: Any) -> None:
    assert jsonable(value) == expected


def test_sql_broker_is_off_by_default() -> None:
    names = [broker.name for broker in default_brokers(Settings())]
    assert "sql" not in names
    enabled = Settings.model_validate({"brokers": {"sql": {"enabled": True}}})
    assert "sql" in [broker.name for broker in default_brokers(enabled)]
