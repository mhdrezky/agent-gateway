"""SQL broker: ``sql.query`` of SPEC §11.4.

Every query passes the gate before a connection is opened. The session is
read-only with a statement timeout, as the resource's own database login.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Any, cast

from pydantic import BaseModel, ValidationError

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.brokers.output import BrokerError, redact, run_safely, secret_fragments
from agent_gateway.brokers.sql.gate import gate
from agent_gateway.brokers.sql.models import QueryParams, SqlDatabaseAttributes
from agent_gateway.brokers.sql.runner import PsycopgRunner, QueryOutput, SqlRunner
from agent_gateway.modules.action_registry.decorators import action, collect_actions
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.credentials.models import CredentialType
from agent_gateway.modules.resources.models import ResourceType


def database_attributes(ctx: ActionContext) -> SqlDatabaseAttributes:
    if ctx.resource.type is not ResourceType.SQL_DATABASE:
        raise BrokerError("resource is not a sql_database")
    try:
        return SqlDatabaseAttributes.model_validate(ctx.resource.attributes)
    except ValidationError as exc:
        raise BrokerError("sql_database resource attributes are invalid") from exc


def database_password(ctx: ActionContext) -> str:
    credential = ctx.credential
    if credential is None or credential.type is not CredentialType.BASIC_AUTH:
        raise BrokerError("sql_database resource needs a basic_auth credential")
    return credential.reveal()


def _json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _redact_value(value: Any, fragments: Sequence[str]) -> Any:
    if isinstance(value, str):
        return redact(value, fragments)
    if isinstance(value, list):
        return [_redact_value(item, fragments) for item in value]
    if isinstance(value, dict):
        return {k: _redact_value(v, fragments) for k, v in cast(dict[str, Any], value).items()}
    return value


def query_result(ctx: ActionContext, output: QueryOutput, cap: int) -> ActionResult:
    """Drop the probe row, redact credential values, and keep whole rows within the limit."""
    secrets = ctx.credential.secret_values() if ctx.credential is not None else []
    fragments = secret_fragments(secrets)
    limited = len(output.rows) > cap
    columns = [redact(name, fragments) for name in output.columns]
    candidates = [_redact_value(row, fragments) for row in output.rows[:cap]]

    # Sized with the widest row_count so the final document cannot outgrow the budget.
    budget = ctx.output_limit_bytes - _json_size(
        {"columns": columns, "rows": [], "row_count": cap, "limited": limited}
    )
    rows: list[list[Any]] = []
    for row in candidates:
        size = _json_size(row) + (1 if rows else 0)
        if size > budget:
            break
        budget -= size
        rows.append(row)
    data = {"columns": columns, "rows": rows, "row_count": len(rows), "limited": limited}
    return ActionResult(ok=True, data=data, truncated=len(rows) < len(candidates))


class SqlBroker:
    def __init__(self, runner: SqlRunner | None = None) -> None:
        self._runner = runner or PsycopgRunner()

    @property
    def name(self) -> str:
        return "sql"

    def resource_attribute_models(self) -> Mapping[ResourceType, type[BaseModel]]:
        return {ResourceType.SQL_DATABASE: SqlDatabaseAttributes}

    def register(self, registry: ActionRegistry) -> None:
        for registered in collect_actions(self):
            registry.register(registered)

    @action(
        id="sql.query",
        resource_type=ResourceType.SQL_DATABASE,
        risk=RiskLevel.LOW,
        description=(
            "Run one read-only SELECT on the database. Only tables in the resource's "
            "allowed_tables may be referenced. Returns columns and rows; at most row_cap rows, "
            "and limited is true when there were more (aggregate in SQL instead)."
        ),
        input_model=QueryParams,
        read_only=True,
    )
    async def query(self, ctx: ActionContext, params: QueryParams) -> ActionResult:
        async def body() -> ActionResult:
            attrs = database_attributes(ctx)
            gated = gate(
                params.sql, attrs.schema_name, frozenset(attrs.allowed_tables), attrs.row_cap
            )
            output = await self._runner.run(attrs, database_password(ctx), gated.sql)
            return query_result(ctx, output, gated.cap)

        return await run_safely(ctx, "sql.query", body)
