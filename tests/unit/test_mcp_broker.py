"""MCP broker: resource attributes, tool params, results, and the SDK client against the fixture."""

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from agent_gateway.brokers.mcp import McpBroker
from agent_gateway.brokers.mcp.broker import tool_result
from agent_gateway.brokers.mcp.client import ToolCallOutput
from agent_gateway.brokers.mcp.models import McpServerAttributes, params_model, schema_problems
from agent_gateway.common.errors import InvalidParamsError
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.modules.catalog.diff import merge_tools
from agent_gateway.modules.catalog.models import CatalogSnapshot, ToolSpec
from agent_gateway.modules.catalog.ports import SourceUnavailableError
from agent_gateway.modules.credentials.models import REDACTED, CredentialType, SecretPayload
from agent_gateway.modules.resources.models import Resource, ResourceType
from tests.fixtures.mcp_fixture import FixtureServer
from tests.unit.broker_support import make_ctx

URL = "http://fixture.internal/mcp"
TOKEN = "fixture-bearer-token-123"
SCHEMA = {
    "type": "object",
    "properties": {"order_id": {"type": "string", "minLength": 1}, "n": {"type": "integer"}},
    "required": ["order_id"],
    "additionalProperties": False,
}


@pytest.mark.parametrize(
    "url",
    ["http://mcp.internal:8765/mcp", "https://tools.example.com/api/mcp", "http://10.0.0.5/mcp"],
)
def test_server_attributes_accept_http_urls(url: str) -> None:
    attrs = McpServerAttributes.model_validate({"url": url})
    assert attrs.transport == "streamable_http"
    assert attrs.timeout_seconds == 30


@pytest.mark.parametrize(
    "attrs",
    [
        {"url": "ftp://x/mcp"},
        {"url": "http://user:pw@x/mcp"},
        {"url": "http://x/mcp\nHost: evil"},
        {"url": "http://x/mcp", "transport": "stdio"},
        {"url": "http://x/mcp", "headers": {"a": "b"}},
        {"url": "http://x/mcp", "timeout_seconds": 90},
    ],
)
def test_server_attributes_refuse_the_rest(attrs: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        McpServerAttributes.model_validate(attrs)


def test_tool_params_follow_the_server_schema() -> None:
    model = params_model("mcp.desk.lookup_order", SCHEMA)
    assert model.model_json_schema() == SCHEMA
    params = model.model_validate({"order_id": "A-1", "n": 2})
    assert params.model_dump(mode="json") == {"order_id": "A-1", "n": 2}
    # A stored execution validates again from its dumped params.
    assert model.model_validate(params.model_dump(mode="json")).arguments == params.arguments
    assert model.model_config.get("extra") == "forbid"


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ({}, "params: 'order_id' is a required property"),
        ({"order_id": ""}, "order_id: does not satisfy 'minLength'"),
        ({"order_id": "x", "n": "secret-value"}, "n: does not satisfy 'type'"),
        ({"order_id": "x", "zzz-injected": 1}, "params: does not satisfy 'additionalProperties'"),
    ],
)
def test_tool_param_errors_never_echo_values(arguments: dict[str, Any], expected: str) -> None:
    problems = schema_problems(SCHEMA, arguments)
    assert problems == [expected]
    assert "secret-value" not in str(problems)
    assert "zzz-injected" not in str(problems)


def tools_snapshot(schema: dict[str, Any]) -> CatalogSnapshot:
    tools = merge_tools(
        None, "desk", [ToolSpec(name="lookup_order", input_schema=schema, annotations=None)]
    )
    return CatalogSnapshot(
        id="res_fixture",
        resource_type=ResourceType.MCP_SERVER,
        resource_name="desk",
        snapshot_id="snap_1",
        synced_at=datetime(2026, 11, 10, tzinfo=UTC),
        tools=tuple(tools.items),
    )


def test_actions_are_bound_to_their_resource() -> None:
    [action] = McpBroker().actions_for(tools_snapshot(SCHEMA))
    definition = action.definition
    assert definition.id == "mcp.desk.lookup_order"
    assert definition.bound_resource == "res_fixture"
    assert definition.resource_type is ResourceType.MCP_SERVER
    assert definition.risk is RiskLevel.HIGH  # no annotation: a destructive write
    assert definition.read_only is False
    assert definition.params_schema() == SCHEMA


def test_registry_reports_tool_param_errors_as_invalid_params() -> None:
    broker = McpBroker()
    registry = InMemoryActionRegistry()
    registry.replace_group("catalog:x", broker.actions_for(tools_snapshot(SCHEMA)))
    with pytest.raises(InvalidParamsError, match=r"does not satisfy 'type'"):
        registry.validate_params("mcp.desk.lookup_order", {"order_id": 5})


def test_invalid_server_schema_refuses_every_call() -> None:
    assert schema_problems({"type": "no-such-type"}, {}) == ["the tool's input schema is invalid"]


def _ctx(credential: SecretPayload | None = None, limit: int = 65536) -> Any:
    return make_ctx(ResourceType.MCP_SERVER, {"url": URL}, credential, output_limit_bytes=limit)


def test_result_keeps_text_and_structured_content() -> None:
    result = tool_result(
        _ctx(), ToolCallOutput(is_error=False, texts=["hi"], other=["image"], structured={"a": 1})
    )
    assert result.ok
    assert result.data == {"content": ["hi"], "other_content": ["image"], "structured": {"a": 1}}
    assert not result.truncated


def test_result_is_cut_to_the_output_limit() -> None:
    big = ToolCallOutput(is_error=False, texts=["x" * 5000], structured={"blob": "y" * 5000})
    result = tool_result(_ctx(limit=1024), big)
    assert result.truncated
    assert "structured" not in result.data
    assert len(result.data["content"][0]) <= 1024


def test_tool_errors_are_failed_results() -> None:
    result = tool_result(_ctx(), ToolCallOutput(is_error=True, texts=["order x not found"]))
    assert not result.ok
    assert result.error == "the tool reported an error: order x not found"


def test_tool_output_redacts_the_bearer_token() -> None:
    credential = SecretPayload(CredentialType.API_TOKEN, TOKEN)
    result = tool_result(_ctx(credential), ToolCallOutput(is_error=False, texts=[f"token={TOKEN}"]))
    assert result.data["content"] == [f"token={REDACTED}"]


def _resource(**attrs: Any) -> Resource:
    return Resource(
        id="res_fixture",
        type=ResourceType.MCP_SERVER,
        name="desk",
        attributes={"url": URL, **attrs},
    )


async def test_read_lists_tools_with_annotations() -> None:
    fixture = FixtureServer()
    broker = McpBroker(http_client=fixture.http_client)
    found = await broker.read(_resource(), None)
    tools = {t.name: t for t in found.tools or ()}
    assert set(tools) == {"lookup_order", "list_queues", "create_ticket", "ping_raw"}
    assert tools["lookup_order"].annotations == {"readOnlyHint": True}
    assert tools["create_ticket"].annotations == {"readOnlyHint": False, "destructiveHint": False}
    assert tools["ping_raw"].annotations is None
    assert tools["lookup_order"].input_schema["required"] == ["order_id"]


async def test_read_sends_the_bearer_token() -> None:
    fixture = FixtureServer(token=TOKEN)
    broker = McpBroker(http_client=fixture.http_client)
    with pytest.raises(SourceUnavailableError, match="could not reach the MCP server"):
        await broker.read(_resource(), None)
    found = await broker.read(_resource(), SecretPayload(CredentialType.API_TOKEN, TOKEN))
    assert found.tools


async def test_read_refuses_a_credential_of_another_type() -> None:
    broker = McpBroker(http_client=FixtureServer().http_client)
    with pytest.raises(SourceUnavailableError, match="must be an api_token"):
        await broker.read(_resource(), SecretPayload(CredentialType.BASIC_AUTH, "pw"))
