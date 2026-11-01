"""MCP goes through the same REST engine (P6); restart recovery (SPEC §12)."""

import json
from typing import Any

import httpx
from mcp.types import CallToolResult, TextContent

from agent_gateway.apps.api_server.app import create_app
from agent_gateway.apps.mcp_server.client import GatewayClient
from agent_gateway.apps.mcp_server.server import build_server
from agent_gateway.modules.execution.models import ExecutionStatus
from tests.world import World


def _mcp_client(world: World, token: str) -> GatewayClient:
    app = create_app(world.gateway, manage_lifecycle=False)
    return GatewayClient(token, base_url="http://gateway", transport=httpx.ASGITransport(app=app))


def _payload(result: object) -> Any:
    assert isinstance(result, CallToolResult)
    assert not result.is_error
    assert len(result.content) == 1
    item = result.content[0]
    assert isinstance(item, TextContent)
    return json.loads(item.text)


async def test_mcp_execute_action_uses_the_engine(world: World) -> None:
    client = _mcp_client(world, world.agent_token)
    server = build_server(client)
    try:
        actions = _payload(await server.call_tool("list_actions", {}))
        assert "fake.echo" in [a["id"] for a in actions["actions"]]

        result = _payload(
            await server.call_tool(
                "execute_action",
                {
                    "action": "fake.echo",
                    "resource_id": world.resource_id,
                    "params": {"message": "via mcp"},
                },
            )
        )
        assert isinstance(result, dict)
        assert result["status"] == "succeeded"
        assert result["result"]["data"] == {"message": "via mcp"}

        fetched = _payload(await server.call_tool("get_execution", {"execution_id": result["id"]}))
        assert isinstance(fetched, dict)
        assert fetched["agent_id"] == world.agent_id
    finally:
        await client.aclose()


async def test_mcp_returns_gateway_errors_as_data(world: World) -> None:
    client = _mcp_client(world, "agw_tok_invalid_token")
    try:
        result = _payload(await build_server(client).call_tool("list_actions", {}))
        assert isinstance(result, dict)
        assert result["error"]["code"] == "unauthenticated"
    finally:
        await client.aclose()


async def test_running_execution_fails_after_restart(world: World) -> None:
    response = await world.api.post(
        "/v1/executions",
        json={"action": "fake.echo", "resource_id": world.resource_id, "params": {"message": "x"}},
        headers=world.agent(),
    )
    execution_id = response.json()["id"]
    store = world.gateway.engine._executions
    await store.update(
        execution_id, lambda e: e.model_copy(update={"status": ExecutionStatus.RUNNING})
    )

    await world.gateway.engine.recover()
    recovered = await store.get(execution_id)
    assert recovered is not None
    assert recovered.status is ExecutionStatus.FAILED
    assert recovered.error is not None
    assert recovered.error.startswith("interrupted")
