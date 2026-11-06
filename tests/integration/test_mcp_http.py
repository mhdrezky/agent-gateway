"""``/mcp`` over Streamable HTTP inside the gateway: a real MCP client, per-request agent auth."""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import httpx2
from fastapi import FastAPI
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, TextContent

from agent_gateway.apps.api_server.app import create_app
from tests.world import World

BASE = "http://127.0.0.1:8080"


@asynccontextmanager
async def running(world: World) -> AsyncIterator[FastAPI]:
    """The app with its lifespan (the MCP session manager) running.

    Entered inside each test, not in a fixture: the session manager's cancel scope must
    be entered and exited in the same task.
    """
    application = create_app(world.gateway, manage_lifecycle=False)
    async with application.router.lifespan_context(application):
        yield application


@asynccontextmanager
async def mcp_session(app: FastAPI, token: str) -> AsyncIterator[ClientSession]:
    http = httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url=BASE,
        headers={"Authorization": f"Bearer {token}"},
    )
    async with (
        http,
        streamable_http_client(f"{BASE}/mcp", http_client=http) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session


async def call(session: ClientSession, tool: str, args: dict[str, Any]) -> Any:
    result = await session.call_tool(tool, args)
    assert isinstance(result, CallToolResult)
    assert not result.is_error
    [item] = result.content
    assert isinstance(item, TextContent)
    return json.loads(item.text)


async def test_agent_runs_actions_over_http_mcp(world: World) -> None:
    async with running(world) as app:
        async with mcp_session(app, world.agent_token) as session:
            tools = {t.name for t in (await session.list_tools()).tools}
            assert tools == {"list_actions", "list_resources", "execute_action", "get_execution"}

            actions = await call(session, "list_actions", {})
            assert "fake.echo" in [a["id"] for a in actions["actions"]]
            resources = await call(session, "list_resources", {})
            assert [r["id"] for r in resources["resources"]] == [world.resource_id]
            assert "attributes" not in resources["resources"][0]

            execution = await call(
                session,
                "execute_action",
                {
                    "action": "fake.echo",
                    "resource_id": world.resource_id,
                    "params": {"message": "hi"},
                },
            )
            assert execution["status"] == "succeeded"
            assert execution["agent_id"] == world.agent_id
            assert execution["result"]["data"] == {"message": "hi"}

            fetched = await call(session, "get_execution", {"execution_id": execution["id"]})
            assert fetched["id"] == execution["id"]
        ctx, _ = world.fake.calls[0]
        assert ctx.agent_id == world.agent_id


async def test_gateway_errors_come_back_as_data(world: World) -> None:
    async with running(world) as app:
        async with mcp_session(app, world.agent_token) as session:
            missing = await call(
                session,
                "execute_action",
                {"action": "fake.rm_rf", "resource_id": world.resource_id},
            )
            assert missing["error"]["code"] == "action_not_found"
            bad = await call(session, "list_resources", {"type": "spaceship"})
            assert bad["error"]["code"] == "invalid_params"
        assert world.fake.calls == []


async def test_each_request_acts_as_its_own_agent(world: World) -> None:
    async with running(world) as app:
        async with mcp_session(app, world.agent_token) as session:
            execution = await call(
                session,
                "execute_action",
                {
                    "action": "fake.echo",
                    "resource_id": world.resource_id,
                    "params": {"message": "x"},
                },
            )
        async with mcp_session(app, world.other_token) as session:
            other = await call(session, "get_execution", {"execution_id": execution["id"]})
        assert other["error"]["code"] == "execution_not_found"


async def _post_mcp(app: FastAPI, headers: dict[str, str]) -> httpx.Response:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client:
        return await client.post(
            "/mcp",
            json=body,
            headers={"Accept": "application/json, text/event-stream", **headers},
        )


async def test_missing_or_bad_token_is_401(world: World) -> None:
    async with running(world) as app:
        for headers in ({}, {"Authorization": "Bearer agw_tok_nope_x"}):
            response = await _post_mcp(app, headers)
            assert response.status_code == 401
            assert response.json()["error"]["code"] == "unauthenticated"


async def test_admin_token_is_refused(world: World) -> None:
    async with running(world) as app:
        response = await _post_mcp(app, {"Authorization": f"Bearer {world.admin_token}"})
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "action_not_allowed"


async def test_unknown_host_header_is_refused(world: World) -> None:
    """DNS rebinding guard: a page on evil.example cannot reach the local /mcp."""
    async with running(world) as app:
        response = await _post_mcp(
            app, {"Authorization": f"Bearer {world.agent_token}", "Host": "evil.example"}
        )
        assert response.status_code in (400, 403, 421)
        assert world.fake.calls == []
