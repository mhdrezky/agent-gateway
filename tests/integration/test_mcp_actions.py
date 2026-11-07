"""``/mcp/actions``: one tool per action, ``resource_id`` enum, ``ToolOutcome`` results."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import httpx2
from fastapi import FastAPI
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult

from agent_gateway.apps.api_server.mcp_actions import WRITE_META, tool_name
from agent_gateway.brokers.base import ActionResult
from agent_gateway.modules.action_registry.models import (
    ActionDefinition,
    RegisteredAction,
    RiskLevel,
)
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
)
from agent_gateway.modules.identity.models import TokenKind
from agent_gateway.modules.resources.models import ResourceType
from tests.fakes.oidc import FakeIdp
from tests.integration.test_mcp_http import BASE, mcp_session, running
from tests.integration.test_user_identity import as_user
from tests.world import NoParams, World


@asynccontextmanager
async def actions_session(app: FastAPI, token: str) -> AsyncIterator[ClientSession]:
    http = httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url=BASE,
        headers={"Authorization": f"Bearer {token}"},
    )
    async with (
        http,
        streamable_http_client(f"{BASE}/mcp/actions", http_client=http) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session


async def call(session: ClientSession, tool: str, args: dict[str, Any]) -> CallToolResult:
    result = await session.call_tool(tool, args)
    assert isinstance(result, CallToolResult)
    assert isinstance(result.structured_content, dict)
    return result


def test_tool_names_have_no_dots() -> None:
    assert tool_name("sql.query") == "sql_query"
    assert tool_name("docker.container.logs") == "docker_container_logs"


async def test_one_tool_per_action_with_a_resource_enum(world: World) -> None:
    async with running(world) as app, actions_session(app, world.agent_token) as session:
        tools = {t.name: t for t in (await session.list_tools()).tools}
    assert set(tools) == {"fake_echo", "test_leak", "test_sleep"}
    echo = tools["fake_echo"]
    assert echo.description
    schema = echo.input_schema
    assert schema["properties"]["resource_id"]["enum"] == [world.resource_id]
    assert schema["required"][0] == "resource_id"
    assert "message" in schema["properties"]


async def test_a_call_runs_the_action(world: World) -> None:
    async with running(world) as app, actions_session(app, world.agent_token) as session:
        result = await call(
            session, "fake_echo", {"resource_id": world.resource_id, "message": "hi"}
        )
    assert not result.is_error
    outcome = result.structured_content
    assert outcome is not None
    assert outcome["status"] == "ok"
    assert outcome["result"] == {"message": "hi"}
    assert outcome["execution_id"].startswith("exe_")
    ctx, _ = world.fake.calls[0]
    assert ctx.agent_id == world.agent_id


async def test_a_held_call_is_pending(approval_world: World) -> None:
    world = approval_world
    async with running(world) as app, actions_session(app, world.agent_token) as session:
        result = await call(
            session, "fake_echo", {"resource_id": world.resource_id, "message": "hi"}
        )
    assert not result.is_error
    outcome = result.structured_content
    assert outcome is not None
    assert outcome["status"] == "pending"
    assert "fake.echo" in outcome["summary"]
    assert world.fake.calls == []


async def test_a_denied_call_is_denied(world: World) -> None:
    await world.gateway.admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(agent_id=world.agent_id),
        actions=["fake.echo"],
        resources=ResourceSelector(ids=(world.resource_id,)),
        effect=PolicyEffect.DENY,
    )
    async with running(world) as app, actions_session(app, world.agent_token) as session:
        result = await call(
            session, "fake_echo", {"resource_id": world.resource_id, "message": "hi"}
        )
    assert result.is_error
    outcome = result.structured_content
    assert outcome is not None
    assert outcome["status"] == "denied"
    assert outcome["execution_id"].startswith("exe_")
    assert world.fake.calls == []


async def test_bad_calls_are_errors_without_running(world: World) -> None:
    async with running(world) as app, actions_session(app, world.agent_token) as session:
        unknown = await call(session, "fake_rm_rf", {"resource_id": world.resource_id})
        no_resource = await call(session, "fake_echo", {"message": "hi"})
        bad_params = await call(session, "fake_echo", {"resource_id": world.resource_id, "nope": 1})
    for result in (unknown, no_resource, bad_params):
        assert result.is_error
        assert result.structured_content is not None
        assert result.structured_content["status"] == "error"
    assert world.fake.calls == []


async def test_an_agent_without_roles_sees_no_tools(world: World) -> None:
    admin = world.gateway.admin
    bare = await admin.create_agent(CLI_PRINCIPAL, "bare-agent", roles=[])
    token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.AGENT, agent_id=bare.id)
    async with (
        running(world) as app,
        actions_session(app, token.plaintext.get_secret_value()) as session,
    ):
        assert (await session.list_tools()).tools == []


async def _post(app: FastAPI, headers: dict[str, str]) -> httpx.Response:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client:
        return await client.post(
            "/mcp/actions",
            json=body,
            headers={"Accept": "application/json, text/event-stream", **headers},
        )


async def test_agent_token_is_required(world: World) -> None:
    async with running(world) as app:
        missing = await _post(app, {})
        admin = await _post(app, {"Authorization": f"Bearer {world.admin_token}"})
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "unauthenticated"
    assert admin.status_code == 403
    assert admin.json()["error"]["code"] == "action_not_allowed"


async def test_meta_tools_stay_on_mcp(world: World) -> None:
    async with running(world) as app, mcp_session(app, world.agent_token) as session:
        tools = {t.name for t in (await session.list_tools()).tools}
    assert tools == {"list_actions", "list_resources", "execute_action", "get_execution"}


async def listed(app: FastAPI, headers: dict[str, str]) -> dict[str, Any]:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client:
        response = await client.post(
            "/mcp/actions",
            json=body,
            headers={"Accept": "application/json, text/event-stream", **headers},
        )
    assert response.status_code == 200, response.text
    return {tool["name"]: tool for tool in response.json()["result"]["tools"]}


def profile(tool: dict[str, Any]) -> tuple[bool, bool, bool]:
    annotations = tool["annotations"]
    return (
        annotations["readOnlyHint"],
        annotations["destructiveHint"],
        tool["_meta"][WRITE_META],
    )


async def _touch(ctx: Any, params: Any) -> ActionResult:
    return ActionResult(ok=True)


async def test_annotations_describe_reads_and_writes(world: World) -> None:
    world.gateway.registry.register(
        RegisteredAction(
            ActionDefinition(
                id="test.touch",
                broker="test",
                resource_type=ResourceType.HTTP_ENDPOINT,
                description="Change the endpoint.",
                risk=RiskLevel.LOW,
                input_model=NoParams,
            ),
            _touch,
        )
    )
    async with running(world) as app:
        tools = await listed(app, world.agent())
    assert profile(tools["fake_echo"]) == (True, False, False)
    assert profile(tools["test_leak"]) == (True, False, False)
    assert profile(tools["test_touch"]) == (False, True, False)


async def test_write_meta_marks_what_the_user_may_confirm(user_world: World, idp: FakeIdp) -> None:
    await user_world.gateway.admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(user_role="staff"),
        actions=["fake.*"],
        resources=ResourceSelector(ids=(user_world.resource_id,)),
        effect=PolicyEffect.ALLOW,
        approval=ApprovalMode.REQUESTER,
    )
    staff = as_user(user_world, idp.token("u-1", ["staff"]))
    async with running(user_world) as app:
        alone = await listed(app, user_world.agent())
        person = await listed(app, staff)
    # The requester policy is on the user side, so an agent-only call is not held.
    assert profile(alone["fake_echo"]) == (True, False, False)
    assert profile(person["fake_echo"]) == (True, False, True)


async def test_admin_approval_is_not_a_user_write(user_world: World, idp: FakeIdp) -> None:
    admin = user_world.gateway.admin
    for subject, mode in (
        (PolicySubject(user_role="staff"), ApprovalMode.REQUESTER),
        (PolicySubject(role="operator"), ApprovalMode.ALWAYS),
    ):
        await admin.create_policy(
            CLI_PRINCIPAL,
            subject=subject,
            actions=["fake.*"],
            resources=ResourceSelector(ids=(user_world.resource_id,)),
            effect=PolicyEffect.ALLOW,
            approval=mode,
        )
    staff = as_user(user_world, idp.token("u-1", ["staff"]))
    async with running(user_world) as app:
        tools = await listed(app, staff)
    assert profile(tools["fake_echo"]) == (True, False, False)


async def test_contract_version_needs_no_auth(world: World) -> None:
    response = await world.api.get("/v1/contract")
    assert response.status_code == 200
    assert response.json() == {"versions": ["agentgate-gateway/1"]}
