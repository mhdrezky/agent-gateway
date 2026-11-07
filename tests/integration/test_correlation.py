"""A caller's correlation id is stored on the execution and its audit events (SPEC §12)."""

from typing import Any, cast

import httpx
from mcp.types import CallToolResult, RequestParamsMeta

from agent_gateway.apps.api_server.correlation import META_CORRELATION
from agent_gateway.modules.execution.models import Execution
from tests.integration.test_mcp_actions import actions_session
from tests.integration.test_mcp_http import BASE, call, mcp_session, running
from tests.integration.test_user_identity import audit_events
from tests.world import World

CID = "11111111-1111-1111-1111-111111111111:3"


def body(world: World, key: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "action": "fake.echo",
        "resource_id": world.resource_id,
        "params": {"message": "hi"},
    }
    if key is not None:
        payload["idempotency_key"] = key
    return payload


async def test_the_header_reaches_the_execution_and_its_audit(world: World) -> None:
    response = await world.api.post(
        "/v1/executions", json=body(world), headers={**world.agent(), "X-Correlation-Id": CID}
    )
    assert response.status_code == 200, response.text
    execution = Execution.model_validate(response.json())
    assert execution.correlation_id == CID

    requested = await audit_events(world, "execution.requested")
    succeeded = await audit_events(world, "execution.succeeded")
    assert requested[-1]["details"]["correlation_id"] == CID
    assert succeeded[-1]["details"]["correlation_id"] == CID
    assert (await world.gateway.audit.verify()).ok


async def test_without_an_id_the_audit_line_is_unchanged(world: World) -> None:
    response = await world.api.post("/v1/executions", json=body(world), headers=world.agent())
    assert response.status_code == 200, response.text
    assert response.json()["correlation_id"] is None
    requested = await audit_events(world, "execution.requested")
    assert "correlation_id" not in requested[-1]["details"]


async def test_a_malformed_id_runs_nothing(world: World) -> None:
    response = await world.api.post(
        "/v1/executions",
        json=body(world),
        headers={**world.agent(), "X-Correlation-Id": "bad\nid"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_params"
    assert world.fake.calls == []


async def test_idempotency_keeps_the_first_id(world: World) -> None:
    first = await world.api.post(
        "/v1/executions",
        json=body(world, "same"),
        headers={**world.agent(), "X-Correlation-Id": "first"},
    )
    second = await world.api.post(
        "/v1/executions",
        json=body(world, "same"),
        headers={**world.agent(), "X-Correlation-Id": "second"},
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert second.json()["correlation_id"] == "first"
    assert len(world.fake.calls) == 1


async def test_an_approval_carries_the_id(approval_world: World) -> None:
    response = await approval_world.api.post(
        "/v1/executions",
        json=body(approval_world),
        headers={**approval_world.agent(), "X-Correlation-Id": CID},
    )
    assert response.status_code == 202, response.text
    requested = await audit_events(approval_world, "approval.requested")
    assert requested[-1]["details"]["correlation_id"] == CID
    assert approval_world.fake.calls == []


async def test_mcp_reads_the_meta_id(world: World) -> None:
    async with running(world) as app, actions_session(app, world.agent_token) as session:
        result = await session.call_tool(
            "fake_echo",
            {"resource_id": world.resource_id, "message": "hi"},
            meta=cast(RequestParamsMeta, {META_CORRELATION: CID}),
        )
    assert isinstance(result, CallToolResult)
    outcome = result.structured_content
    assert isinstance(outcome, dict)
    stored = await world.api.get(f"/v1/executions/{outcome['execution_id']}", headers=world.agent())
    assert stored.json()["correlation_id"] == CID


async def test_the_meta_tool_reads_the_header(world: World) -> None:
    async with (
        running(world) as app,
        mcp_session(app, world.agent_token, {"X-Correlation-Id": CID}) as session,
    ):
        result = await call(
            session,
            "execute_action",
            {"action": "fake.echo", "resource_id": world.resource_id, "params": {"message": "hi"}},
        )
    assert result["correlation_id"] == CID


async def test_mcp_refuses_disagreeing_ids(world: World) -> None:
    raw = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "fake_echo",
            "arguments": {"resource_id": world.resource_id, "message": "hi"},
            "_meta": {META_CORRELATION: "from-meta"},
        },
    }
    async with (
        running(world) as app,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client,
    ):
        response = await client.post(
            "/mcp/actions",
            json=raw,
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {world.agent_token}",
                "X-Correlation-Id": "from-header",
            },
        )
    assert response.status_code == 200, response.text
    content = response.json()["result"]["structuredContent"]
    assert content["status"] == "error"
    assert "disagree" in content["error"]
    assert world.fake.calls == []
