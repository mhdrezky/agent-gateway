"""An agent calling on behalf of a user (``X-User-Token``) over REST and MCP (SPEC §9.4)."""

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from agent_gateway.config import Settings, UserSettings
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.authorization.models import ApprovalMode
from agent_gateway.modules.execution.models import Execution
from agent_gateway.modules.identity.models import UserMatch
from agent_gateway.modules.identity.users import USER_AUTH_FAILED_MESSAGE
from tests.fakes.oidc import FakeIdp, oidc_settings
from tests.integration.test_mcp_http import BASE, running
from tests.world import World, build_world

USER = "x-user-token"


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
async def user_world(settings: Settings, idp: FakeIdp) -> AsyncIterator[World]:
    configured = settings.model_copy(update={"users": UserSettings(oidc=oidc_settings())})
    w = await build_world(configured, approval=ApprovalMode.NEVER, jwks=idp)
    await w.gateway.admin.add_user(CLI_PRINCIPAL, UserMatch(group="staff"), ["staff"])
    yield w
    await w.api.aclose()
    await w.gateway.stop()


def as_user(world: World, token: str) -> dict[str, str]:
    return {**world.agent(), USER: token}


async def audit_events(world: World, event: str) -> list[dict[str, Any]]:
    response = await world.api.get(
        "/v1/admin/audit", params={"event": event}, headers=world.admin()
    )
    assert response.status_code == 200, response.text
    entries: list[dict[str, Any]] = response.json()
    return entries


async def test_whoami_names_the_user(user_world: World, idp: FakeIdp) -> None:
    response = await user_world.api.get(
        "/v1/whoami", headers=as_user(user_world, idp.token("u-1", ["staff"]))
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["agent_id"] == user_world.agent_id
    assert body["roles"] == ["operator"]
    assert body["user"]["subject"] == "u-1"
    assert body["user"]["roles"] == ["staff"]


async def test_without_the_header_nothing_changes(user_world: World) -> None:
    body = (await user_world.api.get("/v1/whoami", headers=user_world.agent())).json()
    assert body["user"] is None


async def test_a_bad_user_token_is_401_and_audited(user_world: World, idp: FakeIdp) -> None:
    for token in ("eyJhbGciOiJub25lIn0.e30.", idp.token(aud="other")):
        response = await user_world.api.get("/v1/whoami", headers=as_user(user_world, token))
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthenticated"
        assert response.json()["error"]["message"] == USER_AUTH_FAILED_MESSAGE
    assert len(await audit_events(user_world, "auth.failed")) == 2


async def test_a_user_token_needs_an_agent_token(user_world: World, idp: FakeIdp) -> None:
    admin = await user_world.api.get(
        "/v1/whoami", headers={**user_world.admin(), USER: idp.token()}
    )
    assert admin.status_code == 403
    alone = await user_world.api.get("/v1/whoami", headers={USER: idp.token()})
    assert alone.status_code == 401


async def test_user_tokens_are_refused_without_oidc_settings(world: World) -> None:
    idp = FakeIdp()
    response = await world.api.get("/v1/whoami", headers=as_user(world, idp.token()))
    assert response.status_code == 401


async def submit(world: World, headers: dict[str, str], key: str | None = None) -> Execution:
    body: dict[str, Any] = {
        "action": "fake.echo",
        "resource_id": world.resource_id,
        "params": {"message": "hi"},
    }
    if key is not None:
        body["idempotency_key"] = key
    response = await world.api.post("/v1/executions", json=body, headers=headers)
    assert response.status_code in (200, 201, 202), response.text
    return Execution.model_validate(response.json())


async def test_executions_record_the_user(user_world: World, idp: FakeIdp) -> None:
    execution = await submit(user_world, as_user(user_world, idp.token("u-1", ["staff"])))
    assert execution.user_subject == "u-1"
    agent_only = await submit(user_world, user_world.agent())
    assert agent_only.user_subject is None
    requested = await audit_events(user_world, "execution.requested")
    by_id = {e["execution_id"]: e for e in requested}
    assert by_id[execution.id]["details"] == {"user": "u-1"}
    assert by_id[agent_only.id]["details"] == {}


async def test_idempotency_keys_are_per_user(user_world: World, idp: FakeIdp) -> None:
    first = await submit(user_world, as_user(user_world, idp.token("u-1")), key="k1")
    again = await submit(user_world, as_user(user_world, idp.token("u-1")), key="k1")
    other = await submit(user_world, as_user(user_world, idp.token("u-2")), key="k1")
    assert again.id == first.id
    assert other.id != first.id
    assert other.user_subject == "u-2"


def test_phase_two_executions_still_load() -> None:
    stored = {
        "id": "exe_01JB8XYZ0000000000000000AA",
        "agent_id": "agt_01JB8XYZ0000000000000000AA",
        "action": "ssh.system.info",
        "resource_id": "res_01JB8XYZ0000000000000000AA",
        "params": {},
        "params_digest": "sha256:" + "0" * 64,
        "status": "succeeded",
        "created_at": "2026-10-31T00:00:00Z",
    }
    assert Execution.model_validate(stored).user_subject is None


async def test_mcp_tool_calls_carry_the_user(user_world: World, idp: FakeIdp) -> None:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "fake_echo",
            "arguments": {"resource_id": user_world.resource_id, "message": "hi"},
        },
    }
    accept = {"Accept": "application/json, text/event-stream"}
    async with (
        running(user_world) as app,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client,
    ):
        good = await client.post(
            "/mcp/actions",
            json=body,
            headers={**accept, **as_user(user_world, idp.token("u-9", ["staff"]))},
        )
        bad = await client.post(
            "/mcp/actions",
            json=body,
            headers={**accept, **as_user(user_world, "garbage")},
        )
    assert good.status_code == 200, good.text
    outcome = good.json()["result"]["structuredContent"]
    assert outcome["status"] == "ok"
    execution = await user_world.gateway.engine.get(
        (await user_world.gateway.authenticator.authenticate(user_world.agent_token)),
        outcome["execution_id"],
    )
    assert execution.user_subject == "u-9"
    assert bad.status_code == 401
    assert len(user_world.fake.calls) == 1
