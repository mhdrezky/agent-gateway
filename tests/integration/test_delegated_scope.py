"""What an agent acting for a user sees and may run: user ∩ agent (SPEC §10.3)."""

from typing import Any

import httpx

from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.authorization.models import (
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
)
from agent_gateway.modules.resources.models import ResourceType
from tests.fakes.oidc import FakeIdp
from tests.integration.test_mcp_http import BASE, running
from tests.integration.test_user_identity import as_user, submit
from tests.world import World

STAFF = ["staff"]


async def ids(world: World, path: str, headers: dict[str, str]) -> list[str]:
    response = await world.api.get(path, headers=headers)
    assert response.status_code == 200, response.text
    return [item["id"] for item in response.json()]


async def test_actions_are_the_intersection(user_world: World, idp: FakeIdp) -> None:
    agent_only = await ids(user_world, "/v1/actions", user_world.agent())
    assert agent_only == ["fake.echo", "test.leak", "test.sleep"]
    staff = await ids(user_world, "/v1/actions", as_user(user_world, idp.token("u-1", STAFF)))
    assert staff == ["fake.echo"]


async def test_resources_need_an_allow_on_both_sides(user_world: World, idp: FakeIdp) -> None:
    admin = user_world.gateway.admin
    extra = await admin.create_resource(
        CLI_PRINCIPAL, ResourceType.HTTP_ENDPOINT, "agent-only-endpoint", attributes={"host": "x"}
    )
    await admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(role="operator"),
        actions=["fake.*"],
        resources=ResourceSelector(ids=(extra.id,)),
        effect=PolicyEffect.ALLOW,
    )
    agent_only = await ids(user_world, "/v1/resources", user_world.agent())
    assert set(agent_only) == {user_world.resource_id, extra.id}
    staff = await ids(user_world, "/v1/resources", as_user(user_world, idp.token("u-1", STAFF)))
    assert staff == [user_world.resource_id]

    body: dict[str, Any] = {
        "action": "fake.echo",
        "resource_id": extra.id,
        "params": {"message": "x"},
    }
    refused = await user_world.api.post(
        "/v1/executions", json=body, headers=as_user(user_world, idp.token("u-1", STAFF))
    )
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "action_not_allowed"


async def test_an_unknown_user_has_an_empty_scope(user_world: World, idp: FakeIdp) -> None:
    nobody = as_user(user_world, idp.token("stranger", ["visitors"]))
    assert await ids(user_world, "/v1/actions", nobody) == []
    assert await ids(user_world, "/v1/resources", nobody) == []
    body = {
        "action": "fake.echo",
        "resource_id": user_world.resource_id,
        "params": {"message": "x"},
    }
    response = await user_world.api.post("/v1/executions", json=body, headers=nobody)
    assert response.status_code == 403
    assert user_world.fake.calls == []


async def test_users_see_only_their_own_executions(user_world: World, idp: FakeIdp) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    bob = as_user(user_world, idp.token("bob", STAFF))
    mine = await submit(user_world, alice)
    theirs = await submit(user_world, bob)

    assert (await user_world.api.get(f"/v1/executions/{mine.id}", headers=alice)).status_code == 200
    hidden = await user_world.api.get(f"/v1/executions/{theirs.id}", headers=alice)
    assert hidden.status_code == 404
    listed = (await user_world.api.get("/v1/executions", headers=alice)).json()["items"]
    assert [e["id"] for e in listed] == [mine.id]

    everything = (await user_world.api.get("/v1/executions", headers=user_world.agent())).json()
    assert {e["id"] for e in everything["items"]} == {mine.id, theirs.id}


async def test_mcp_tools_follow_the_user_scope(user_world: World, idp: FakeIdp) -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    accept = {"Accept": "application/json, text/event-stream"}
    async with (
        running(user_world) as app,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client,
    ):
        staff = await client.post(
            "/mcp/actions",
            json=body,
            headers={**accept, **as_user(user_world, idp.token("u-1", STAFF))},
        )
        nobody = await client.post(
            "/mcp/actions",
            json=body,
            headers={**accept, **as_user(user_world, idp.token("stranger"))},
        )
    assert [t["name"] for t in staff.json()["result"]["tools"]] == ["fake_echo"]
    assert nobody.json()["result"]["tools"] == []
