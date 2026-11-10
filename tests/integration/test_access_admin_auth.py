"""Who may call ``/v1/admin/*`` and what an access admin sees (SPEC §23, contract §1, §3,
§10 to §12)."""

from collections.abc import AsyncIterator
from typing import Any

import pytest

from agent_gateway.config import Settings
from agent_gateway.modules.authorization.models import ApprovalMode
from tests.access_world import ALICE, BOB, CAROL, AccessWorld, build_access_world


@pytest.fixture
async def aw(settings: Settings) -> AsyncIterator[AccessWorld]:
    world = await build_access_world(settings)
    yield world
    await world.w.api.aclose()
    await world.w.gateway.stop()


@pytest.fixture
async def approvals_aw(settings: Settings) -> AsyncIterator[AccessWorld]:
    """Staff writes need an admin's approval."""
    world = await build_access_world(settings, user_approval=ApprovalMode.ALWAYS)
    yield world
    await world.w.api.aclose()
    await world.w.gateway.stop()


def code(response: Any) -> str:
    return str(response.json()["error"]["code"])


async def test_the_contract_lists_the_admin_version(aw: AccessWorld) -> None:
    response = await aw.w.api.get("/v1/contract")
    assert response.json() == {"versions": ["agentgate-gateway/1", "agentgate-gateway-admin/1"]}


# ---- who is an admin (contract §3) -------------------------------------------------------


async def test_an_access_admin_reads_roles_through_the_agent(aw: AccessWorld) -> None:
    response = await aw.w.api.get("/v1/admin/roles", headers=aw.as_user(CAROL))
    assert response.status_code == 200, response.text
    roles = {r["id"]: r for r in response.json()}
    assert roles["operator"]["held_by_agents"] == ["claude-ops", "other-agent"]
    assert roles["operator"]["editable"] is False
    assert roles["staff"] == {
        "id": "staff",
        "description": "",
        "actions": ["fake.*", "test.leak"],
        "held_by_agents": [],
        "editable": True,
    }


async def test_without_a_user_token_the_agent_gets_401(aw: AccessWorld) -> None:
    response = await aw.w.api.get("/v1/admin/roles", headers=aw.w.agent())
    assert response.status_code == 401
    assert code(response) == "unauthenticated"
    # Infra endpoints keep answering an agent as before.
    response = await aw.w.api.get("/v1/admin/agents", headers=aw.w.agent())
    assert response.status_code == 403
    assert code(response) == "admin_required"


async def test_a_bad_user_token_is_401(aw: AccessWorld) -> None:
    headers = {**aw.w.agent(), "x-user-token": aw.idp.token("u-carol", ["x"], aud="other")}
    response = await aw.w.api.get("/v1/admin/roles", headers=headers)
    assert response.status_code == 401


@pytest.mark.parametrize("path", ["/v1/admin/roles", "/v1/admin/agents", "/v1/admin/config"])
async def test_a_user_who_is_not_an_admin_gets_not_admin(aw: AccessWorld, path: str) -> None:
    response = await aw.w.api.get(path, headers=aw.as_user(ALICE))
    assert response.status_code == 403
    assert code(response) == "not_admin"


async def test_the_agents_own_grants_play_no_part(aw: AccessWorld) -> None:
    # Both agents hold the same role; an admin user is an admin through either, and a
    # non-admin user is not one through either.
    assert (await aw.w.api.get("/v1/admin/roles", headers=aw.as_user_via_other(CAROL))).is_success
    response = await aw.w.api.get("/v1/admin/roles", headers=aw.as_user_via_other(ALICE))
    assert code(response) == "not_admin"


INFRA = [
    ("GET", "/v1/admin/agents", None),
    ("POST", "/v1/admin/agents", {"name": "x"}),
    ("PATCH", "/v1/admin/agents/agt_x", {}),
    ("POST", "/v1/admin/agents/agt_x/tokens", {}),
    ("GET", "/v1/admin/tokens", None),
    ("POST", "/v1/admin/tokens", {}),
    ("DELETE", "/v1/admin/tokens/tok_x", None),
    ("POST", "/v1/admin/resources", {"type": "model", "name": "m"}),
    ("PATCH", "/v1/admin/resources/res_x", {}),
    ("DELETE", "/v1/admin/resources/res_x", None),
    ("GET", "/v1/admin/credentials", None),
    ("POST", "/v1/admin/credentials", {"name": "c", "type": "api_token", "value": "v"}),
    ("PUT", "/v1/admin/credentials/cred_x", {"value": "v"}),
    ("DELETE", "/v1/admin/credentials/cred_x", None),
    ("PUT", "/v1/admin/roles/staff", {"actions": ["fake.*"]}),
    ("DELETE", "/v1/admin/roles/staff", None),
    (
        "POST",
        "/v1/admin/policies",
        {
            "subject": {"user_role": "staff"},
            "actions": ["fake.echo"],
            "resources": {"ids": ["res_x"]},
            "effect": "allow",
        },
    ),
    ("DELETE", "/v1/admin/policies/pol_x", None),
    ("GET", "/v1/admin/audit/verify", None),
    ("GET", "/v1/admin/policies?side=agent", None),
]


@pytest.mark.parametrize(("method", "path", "body"), INFRA, ids=[f"{m} {p}" for m, p, _ in INFRA])
async def test_infra_endpoints_are_infra_only_for_an_access_admin(
    aw: AccessWorld, method: str, path: str, body: dict[str, Any] | None
) -> None:
    response = await aw.w.api.request(method, path, json=body, headers=aw.as_user(CAROL))
    assert response.status_code == 403, response.text
    assert code(response) == "infra_only"


async def test_infra_only_changes_nothing(aw: AccessWorld) -> None:
    before = await aw.w.gateway.admin.list_roles(_static())
    await aw.w.api.put(
        "/v1/admin/roles/staff", json={"actions": ["test.*"]}, headers=aw.as_user(CAROL)
    )
    assert await aw.w.gateway.admin.list_roles(_static()) == before


async def test_the_static_token_keeps_everything_as_before(aw: AccessWorld) -> None:
    roles = await aw.w.api.get("/v1/admin/roles", headers=aw.w.admin())
    assert roles.status_code == 200
    assert "held_by_agents" not in roles.json()[0]
    resources = await aw.w.api.get("/v1/admin/resources", headers=aw.w.admin())
    assert "attributes" in resources.json()[0]
    audit = await aw.w.api.get("/v1/admin/audit", headers=aw.w.admin())
    assert isinstance(audit.json(), list)
    assert (await aw.w.api.get("/v1/admin/agents", headers=aw.w.admin())).status_code == 200
    assert (await aw.w.api.get("/v1/admin/audit/verify", headers=aw.w.admin())).json()["ok"]


# ---- the calling agent's view: approvals (contract §1.1, §10) ----------------------------


async def submit(aw: AccessWorld, headers: dict[str, str], action: str = "fake.echo") -> str:
    params = {"message": "hi"} if action == "fake.echo" else {}
    response = await aw.w.api.post(
        "/v1/executions",
        json={"action": action, "resource_id": aw.w.resource_id, "params": params},
        headers=headers,
    )
    assert response.status_code in (200, 202), response.text
    return str(response.json()["id"])


async def approvals(aw: AccessWorld, who: tuple[str, list[str]]) -> list[dict[str, Any]]:
    response = await aw.w.api.get(
        "/v1/admin/approvals", params={"status": "pending"}, headers=aw.as_user(who)
    )
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()
    return items


async def test_admin_approvals_are_those_of_the_calling_agent(approvals_aw: AccessWorld) -> None:
    aw = approvals_aw
    mine = await submit(aw, aw.as_user(ALICE))
    await submit(aw, aw.as_user_via_other(ALICE))
    await submit(aw, aw.w.agent(), "priv.sudo")
    items = await approvals(aw, CAROL)
    assert [i["execution_id"] for i in items] == [mine]
    item = items[0]
    assert item["action"] == "fake.echo"
    assert item["resource"] == "echo-endpoint"
    assert item["params"] == {"message": "hi"}
    assert item["requested_by"] == {"agent": "claude-ops", "subject": "u-alice"}
    assert item["status"] == "pending"
    # The static token still sees all three.
    static = await aw.w.api.get("/v1/admin/approvals?status=pending", headers=aw.w.admin())
    assert len(static.json()) == 3


async def test_another_agents_approval_is_404_and_a_privileged_one_infra_only(
    approvals_aw: AccessWorld,
) -> None:
    aw = approvals_aw
    other = await submit(aw, aw.as_user_via_other(ALICE))
    sudo = await submit(aw, aw.w.agent(), "priv.sudo")
    executions = aw.w.gateway.executions
    other_approval = (await executions.get(other)).approval_id  # type: ignore[union-attr]
    sudo_approval = (await executions.get(sudo)).approval_id  # type: ignore[union-attr]
    response = await aw.w.api.post(
        f"/v1/admin/approvals/{other_approval}/approve", headers=aw.as_user(CAROL)
    )
    assert response.status_code == 404
    assert code(response) == "approval_not_found"
    response = await aw.w.api.post(
        f"/v1/admin/approvals/{sudo_approval}/approve", headers=aw.as_user(CAROL)
    )
    assert response.status_code == 403
    assert code(response) == "infra_only"


async def test_an_admin_cannot_approve_a_write_they_asked_for(approvals_aw: AccessWorld) -> None:
    aw = approvals_aw
    await submit(aw, aw.as_user(BOB))
    approval = (await approvals(aw, BOB))[0]
    response = await aw.w.api.post(
        f"/v1/admin/approvals/{approval['id']}/approve", headers=aw.as_user(BOB)
    )
    assert response.status_code == 409
    assert code(response) == "self_approval"
    # Another admin may.
    response = await aw.w.api.post(
        f"/v1/admin/approvals/{approval['id']}/approve", headers=aw.as_user(CAROL)
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"
    assert response.json()["decided_by"] == "u-carol"


async def test_approving_runs_the_write_and_is_audited_as_the_user(
    approvals_aw: AccessWorld,
) -> None:
    aw = approvals_aw
    execution_id = await submit(aw, aw.as_user(ALICE))
    approval = (await approvals(aw, CAROL))[0]
    response = await aw.w.api.post(
        f"/v1/admin/approvals/{approval['id']}/approve", headers=aw.as_user(CAROL)
    )
    assert response.status_code == 200, response.text
    await aw.w.gateway.engine.drain()
    execution = await aw.w.gateway.executions.get(execution_id)
    assert execution is not None
    assert execution.status == "succeeded"
    again = await aw.w.api.post(
        f"/v1/admin/approvals/{approval['id']}/approve", headers=aw.as_user(CAROL)
    )
    assert again.status_code == 409
    assert code(again) == "approval_not_pending"

    page = await aw.w.api.get(
        "/v1/admin/audit", params={"event": "approval.approved"}, headers=aw.as_user(CAROL)
    )
    entry = page.json()["items"][0]
    assert entry["actor"] == {"kind": "user", "subject": "u-carol", "via_agent": "claude-ops"}
    raw = await aw.w.gateway.audit.query()
    approved = next(e for e in raw if e.event == "approval.approved")
    assert approved.actor.type == "user"
    assert approved.actor.id == "u-carol"
    assert approved.details["via_agent"] == aw.w.agent_id


async def test_rejecting_needs_a_reason(approvals_aw: AccessWorld) -> None:
    aw = approvals_aw
    await submit(aw, aw.as_user(ALICE))
    approval = (await approvals(aw, CAROL))[0]
    url = f"/v1/admin/approvals/{approval['id']}/reject"
    assert (await aw.w.api.post(url, json={}, headers=aw.as_user(CAROL))).status_code == 422
    response = await aw.w.api.post(url, json={"reason": "not today"}, headers=aw.as_user(CAROL))
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "rejected"
    assert response.json()["reason"] == "not today"


# ---- history and audit (contract §11, §12) -----------------------------------------------


async def test_executions_are_those_of_the_calling_agent_without_privileged(
    approvals_aw: AccessWorld,
) -> None:
    aw = approvals_aw
    mine = [await submit(aw, aw.as_user(ALICE)) for _ in range(3)]
    other = await submit(aw, aw.as_user_via_other(ALICE))
    sudo = await submit(aw, aw.w.agent(), "priv.sudo")
    first = await aw.w.api.get(
        "/v1/admin/executions", params={"limit": 2}, headers=aw.as_user(CAROL)
    )
    assert first.status_code == 200, first.text
    body = first.json()
    assert [i["id"] for i in body["items"]] == [mine[2], mine[1]]
    assert body["items"][0]["agent"] == "claude-ops"
    assert body["items"][0]["subject"] == "u-alice"
    assert "params" not in body["items"][0]
    second = await aw.w.api.get(
        "/v1/admin/executions",
        params={"limit": 2, "cursor": body["next_cursor"]},
        headers=aw.as_user(CAROL),
    )
    assert [i["id"] for i in second.json()["items"]] == [mine[0]]
    assert second.json()["next_cursor"] is None

    detail = await aw.w.api.get(f"/v1/admin/executions/{mine[0]}", headers=aw.as_user(CAROL))
    assert detail.json()["params"] == {"message": "hi"}
    response = await aw.w.api.get(f"/v1/admin/executions/{other}", headers=aw.as_user(CAROL))
    assert response.status_code == 404
    response = await aw.w.api.get(f"/v1/admin/executions/{sudo}", headers=aw.as_user(CAROL))
    assert code(response) == "infra_only"
    # The static token sees all five, privileged included.
    static = await aw.w.api.get("/v1/admin/executions", headers=aw.w.admin())
    assert len(static.json()["items"]) == 5


async def test_executions_filter_by_subject_status_and_action(aw: AccessWorld) -> None:
    await submit(aw, aw.as_user(ALICE))
    bobs = await submit(aw, aw.as_user(BOB))
    response = await aw.w.api.get(
        "/v1/admin/executions",
        params={"subject": "u-bob", "status": "succeeded", "action": "fake.echo"},
        headers=aw.as_user(CAROL),
    )
    assert [i["id"] for i in response.json()["items"]] == [bobs]
    none = await aw.w.api.get(
        "/v1/admin/executions", params={"action": "test.leak"}, headers=aw.as_user(CAROL)
    )
    assert none.json() == {"items": [], "next_cursor": None}


async def test_audit_shows_only_what_went_through_the_calling_agent(
    approvals_aw: AccessWorld,
) -> None:
    aw = approvals_aw
    mine = await submit(aw, aw.as_user(ALICE))
    other = await submit(aw, aw.as_user_via_other(ALICE))
    sudo = await submit(aw, aw.w.agent(), "priv.sudo")
    response = await aw.w.api.get("/v1/admin/audit", headers=aw.as_user(CAROL))
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    targets = {i["target"] for i in items}
    assert mine in targets
    assert other not in targets
    assert sudo not in targets
    assert {i["event"] for i in items} >= {"execution.requested", "approval.requested"}
    requested = next(i for i in items if i["event"] == "execution.requested")
    assert requested["actor"] == {"kind": "agent", "subject": "u-alice", "via_agent": "claude-ops"}
    seqs = [i["seq"] for i in items]
    assert seqs == sorted(seqs, reverse=True)


async def test_audit_pages_with_a_cursor_and_filters_by_subject(aw: AccessWorld) -> None:
    for _ in range(3):
        await submit(aw, aw.as_user(ALICE))
    await submit(aw, aw.as_user(BOB))
    seen: list[int] = []
    cursor: str | None = None
    while True:
        params: dict[str, Any] = {"limit": 2, "subject": "u-alice"}
        if cursor:
            params["cursor"] = cursor
        page = (
            await aw.w.api.get("/v1/admin/audit", params=params, headers=aw.as_user(CAROL))
        ).json()
        seen += [i["seq"] for i in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert len(seen) == len(set(seen)) == 9  # requested, started, succeeded x 3
    assert seen == sorted(seen, reverse=True)
    bad = await aw.w.api.get("/v1/admin/audit?cursor=abc", headers=aw.as_user(CAROL))
    assert bad.status_code == 422


def _static() -> Any:
    from agent_gateway.modules.administration.service import CLI_PRINCIPAL

    return CLI_PRINCIPAL
