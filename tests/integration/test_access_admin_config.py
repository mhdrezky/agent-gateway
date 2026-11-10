"""Access configuration, plans, and apply (SPEC §23, contract §8, §9)."""

import copy
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest

from agent_gateway.config import Settings
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.authorization.models import Role
from tests.access_world import ALICE, BOB, CAROL, AccessWorld, build_access_world

Who = tuple[str, list[str]]


@pytest.fixture
async def aw(settings: Settings) -> AsyncIterator[AccessWorld]:
    world = await build_access_world(settings)
    yield world
    await world.w.api.aclose()
    await world.w.gateway.stop()


@pytest.fixture
async def production(settings: Settings) -> AsyncIterator[AccessWorld]:
    world = await build_access_world(settings, second_admin=True)
    yield world
    await world.w.api.aclose()
    await world.w.gateway.stop()


async def config(aw: AccessWorld, who: Who = CAROL) -> dict[str, Any]:
    response = await aw.w.api.get("/v1/admin/config", headers=aw.as_user(who))
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def plan(aw: AccessWorld, desired: dict[str, Any], who: Who = CAROL) -> dict[str, Any]:
    response = await aw.w.api.post(
        "/v1/admin/config/plan", json={"config": desired}, headers=aw.as_user(who)
    )
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def apply(aw: AccessWorld, plan_id: str, who: Who = CAROL) -> Any:
    return await aw.w.api.post(
        "/v1/admin/config/apply", json={"plan_id": plan_id}, headers=aw.as_user(who)
    )


def codes(planned: dict[str, Any]) -> list[str]:
    return [p["code"] for p in planned["problems"]]


def cell(role: str, resource: str, action: str, approval: str = "never") -> dict[str, Any]:
    """The policy a console matrix cell writes (contract §9.1)."""
    return {
        "name": f"{role}--{resource}--{action.replace('.', '_')}",
        "subject": {"user_role": role},
        "actions": [action],
        "resources": {"names": [resource], "tags": []},
        "effect": "allow",
        "approval": approval,
        "expires_at": None,
    }


# ---- config (contract §8.1) --------------------------------------------------------------


async def test_config_is_keyed_by_names_and_leaves_out_agent_roles(aw: AccessWorld) -> None:
    body = await config(aw)
    assert body["schema"] == "agentgate-access/1"
    assert [r["id"] for r in body["roles"]] == ["platform-admin", "staff"]
    assert {u["match"].get("group") for u in body["users"]} == {"staff", "platform-admin"}
    assert [p["name"] for p in body["policies"]] == ["staff-echo"]
    assert body["policies"][0]["resources"]["names"] == ["echo-endpoint"]
    assert body["resource_tables"] == {"sample": ["customer"]}
    assert "operator" not in str(body)


async def test_an_unnamed_user_policy_is_exported_by_id_and_round_trips(aw: AccessWorld) -> None:
    from agent_gateway.modules.authorization.models import (
        PolicyEffect,
        PolicySubject,
        ResourceSelector,
    )

    made = await aw.w.gateway.admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(user="u-alice"),
        actions=["fake.echo"],
        resources=ResourceSelector(ids=(aw.w.resource_id,)),
        effect=PolicyEffect.DENY,
    )
    body = await config(aw)
    assert made.id.lower() in [p["name"] for p in body["policies"]]
    planned = await plan(aw, body)
    assert planned["changes"] == []
    assert planned["problems"] == []


# ---- plan and apply (contract §8.2, §8.3) ------------------------------------------------


async def test_an_unchanged_config_plans_to_nothing(aw: AccessWorld) -> None:
    planned = await plan(aw, await config(aw))
    assert planned["changes"] == []
    assert planned["problems"] == []
    assert planned["created_by"] == "u-carol"
    assert planned["status"] == "open"
    assert planned["plan_id"].startswith("pln_")
    assert planned["base_digest"].startswith("sha256:")
    response = await apply(aw, planned["plan_id"])
    assert response.status_code == 200, response.text
    assert response.json()["changes"] == []


async def test_plan_then_apply_changes_access_on_the_next_request(aw: AccessWorld) -> None:
    # Before: a reader user has no role, so nothing goes through.
    reader = ("u-dave", ["readers"])
    denied = await aw.w.api.post(
        "/v1/executions",
        json={"action": "fake.echo", "resource_id": aw.w.resource_id, "params": {"message": "x"}},
        headers=aw.as_user(reader),
    )
    assert denied.status_code == 403

    desired = await config(aw)
    desired["roles"].append({"id": "reader", "description": "Reads", "actions": ["fake.echo"]})
    desired["users"].append({"match": {"group": "readers"}, "roles": ["reader"]})
    desired["policies"].append(cell("reader", "echo-endpoint", "fake.echo"))
    desired["resource_tables"]["sample"] = ["customer", "product"]
    planned = await plan(aw, desired)
    assert planned["problems"] == []
    assert [(c["kind"], c["name"], c["op"]) for c in planned["changes"]] == [
        ("role", "reader", "create"),
        ("user", "group:readers", "create"),
        ("policy", "reader--echo-endpoint--fake_echo", "create"),
        ("resource_tables", "sample", "update"),
    ]
    assert planned["changes"][3]["before"] == ["customer"]
    assert planned["changes"][3]["after"] == ["customer", "product"]

    response = await apply(aw, planned["plan_id"])
    assert response.status_code == 200, response.text
    assert response.json()["applied_by"] == "u-carol"

    allowed = await aw.w.api.post(
        "/v1/executions",
        json={"action": "fake.echo", "resource_id": aw.w.resource_id, "params": {"message": "x"}},
        headers=aw.as_user(reader),
    )
    assert allowed.status_code == 200, allowed.text
    after = await config(aw)
    assert after["resource_tables"]["sample"] == ["customer", "product"]
    new_user = next(u for u in after["users"] if u["match"].get("group") == "readers")
    assert new_user["id"].startswith("usr_")
    # A second plan of the same config has nothing to do.
    assert (await plan(aw, after))["changes"] == []


async def test_apply_is_one_audit_entry_with_the_full_diff(aw: AccessWorld) -> None:
    desired = await config(aw)
    desired["roles"][1]["description"] = "Everyone"
    planned = await plan(aw, desired)
    assert (await apply(aw, planned["plan_id"])).status_code == 200
    entries = [e for e in await aw.w.gateway.audit.query() if e.event == "access.applied"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry.actor.type == "user"
    assert entry.actor.id == "u-carol"
    assert entry.details["via_agent"] == aw.w.agent_id
    assert entry.details["plan_id"] == planned["plan_id"]
    assert entry.details["changes"] == planned["changes"]
    page = await aw.w.api.get(
        "/v1/admin/audit", params={"event": "access.applied"}, headers=aw.as_user(CAROL)
    )
    view = page.json()["items"][0]
    assert view["actor"] == {"kind": "user", "subject": "u-carol", "via_agent": "claude-ops"}
    assert view["target"] == planned["plan_id"]


async def test_updates_and_deletes_are_planned(aw: AccessWorld) -> None:
    desired = await config(aw)
    desired["roles"] = [r for r in desired["roles"] if r["id"] != "staff"] + [
        {"id": "staff", "description": "", "actions": ["fake.echo"]}
    ]
    desired["users"] = [u for u in desired["users"] if u["match"].get("group") != "staff"]
    desired["policies"] = []
    planned = await plan(aw, desired)
    assert planned["problems"] == []
    assert [(c["kind"], c["name"], c["op"]) for c in planned["changes"]] == [
        ("role", "staff", "update"),
        ("user", "group:staff", "delete"),
        ("policy", "staff-echo", "delete"),
    ]
    assert (await apply(aw, planned["plan_id"])).status_code == 200
    after = await config(aw)
    assert after["policies"] == []
    assert len(after["users"]) == 1


async def test_a_promoted_user_with_a_foreign_id_matches_by_match(aw: AccessWorld) -> None:
    """Promote (contract §13): ids belong to the source instance; the match decides."""
    desired = await config(aw)
    desired["users"][0]["id"] = "usr_FROMANOTHERINSTANCE00000000"
    desired["users"][1]["id"] = None
    planned = await plan(aw, desired)
    assert planned["changes"] == []


# ---- problems (contract §8.2) ------------------------------------------------------------


async def test_missing_names_are_problems(aw: AccessWorld) -> None:
    desired = await config(aw)
    desired["roles"].append({"id": "ghost", "actions": ["nothing.here", "fake.*"]})
    desired["users"].append({"match": {"group": "ghosts"}, "roles": ["no-such-role"]})
    desired["policies"].append(cell("staff", "no-such-resource", "fake.echo"))
    desired["resource_tables"]["no-such-db"] = ["t"]
    planned = await plan(aw, desired)
    assert sorted(set(codes(planned))) == ["missing_action", "missing_resource", "missing_role"]
    assert (await apply(aw, planned["plan_id"])).json()["error"]["code"] == "plan_has_problems"


async def test_changing_a_role_an_agent_holds_is_a_problem(aw: AccessWorld) -> None:
    desired = await config(aw)
    desired["roles"].append({"id": "operator", "actions": ["fake.*"]})
    assert codes(await plan(aw, desired)) == ["role_held_by_agent"]
    # Naming it unchanged is no change and no problem.
    desired["roles"][-1] = {"id": "operator", "actions": ["fake.*", "test.*", "priv.sudo"]}
    planned = await plan(aw, desired)
    assert planned["problems"] == []
    assert planned["changes"] == []


async def test_an_agent_side_policy_is_a_problem(aw: AccessWorld) -> None:
    desired = await config(aw)
    agent_policy = cell("staff", "echo-endpoint", "fake.echo")
    agent_policy["subject"] = {"role": "operator"}
    desired["policies"].append(agent_policy)
    assert codes(await plan(aw, desired)) == ["agent_side_policy"]


@pytest.mark.parametrize("pattern", ["priv.sudo", "priv.*"])
async def test_granting_a_privileged_action_is_a_problem(aw: AccessWorld, pattern: str) -> None:
    desired = await config(aw)
    desired["roles"][1]["actions"].append(pattern)
    assert codes(await plan(aw, desired)) == ["privileged_action"]
    desired = await config(aw)
    policy = cell("staff", "echo-endpoint", "fake.echo")
    policy["actions"] = [pattern]
    desired["policies"].append(policy)
    assert "privileged_action" in codes(await plan(aw, desired))


async def test_a_table_the_catalog_does_not_list_is_a_problem(aw: AccessWorld) -> None:
    desired = await config(aw)
    desired["resource_tables"]["sample"] = ["customer", "salary"]
    planned = await plan(aw, desired)
    assert codes(planned) == ["table_not_in_catalog"]
    assert "salary" in planned["problems"][0]["message"]


async def test_tables_are_not_checked_without_a_snapshot(aw: AccessWorld) -> None:
    aw.w.gateway.access.catalog = _null_catalog()
    desired = await config(aw)
    desired["resource_tables"]["sample"] = ["customer", "salary"]
    assert codes(await plan(aw, desired)) == []


async def test_removing_every_admin_is_last_admin(aw: AccessWorld) -> None:
    desired = await config(aw)
    desired["users"] = [u for u in desired["users"] if u["match"].get("group") != "platform-admin"]
    assert "last_admin" in codes(await plan(aw, desired))
    # Taking the role away from the store item counts the same.
    desired = await config(aw)
    for user in desired["users"]:
        if user["match"].get("group") == "platform-admin":
            user["roles"] = []
    assert "last_admin" in codes(await plan(aw, desired))


async def test_removing_your_own_admin_role_is_self_lockout(aw: AccessWorld) -> None:
    desired = await config(aw)
    # carol stays admin by subject; bob, who plans, loses it with the group.
    desired["users"] = [u for u in desired["users"] if u["match"].get("group") != "platform-admin"]
    desired["users"].append({"match": {"subject": "u-carol"}, "roles": ["platform-admin"]})
    assert codes(await plan(aw, desired, BOB)) == ["self_lockout"]
    assert codes(await plan(aw, desired, CAROL)) == []


async def test_an_invalid_config_is_422(aw: AccessWorld) -> None:
    desired = await config(aw)
    desired["roles"].append({"id": "Bad Role", "actions": []})
    response = await aw.w.api.post(
        "/v1/admin/config/plan", json={"config": desired}, headers=aw.as_user(CAROL)
    )
    assert response.status_code == 422
    desired = await config(aw)
    desired["roles"].append(desired["roles"][0])
    response = await aw.w.api.post(
        "/v1/admin/config/plan", json={"config": desired}, headers=aw.as_user(CAROL)
    )
    assert response.status_code == 422


# ---- apply rules (contract §8.3) ---------------------------------------------------------


async def test_a_plan_is_stale_once_the_config_changes(aw: AccessWorld) -> None:
    desired = await config(aw)
    desired["roles"][1]["description"] = "changed"
    planned = await plan(aw, desired)
    await aw.w.gateway.admin.put_role(CLI_PRINCIPAL, Role(id="extra", actions=("fake.echo",)))
    response = await apply(aw, planned["plan_id"])
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "plan_stale"


async def test_an_applied_plan_cannot_be_applied_again(aw: AccessWorld) -> None:
    planned = await plan(aw, await config(aw))
    assert (await apply(aw, planned["plan_id"])).status_code == 200
    again = await apply(aw, planned["plan_id"])
    assert again.json()["error"]["code"] == "plan_stale"


async def test_a_plan_expires_after_15_minutes(aw: AccessWorld) -> None:
    planned = await plan(aw, await config(aw))
    aw.clock.advance(timedelta(minutes=15))
    response = await apply(aw, planned["plan_id"])
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "plan_expired"


async def test_an_unknown_plan_is_404(aw: AccessWorld) -> None:
    assert (await apply(aw, "pln_nope")).status_code == 404


async def test_open_plans_are_listed_for_a_second_admin(aw: AccessWorld) -> None:
    first = await plan(aw, await config(aw), BOB)
    second = await plan(aw, await config(aw), CAROL)
    assert (await apply(aw, second["plan_id"])).status_code == 200
    response = await aw.w.api.get(
        "/v1/admin/config/plans", params={"status": "open"}, headers=aw.as_user(CAROL)
    )
    assert [p["plan_id"] for p in response.json()] == [first["plan_id"]]
    aw.clock.advance(timedelta(minutes=16))
    response = await aw.w.api.get(
        "/v1/admin/config/plans", params={"status": "open"}, headers=aw.as_user(CAROL)
    )
    assert response.json() == []


async def test_production_needs_a_second_admin(production: AccessWorld) -> None:
    aw = production
    desired = await config(aw)
    desired["roles"][1]["description"] = "reviewed"
    planned = await plan(aw, desired, BOB)
    response = await apply(aw, planned["plan_id"], BOB)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "second_admin_required"
    response = await apply(aw, planned["plan_id"], CAROL)
    assert response.status_code == 200, response.text
    assert response.json()["applied_by"] == "u-carol"


async def test_practice_lets_the_planner_apply(aw: AccessWorld) -> None:
    planned = await plan(aw, await config(aw), BOB)
    assert (await apply(aw, planned["plan_id"], BOB)).status_code == 200


async def test_a_user_cannot_plan(aw: AccessWorld) -> None:
    response = await aw.w.api.post(
        "/v1/admin/config/plan", json={"config": await config(aw)}, headers=aw.as_user(ALICE)
    )
    assert response.json()["error"]["code"] == "not_admin"


async def test_the_static_token_may_plan_and_apply(aw: AccessWorld) -> None:
    body = (await aw.w.api.get("/v1/admin/config", headers=aw.w.admin())).json()
    desired = copy.deepcopy(body)
    desired["roles"][1]["description"] = "from the gateway"
    response = await aw.w.api.post(
        "/v1/admin/config/plan", json={"config": desired}, headers=aw.w.admin()
    )
    planned = response.json()
    assert planned["created_by"].startswith("admin:tok_")
    response = await aw.w.api.post(
        "/v1/admin/config/apply", json={"plan_id": planned["plan_id"]}, headers=aw.w.admin()
    )
    assert response.status_code == 200, response.text


def _null_catalog() -> Any:
    from agent_gateway.modules.administration.catalog_port import NullCatalog

    return NullCatalog()
