"""A write the requesting user confirms over REST (SPEC §13b, contract §6)."""

import asyncio
from typing import Any

import httpx

from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.execution.models import Execution, ExecutionStatus
from tests.fakes.oidc import FakeIdp
from tests.integration.test_user_identity import as_user, audit_events, submit
from tests.world import USER_HEADER, World

STAFF = ["staff"]


async def allow_fake(world: World, subject: PolicySubject, approval: ApprovalMode) -> None:
    await world.gateway.admin.create_policy(
        CLI_PRINCIPAL,
        subject=subject,
        actions=["fake.*"],
        resources=ResourceSelector(ids=(world.resource_id,)),
        effect=PolicyEffect.ALLOW,
        approval=approval,
    )


async def held(world: World, headers: dict[str, str]) -> tuple[Execution, str]:
    await allow_fake(world, PolicySubject(user_role="staff"), ApprovalMode.REQUESTER)
    execution = await submit(world, headers)
    assert execution.status is ExecutionStatus.PENDING_APPROVAL
    assert execution.approval_id is not None
    return execution, execution.approval_id


async def decide(
    world: World, approval_id: str, headers: dict[str, str], decision: str = "confirm"
) -> httpx.Response:
    return await world.api.post(
        f"/v1/approvals/{approval_id}/decide", json={"decision": decision}, headers=headers
    )


async def mine(world: World, headers: dict[str, str], **params: str) -> list[dict[str, Any]]:
    response = await world.api.get("/v1/approvals/mine", params=params, headers=headers)
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()
    return items


async def execution_status(world: World, execution_id: str) -> str:
    response = await world.api.get(f"/v1/executions/{execution_id}", headers=world.admin())
    assert response.status_code == 200, response.text
    status: str = response.json()["status"]
    return status


def assert_error(response: httpx.Response, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code


async def test_the_requester_sees_and_confirms_the_write(user_world: World, idp: FakeIdp) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    execution, approval_id = await held(user_world, alice)
    [stored] = (await user_world.api.get("/v1/admin/approvals", headers=user_world.admin())).json()
    assert stored["mode"] == "requester"
    assert stored["requester"] == "alice"

    [view] = await mine(user_world, alice, status="pending")
    assert view["id"] == approval_id
    assert view["execution_id"] == execution.id
    assert view["tool"] == "fake_echo"
    assert view["params"] == {"message": "hi"}
    assert view["status"] == "pending"
    assert user_world.fake.calls == []

    response = await decide(user_world, approval_id, alice)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "confirmed"
    assert body["result"] == {"message": "hi"}
    assert body["decided_at"] is not None
    assert len(user_world.fake.calls) == 1
    assert await execution_status(user_world, execution.id) == "succeeded"

    approved = await audit_events(user_world, "approval.approved")
    assert approved[-1]["actor"] == {"type": "user", "id": "alice"}
    assert await mine(user_world, alice, status="pending") == []
    assert [v["status"] for v in await mine(user_world, alice)] == ["confirmed"]


async def test_the_requester_rejects(user_world: World, idp: FakeIdp) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    execution, approval_id = await held(user_world, alice)
    response = await decide(user_world, approval_id, alice, "reject")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "rejected"
    assert user_world.fake.calls == []
    assert await execution_status(user_world, execution.id) == "rejected"


async def test_a_decided_approval_is_409(user_world: World, idp: FakeIdp) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    _, approval_id = await held(user_world, alice)
    assert (await decide(user_world, approval_id, alice)).status_code == 200
    assert_error(await decide(user_world, approval_id, alice), 409, "approval_not_pending")
    assert len(user_world.fake.calls) == 1


async def test_only_a_person_may_decide(user_world: World, idp: FakeIdp) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    _, approval_id = await held(user_world, alice)
    assert_error(
        await user_world.api.get("/v1/approvals/mine", headers=user_world.agent()),
        401,
        "unauthenticated",
    )
    assert_error(await decide(user_world, approval_id, user_world.agent()), 401, "unauthenticated")
    assert_error(await user_world.api.get("/v1/approvals/mine"), 401, "unauthenticated")
    assert user_world.fake.calls == []


async def test_someone_elses_approval_is_not_found(user_world: World, idp: FakeIdp) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    bob = as_user(user_world, idp.token("bob", STAFF))
    _, approval_id = await held(user_world, alice)

    assert await mine(user_world, bob) == []
    assert_error(await decide(user_world, approval_id, bob), 404, "approval_not_found")
    # The same user through another agent's token does not see it either.
    via_other = {**user_world.other(), USER_HEADER: idp.token("alice", STAFF)}
    assert await mine(user_world, via_other) == []
    assert_error(await decide(user_world, approval_id, via_other), 404, "approval_not_found")
    assert_error(await decide(user_world, "apr_does_not_exist", alice), 404, "approval_not_found")
    assert user_world.fake.calls == []


async def test_an_admin_approval_is_not_the_requesters(user_world: World, idp: FakeIdp) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    await allow_fake(user_world, PolicySubject(user_role="staff"), ApprovalMode.REQUESTER)
    await allow_fake(user_world, PolicySubject(role="operator"), ApprovalMode.ALWAYS)
    execution = await submit(user_world, alice)
    assert execution.approval_id is not None

    assert await mine(user_world, alice) == []
    assert_error(await decide(user_world, execution.approval_id, alice), 404, "approval_not_found")
    approve = await user_world.api.post(
        f"/v1/admin/approvals/{execution.approval_id}/approve", headers=user_world.admin()
    )
    assert approve.status_code == 200, approve.text
    await user_world.gateway.engine.drain()
    assert len(user_world.fake.calls) == 1


async def test_the_admin_may_still_decide_a_requester_approval(
    user_world: World, idp: FakeIdp
) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    execution, approval_id = await held(user_world, alice)
    reject = await user_world.api.post(
        f"/v1/admin/approvals/{approval_id}/reject", json={}, headers=user_world.admin()
    )
    assert reject.status_code == 200, reject.text
    assert await execution_status(user_world, execution.id) == "rejected"
    assert [v["status"] for v in await mine(user_world, alice)] == ["rejected"]


async def test_confirming_re_checks_authorization(user_world: World, idp: FakeIdp) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    execution, approval_id = await held(user_world, alice)
    await user_world.gateway.admin.put_role(CLI_PRINCIPAL, Role(id="staff", actions=()))

    response = await decide(user_world, approval_id, alice)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "denied"
    assert user_world.fake.calls == []
    assert await execution_status(user_world, execution.id) == "denied"
    denied = await audit_events(user_world, "execution.denied")
    assert denied[-1]["actor"] == {"type": "user", "id": "alice"}


async def test_agent_only_calls_cannot_reach_a_requester_policy(user_world: World) -> None:
    await allow_fake(user_world, PolicySubject(role="operator"), ApprovalMode.REQUESTER)
    body = {
        "action": "fake.echo",
        "resource_id": user_world.resource_id,
        "params": {"message": "x"},
    }
    response = await user_world.api.post("/v1/executions", json=body, headers=user_world.agent())
    assert_error(response, 403, "action_not_allowed")
    assert user_world.fake.calls == []


async def test_confirm_and_dispatch_never_run_twice(user_world: World, idp: FakeIdp) -> None:
    alice = as_user(user_world, idp.token("alice", STAFF))
    _, approval_id = await held(user_world, alice)
    engine = user_world.gateway.engine
    response, *_ = await asyncio.gather(
        decide(user_world, approval_id, alice),
        engine.dispatch_approvals(),
        engine.dispatch_approvals(),
    )
    assert response.status_code == 200, response.text
    await engine.drain()
    await engine.dispatch_approvals()
    await engine.drain()
    assert len(user_world.fake.calls) == 1
