"""Approval flows end to end (SPEC §13)."""

from datetime import timedelta

from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from tests.world import World


async def _submit(world: World) -> dict:  # type: ignore[type-arg]
    response = await world.api.post(
        "/v1/executions",
        json={"action": "fake.echo", "resource_id": world.resource_id, "params": {"message": "hi"}},
        headers=world.agent(),
    )
    assert response.status_code == 202
    body: dict = response.json()  # type: ignore[type-arg]
    assert body["status"] == "pending_approval"
    assert body["approval_id"]
    return body


async def test_approve_runs_the_execution(approval_world: World) -> None:
    w = approval_world
    execution = await _submit(w)
    assert w.fake.calls == []

    pending = (await w.api.get("/v1/admin/approvals?status=pending", headers=w.admin())).json()
    assert [a["id"] for a in pending] == [execution["approval_id"]]

    by_agent = await w.api.post(
        f"/v1/admin/approvals/{execution['approval_id']}/approve", headers=w.agent()
    )
    # An agent alone never approves; admin approval endpoints want an admin user (SPEC §23).
    assert by_agent.status_code == 401

    approved = await w.api.post(
        f"/v1/admin/approvals/{execution['approval_id']}/approve", headers=w.admin()
    )
    assert approved.json()["status"] == "approved"
    await w.gateway.engine.drain()

    done = (await w.api.get(f"/v1/executions/{execution['id']}", headers=w.agent())).json()
    assert done["status"] == "succeeded"
    assert len(w.fake.calls) == 1

    again = await w.api.post(
        f"/v1/admin/approvals/{execution['approval_id']}/approve", headers=w.admin()
    )
    assert again.status_code == 409


async def test_reject_closes_the_execution(approval_world: World) -> None:
    w = approval_world
    execution = await _submit(w)
    rejected = await w.api.post(
        f"/v1/admin/approvals/{execution['approval_id']}/reject",
        json={"reason": "not now"},
        headers=w.admin(),
    )
    assert rejected.json()["status"] == "rejected"
    done = (await w.api.get(f"/v1/executions/{execution['id']}", headers=w.agent())).json()
    assert done["status"] == "rejected"
    assert w.fake.calls == []


async def test_cli_approval_is_picked_up_by_the_dispatcher(approval_world: World) -> None:
    w = approval_world
    execution = await _submit(w)
    # The CLI approves from another process: only the stored approval changes.
    await w.gateway.admin.approve(CLI_PRINCIPAL, execution["approval_id"])
    await w.gateway.engine.dispatch_approvals()
    await w.gateway.engine.drain()
    done = (await w.api.get(f"/v1/executions/{execution['id']}", headers=w.agent())).json()
    assert done["status"] == "succeeded"


async def test_expired_approval_expires_the_execution(approval_world: World) -> None:
    w = approval_world
    execution = await _submit(w)
    approval_store = w.gateway.admin._approvals
    approval = await approval_store.get(execution["approval_id"])
    assert approval is not None
    # Rewind the approval instead of waiting 15 minutes.
    store = approval_store._approvals  # type: ignore[attr-defined]
    await store.update(
        approval.id,
        lambda a: a.model_copy(update={"expires_at": a.requested_at - timedelta(seconds=1)}),
    )
    await w.gateway.engine.dispatch_approvals()
    done = (await w.api.get(f"/v1/executions/{execution['id']}", headers=w.agent())).json()
    assert done["status"] == "expired"
    assert w.fake.calls == []
