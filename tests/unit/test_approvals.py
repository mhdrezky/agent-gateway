"""Approval state machine and TTL (SPEC §13, §19)."""

from datetime import timedelta

import pytest

from agent_gateway.common.canonical import sha256_digest
from agent_gateway.common.errors import (
    AdminRequiredError,
    ApprovalNotFoundError,
    ApprovalNotPendingError,
    AuditUnavailableError,
)
from agent_gateway.common.ids import IdPrefix, has_prefix
from agent_gateway.config import ApprovalSettings
from agent_gateway.modules.approvals.models import Approval, ApprovalStatus
from agent_gateway.modules.approvals.service import ApprovalWorkflow
from agent_gateway.modules.audit.models import ActorType, AuditEventType
from agent_gateway.modules.identity.models import Principal, TokenKind
from tests.fakes.audit import FakeAuditLog
from tests.fakes.clock import FixedClock
from tests.fakes.storage import InMemoryCollection

DIGEST = sha256_digest({"service": "nginx"})
ADMIN = Principal(kind=TokenKind.ADMIN, token_id="tok_admin")
AGENT = Principal(kind=TokenKind.AGENT, token_id="tok_agent", agent_id="agt_1")


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def audit(clock: FixedClock) -> FakeAuditLog:
    return FakeAuditLog(clock)


@pytest.fixture
def store() -> InMemoryCollection[Approval]:
    return InMemoryCollection[Approval]()


@pytest.fixture
def service(
    store: InMemoryCollection[Approval], audit: FakeAuditLog, clock: FixedClock
) -> ApprovalWorkflow:
    return ApprovalWorkflow(store, audit, clock, ApprovalSettings(ttl_minutes=15))


def _events(audit: FakeAuditLog) -> list[AuditEventType]:
    return [e.event for e in audit.entries]


async def test_request_creates_pending_approval_with_ttl(
    service: ApprovalWorkflow, audit: FakeAuditLog, clock: FixedClock
) -> None:
    approval = await service.request("exe_1", DIGEST)

    assert has_prefix(approval.id, IdPrefix.APPROVAL)
    assert approval.status is ApprovalStatus.PENDING
    assert approval.params_digest == DIGEST
    assert approval.requested_at == clock.now()
    assert approval.expires_at == clock.now() + timedelta(minutes=15)
    assert await service.get(approval.id) == approval
    assert _events(audit) == [AuditEventType.APPROVAL_REQUESTED]
    assert audit.entries[0].details["approval_id"] == approval.id


async def test_ttl_comes_from_settings(
    store: InMemoryCollection[Approval], audit: FakeAuditLog, clock: FixedClock
) -> None:
    service = ApprovalWorkflow(store, audit, clock, ApprovalSettings(ttl_minutes=30))
    approval = await service.request("exe_1", DIGEST)
    assert approval.expires_at - approval.requested_at == timedelta(minutes=30)


async def test_admin_can_approve(
    service: ApprovalWorkflow, audit: FakeAuditLog, clock: FixedClock
) -> None:
    approval = await service.request("exe_1", DIGEST)
    clock.advance(timedelta(minutes=1))

    approved = await service.approve(approval.id, ADMIN)

    assert approved.status is ApprovalStatus.APPROVED
    assert approved.decided_by == "tok_admin"
    assert approved.decided_at == clock.now()
    assert await service.get(approval.id) == approved
    entry = audit.entries[-1]
    assert entry.event is AuditEventType.APPROVAL_APPROVED
    assert entry.actor.type is ActorType.ADMIN
    assert entry.execution_id == "exe_1"
    assert entry.params_digest == DIGEST


async def test_admin_can_reject_with_reason(service: ApprovalWorkflow, audit: FakeAuditLog) -> None:
    approval = await service.request("exe_1", DIGEST)

    rejected = await service.reject(approval.id, ADMIN, reason="not now")

    assert rejected.status is ApprovalStatus.REJECTED
    assert rejected.reason == "not now"
    assert audit.entries[-1].event is AuditEventType.APPROVAL_REJECTED
    assert audit.entries[-1].details["reason"] == "not now"


@pytest.mark.parametrize("decision", ["approve", "reject"])
async def test_agent_cannot_decide(
    service: ApprovalWorkflow, audit: FakeAuditLog, decision: str
) -> None:
    approval = await service.request("exe_1", DIGEST)

    with pytest.raises(AdminRequiredError):
        await getattr(service, decision)(approval.id, AGENT)

    stored = await service.get(approval.id)
    assert stored is not None
    assert stored.status is ApprovalStatus.PENDING
    assert _events(audit) == [AuditEventType.APPROVAL_REQUESTED]


@pytest.mark.parametrize(
    ("first", "second"),
    [("approve", "approve"), ("approve", "reject"), ("reject", "approve"), ("reject", "reject")],
)
async def test_decided_approval_is_not_pending(
    service: ApprovalWorkflow, first: str, second: str
) -> None:
    approval = await service.request("exe_1", DIGEST)
    await getattr(service, first)(approval.id, ADMIN)

    with pytest.raises(ApprovalNotPendingError):
        await getattr(service, second)(approval.id, ADMIN)


async def test_unknown_approval(service: ApprovalWorkflow) -> None:
    with pytest.raises(ApprovalNotFoundError):
        await service.approve("apr_missing", ADMIN)
    assert await service.get("apr_missing") is None


async def test_approve_after_expiry_marks_expired(
    service: ApprovalWorkflow, audit: FakeAuditLog, clock: FixedClock
) -> None:
    approval = await service.request("exe_1", DIGEST)
    clock.advance(timedelta(minutes=15))

    with pytest.raises(ApprovalNotPendingError):
        await service.approve(approval.id, ADMIN)

    stored = await service.get(approval.id)
    assert stored is not None
    assert stored.status is ApprovalStatus.EXPIRED
    assert _events(audit) == [AuditEventType.APPROVAL_REQUESTED, AuditEventType.APPROVAL_EXPIRED]


async def test_approve_just_before_expiry(service: ApprovalWorkflow, clock: FixedClock) -> None:
    approval = await service.request("exe_1", DIGEST)
    clock.advance(timedelta(minutes=15) - timedelta(milliseconds=1))
    assert (await service.approve(approval.id, ADMIN)).status is ApprovalStatus.APPROVED


async def test_get_marks_overdue_approval_expired(
    service: ApprovalWorkflow, audit: FakeAuditLog, clock: FixedClock
) -> None:
    approval = await service.request("exe_1", DIGEST)
    clock.advance(timedelta(hours=1))

    stored = await service.get(approval.id)

    assert stored is not None
    assert stored.status is ApprovalStatus.EXPIRED
    assert _events(audit)[-1] is AuditEventType.APPROVAL_EXPIRED


async def test_expire_due_only_touches_overdue_pending(
    service: ApprovalWorkflow, audit: FakeAuditLog, clock: FixedClock
) -> None:
    old = await service.request("exe_1", DIGEST)
    decided = await service.request("exe_2", DIGEST)
    await service.approve(decided.id, ADMIN)
    clock.advance(timedelta(minutes=10))
    fresh = await service.request("exe_3", DIGEST)
    clock.advance(timedelta(minutes=6))

    expired = await service.expire_due()

    assert [a.id for a in expired] == [old.id]
    assert expired[0].status is ApprovalStatus.EXPIRED
    assert await service.expire_due() == []
    statuses = {a.id: a.status for a in await service.find()}
    assert statuses == {
        old.id: ApprovalStatus.EXPIRED,
        decided.id: ApprovalStatus.APPROVED,
        fresh.id: ApprovalStatus.PENDING,
    }
    assert _events(audit).count(AuditEventType.APPROVAL_EXPIRED) == 1


async def test_find_filters_by_status(service: ApprovalWorkflow, clock: FixedClock) -> None:
    first = await service.request("exe_1", DIGEST)
    clock.advance(timedelta(seconds=1))
    second = await service.request("exe_2", DIGEST)
    await service.reject(second.id, ADMIN)

    assert [a.id for a in await service.find()] == [first.id, second.id]
    assert [a.id for a in await service.find(status=ApprovalStatus.PENDING)] == [first.id]
    assert [a.id for a in await service.find(status=ApprovalStatus.REJECTED)] == [second.id]


async def test_audit_failure_blocks_decision(
    service: ApprovalWorkflow, audit: FakeAuditLog
) -> None:
    approval = await service.request("exe_1", DIGEST)
    audit.fail_writes = True

    with pytest.raises(AuditUnavailableError):
        await service.approve(approval.id, ADMIN)

    stored = await service.get(approval.id)
    assert stored is not None
    assert stored.status is ApprovalStatus.PENDING


async def test_audit_failure_blocks_request(service: ApprovalWorkflow, audit: FakeAuditLog) -> None:
    audit.fail_writes = True
    with pytest.raises(AuditUnavailableError):
        await service.request("exe_1", DIGEST)
    assert await service.find() == []


async def test_reason_too_long_is_rejected_before_audit(
    service: ApprovalWorkflow, audit: FakeAuditLog
) -> None:
    approval = await service.request("exe_1", DIGEST)
    with pytest.raises(ValueError, match="reason"):
        await service.reject(approval.id, ADMIN, reason="x" * 501)
    assert _events(audit) == [AuditEventType.APPROVAL_REQUESTED]
