"""Approval state machine (SPEC §13): pending -> approved | rejected | expired.

Every transition is written to the audit log *before* it is stored, so a failing audit
log (``AuditUnavailableError``) leaves the approval untouched (fail closed). The stored
update re-checks the state, so a decision that lost a race is refused, not applied twice.
"""

import asyncio
from collections.abc import Callable
from datetime import timedelta

from agent_gateway.common.clock import Clock
from agent_gateway.common.errors import (
    AdminRequiredError,
    ApprovalNotFoundError,
    ApprovalNotPendingError,
)
from agent_gateway.common.ids import IdPrefix, new_id
from agent_gateway.config import ApprovalSettings
from agent_gateway.modules.approvals.models import Approval, ApprovalStatus
from agent_gateway.modules.audit.models import Actor, ActorType, AuditEventType, AuditRecord
from agent_gateway.modules.audit.ports import AuditLog
from agent_gateway.modules.identity.models import Principal
from agent_gateway.modules.storage.ports import Collection

SYSTEM_ACTOR = Actor(type=ActorType.SYSTEM, id="approvals")


class ApprovalWorkflow:
    def __init__(
        self,
        approvals: Collection[Approval],
        audit: AuditLog,
        clock: Clock,
        settings: ApprovalSettings,
    ) -> None:
        self._approvals = approvals
        self._audit = audit
        self._clock = clock
        self._ttl = timedelta(minutes=settings.ttl_minutes)
        self._lock = asyncio.Lock()

    async def request(self, execution_id: str, params_digest: str) -> Approval:
        now = self._clock.now()
        approval = Approval(
            id=new_id(IdPrefix.APPROVAL),
            execution_id=execution_id,
            params_digest=params_digest,
            requested_at=now,
            expires_at=now + self._ttl,
        )
        await self._record(AuditEventType.APPROVAL_REQUESTED, approval, SYSTEM_ACTOR)
        await self._approvals.put(approval)
        return approval

    async def get(self, approval_id: str) -> Approval | None:
        approval = await self._approvals.get(approval_id)
        if approval is None or not self._is_overdue(approval):
            return approval
        async with self._lock:
            return await self._expire(approval_id)

    async def find(self, *, status: ApprovalStatus | None = None) -> list[Approval]:
        await self.expire_due()
        items = await self._approvals.all()
        return sorted(
            (a for a in items if status is None or a.status is status),
            key=lambda a: a.requested_at,
        )

    async def approve(self, approval_id: str, actor: Principal) -> Approval:
        return await self._decide(approval_id, actor, ApprovalStatus.APPROVED, None)

    async def reject(
        self, approval_id: str, actor: Principal, reason: str | None = None
    ) -> Approval:
        return await self._decide(approval_id, actor, ApprovalStatus.REJECTED, reason)

    async def expire_due(self) -> list[Approval]:
        expired: list[Approval] = []
        async with self._lock:
            for approval in await self._approvals.all():
                if self._is_overdue(approval):
                    expired.append(await self._expire(approval.id))
        return expired

    async def _decide(
        self,
        approval_id: str,
        actor: Principal,
        status: ApprovalStatus,
        reason: str | None,
    ) -> Approval:
        if not actor.is_admin:
            raise AdminRequiredError("only an admin can approve or reject")
        async with self._lock:
            current = await self._approvals.get(approval_id)
            if current is None:
                raise ApprovalNotFoundError(f"approval {approval_id} not found")
            if self._is_overdue(current):
                await self._expire(approval_id)
                raise ApprovalNotPendingError(f"approval {approval_id} has expired")
            _require_pending(current)

            # model_validate (not model_copy) so ``reason`` is length-checked before auditing.
            decided = Approval.model_validate(
                current.model_dump()
                | {
                    "status": status,
                    "decided_by": actor.token_id,
                    "decided_at": self._clock.now(),
                    "reason": reason,
                }
            )
            event = (
                AuditEventType.APPROVAL_APPROVED
                if status is ApprovalStatus.APPROVED
                else AuditEventType.APPROVAL_REJECTED
            )
            admin = Actor(type=ActorType.ADMIN, id=actor.token_id)
            await self._record(event, decided, admin)
            return await self._approvals.update(approval_id, _transition(decided))

    async def _expire(self, approval_id: str) -> Approval:
        """Mark one overdue pending approval as expired. Caller holds ``self._lock``."""
        current = await self._approvals.get(approval_id)
        if current is None:
            raise ApprovalNotFoundError(f"approval {approval_id} not found")
        if current.status is not ApprovalStatus.PENDING:
            return current
        expired = current.model_copy(update={"status": ApprovalStatus.EXPIRED})
        await self._record(AuditEventType.APPROVAL_EXPIRED, expired, SYSTEM_ACTOR)
        return await self._approvals.update(approval_id, _transition(expired))

    def _is_overdue(self, approval: Approval) -> bool:
        return (
            approval.status is ApprovalStatus.PENDING and self._clock.now() >= approval.expires_at
        )

    async def _record(self, event: AuditEventType, approval: Approval, actor: Actor) -> None:
        details: dict[str, object] = {"approval_id": approval.id}
        if approval.reason is not None:
            details["reason"] = approval.reason
        await self._audit.append(
            AuditRecord(
                event=event,
                actor=actor,
                execution_id=approval.execution_id,
                params_digest=approval.params_digest,
                details=details,
            )
        )


def _require_pending(approval: Approval) -> None:
    if approval.status is not ApprovalStatus.PENDING:
        raise ApprovalNotPendingError(f"approval {approval.id} is {approval.status}")


def _transition(target: Approval) -> Callable[[Approval], Approval]:
    """Update function that applies ``target`` only if the stored approval is still pending."""

    def apply(stored: Approval) -> Approval:
        _require_pending(stored)
        return target

    return apply
