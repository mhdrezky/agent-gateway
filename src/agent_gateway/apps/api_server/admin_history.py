"""Admin approvals, execution history, and audit as an access admin sees them (SPEC §23,
contract §1.1, §10 to §12).

Through an agent (``X-User-Token``) only what happened through that agent is visible:
another agent's item is ``404``, a privileged action (``ssh.sudo``) or a sudo window never
shows up, and asking for a privileged item by id is ``403 infra_only``. Without a calling
agent (static admin token) everything is visible.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from agent_gateway.common.clock import to_rfc3339
from agent_gateway.common.errors import (
    ApprovalNotFoundError,
    ExecutionNotFoundError,
    InfraOnlyError,
    InvalidParamsError,
    SelfApprovalError,
)
from agent_gateway.modules.administration.access_models import (
    AdminApprovalView,
    AdminExecutionPage,
    AuditActor,
    AuditEntryView,
    AuditPage,
    ExecutionDetail,
    ExecutionView,
    RequestedBy,
)
from agent_gateway.modules.approvals.models import Approval, ApprovalStatus, Approver
from agent_gateway.modules.audit.models import ActorType, AuditEntry, AuditEventType
from agent_gateway.modules.execution.models import Execution, ExecutionStatus
from agent_gateway.modules.identity.models import Principal
from agent_gateway.runtime import Gateway

PRIVILEGED_HIDDEN = "privileged actions stay with the gateway admin"
# Executions are read from the store in batches of this size while filtering.
SCAN_BATCH = 200
# Events never shown through an agent: they belong to no app and to no person.
_INFRA_EVENTS = frozenset(
    {
        AuditEventType.AUTH_FAILED,
        AuditEventType.ELEVATION_GRANTED,
        AuditEventType.ELEVATION_REVOKED,
    }
)
_ACTOR_KIND: dict[ActorType, Any] = {
    ActorType.ADMIN: "admin_token",
    ActorType.AGENT: "agent",
    ActorType.USER: "user",
    ActorType.SYSTEM: "system",
}
_APPROVAL_STATUS: dict[ApprovalStatus, Literal["pending", "approved", "rejected", "expired"]] = {
    ApprovalStatus.PENDING: "pending",
    ApprovalStatus.APPROVED: "approved",
    ApprovalStatus.REJECTED: "rejected",
    ApprovalStatus.EXPIRED: "expired",
}
_OUTCOMES = {
    AuditEventType.EXECUTION_DENIED: "denied",
    AuditEventType.EXECUTION_REJECTED: "rejected",
    AuditEventType.EXECUTION_FAILED: "failed",
    AuditEventType.APPROVAL_REJECTED: "rejected",
    AuditEventType.APPROVAL_EXPIRED: "expired",
    AuditEventType.AUTH_FAILED: "failed",
}


@dataclass(slots=True)
class _Names:
    agents: dict[str, str] = field(default_factory=dict)
    resources: dict[str, str] = field(default_factory=dict)

    def agent(self, agent_id: str) -> str:
        return self.agents.get(agent_id, agent_id)

    def resource(self, resource_id: str) -> str:
        return self.resources.get(resource_id, resource_id)


async def _names(gateway: Gateway) -> _Names:
    agents, resources = await gateway.access.names()
    return _Names(agents=agents, resources=resources)


def _calling_agent(principal: Principal) -> str | None:
    """The agent an access admin calls through; ``None`` for the static admin token."""
    return None if principal.is_admin else principal.agent_id


# ---- approvals (contract §10) ------------------------------------------------------------


async def list_approvals(
    gateway: Gateway, principal: Principal, status: ApprovalStatus | None
) -> list[AdminApprovalView]:
    agent_id = _calling_agent(principal)
    names = await _names(gateway)
    views: list[AdminApprovalView] = []
    for approval in reversed(await gateway.approvals.find(status=status)):
        if approval.mode is not Approver.ADMIN:
            continue  # the requester confirms those in the app's own inbox
        execution = await gateway.executions.get(approval.execution_id)
        if execution is None or (agent_id is not None and execution.agent_id != agent_id):
            continue
        if agent_id is not None and gateway.access.is_privileged(execution.action):
            continue
        views.append(_approval_view(approval, execution, names))
    return views


async def decide_approval(
    gateway: Gateway,
    principal: Principal,
    approval_id: str,
    *,
    approve: bool,
    reason: str | None = None,
) -> AdminApprovalView:
    """An access admin approves or rejects an admin approval of its calling agent."""
    user, agent_id = principal.user, principal.agent_id
    if user is None or agent_id is None:  # pragma: no cover - guarded by the dependency
        raise InfraOnlyError("an access admin decides through an agent")
    approval = await gateway.approvals.get(approval_id)
    execution = await gateway.executions.get(approval.execution_id) if approval else None
    if (
        approval is None
        or execution is None
        or execution.agent_id != agent_id
        or approval.mode is not Approver.ADMIN
    ):
        raise ApprovalNotFoundError(f"approval {approval_id} not found")
    if gateway.access.is_privileged(execution.action):
        raise InfraOnlyError(PRIVILEGED_HIDDEN)
    if approve and execution.user_subject == user.subject:
        raise SelfApprovalError("you cannot approve a write you requested yourself")
    decided = await gateway.approvals.decide_as_access_admin(
        approval_id, user.subject, agent_id, approve=approve, reason=reason
    )
    await gateway.engine.dispatch_approvals()
    return _approval_view(decided, execution, await _names(gateway))


def _approval_view(approval: Approval, execution: Execution, names: _Names) -> AdminApprovalView:
    resource = names.resource(execution.resource_id)
    return AdminApprovalView(
        id=approval.id,
        execution_id=execution.id,
        action=execution.action,
        resource=resource,
        summary=f"{execution.action} on {resource}",
        params=execution.params,
        requested_by=RequestedBy(
            agent=names.agent(execution.agent_id), subject=execution.user_subject
        ),
        status=_APPROVAL_STATUS[approval.status],
        created_at=to_rfc3339(approval.requested_at),
        expires_at=to_rfc3339(approval.expires_at),
        decided_at=None if approval.decided_at is None else to_rfc3339(approval.decided_at),
        decided_by=approval.decided_by,
        reason=approval.reason,
    )


# ---- executions (contract §11) -----------------------------------------------------------


async def execution_page(
    gateway: Gateway,
    principal: Principal,
    *,
    since: datetime | None,
    until: datetime | None,
    status: ExecutionStatus | None,
    subject: str | None,
    action: str | None,
    limit: int,
    cursor: str | None,
) -> AdminExecutionPage:
    agent_id = _calling_agent(principal)
    hide_privileged = agent_id is not None
    names = await _names(gateway)
    found: list[Execution] = []
    before = cursor
    reached_since = False
    while not reached_since and len(found) <= limit:
        batch = await gateway.executions.page(
            agent_id=agent_id, user_subject=subject, before=before, limit=SCAN_BATCH
        )
        for execution in batch:
            if since is not None and execution.created_at < since:
                reached_since = True  # newest first: everything after is older still
                break
            if (
                (until is None or execution.created_at <= until)
                and (status is None or execution.status is status)
                and (action is None or execution.action == action)
                and not (hide_privileged and gateway.access.is_privileged(execution.action))
            ):
                found.append(execution)
                if len(found) > limit:
                    break
        if len(batch) < SCAN_BATCH:
            break
        before = batch[-1].id
    page = found[:limit]
    next_cursor = page[-1].id if len(found) > limit else None
    return AdminExecutionPage(
        items=[_execution_view(e, names) for e in page], next_cursor=next_cursor
    )


async def execution_detail(
    gateway: Gateway, principal: Principal, execution_id: str
) -> ExecutionDetail:
    agent_id = _calling_agent(principal)
    execution = await gateway.executions.get(execution_id)
    if execution is None or (agent_id is not None and execution.agent_id != agent_id):
        raise ExecutionNotFoundError(f"execution {execution_id} not found")
    if agent_id is not None and gateway.access.is_privileged(execution.action):
        raise InfraOnlyError(PRIVILEGED_HIDDEN)
    view = _execution_view(execution, await _names(gateway))
    # Results were redacted when the execution ran (P2); nothing secret is stored.
    return ExecutionDetail(
        **view.model_dump(),
        params=execution.params,
        result=None if execution.result is None else execution.result.model_dump(mode="json"),
    )


def _execution_view(execution: Execution, names: _Names) -> ExecutionView:
    duration: int | None = None
    if execution.started_at is not None and execution.finished_at is not None:
        delta = execution.finished_at - execution.started_at
        duration = max(0, int(delta.total_seconds() * 1000))
    return ExecutionView(
        id=execution.id,
        action=execution.action,
        resource=names.resource(execution.resource_id),
        agent=names.agent(execution.agent_id),
        subject=execution.user_subject,
        status=execution.status.value,
        decision_reason=None if execution.decision is None else execution.decision.reason,
        correlation_id=execution.correlation_id,
        created_at=to_rfc3339(execution.created_at),
        finished_at=None if execution.finished_at is None else to_rfc3339(execution.finished_at),
        duration_ms=duration,
        error=execution.error,
    )


# ---- audit (contract §12) ----------------------------------------------------------------


async def audit_page(
    gateway: Gateway,
    principal: Principal,
    *,
    since: datetime | None,
    until: datetime | None,
    event: AuditEventType | None,
    subject: str | None,
    limit: int,
    cursor: str | None,
) -> AuditPage:
    before: int | None = None
    if cursor is not None:
        if not cursor.isdigit():
            raise InvalidParamsError("cursor: not a cursor this endpoint returned")
        before = int(cursor)
    agent_id = _calling_agent(principal)
    names = await _names(gateway)
    executions: dict[str, Execution | None] = {}

    async def execution_of(entry: AuditEntry) -> Execution | None:
        if entry.execution_id is None:
            return None
        if entry.execution_id not in executions:
            executions[entry.execution_id] = await gateway.executions.get(entry.execution_id)
        return executions[entry.execution_id]

    found: list[AuditEntryView] = []
    entries = await gateway.audit.query(since=since, until=until, event=event)
    for entry in sorted(entries, key=lambda e: e.seq, reverse=True):
        if before is not None and entry.seq >= before:
            continue
        execution = await execution_of(entry)
        if agent_id is not None and not _through(gateway, entry, execution, agent_id):
            continue
        if subject is not None and subject not in _subjects(entry, execution):
            continue
        found.append(_audit_view(entry, execution, names))
        if len(found) > limit:
            break
    page = found[:limit]
    next_cursor = str(page[-1].seq) if len(found) > limit else None
    return AuditPage(items=page, next_cursor=next_cursor)


def _through(
    gateway: Gateway, entry: AuditEntry, execution: Execution | None, agent_id: str
) -> bool:
    """Whether ``entry`` happened through ``agent_id`` and is not infra-only."""
    if entry.event in _INFRA_EVENTS:
        return False
    if entry.action is not None and gateway.access.is_privileged(entry.action):
        return False
    if entry.execution_id is not None:
        return (
            execution is not None
            and execution.agent_id == agent_id
            and not gateway.access.is_privileged(execution.action)
        )
    if entry.actor.type is ActorType.AGENT and entry.actor.id == agent_id:
        return True
    return entry.details.get("via_agent") == agent_id


def _subjects(entry: AuditEntry, execution: Execution | None) -> set[str]:
    found: set[str] = set()
    if entry.actor.type is ActorType.USER:
        found.add(entry.actor.id)
    user = entry.details.get("user")
    if isinstance(user, str):
        found.add(user)
    if execution is not None and execution.user_subject is not None:
        found.add(execution.user_subject)
    return found


def _audit_view(entry: AuditEntry, execution: Execution | None, names: _Names) -> AuditEntryView:
    actor = entry.actor
    via = entry.details.get("via_agent")
    subject: str | None = None
    via_agent: str | None = names.agent(via) if isinstance(via, str) else None
    if actor.type is ActorType.USER:
        subject = actor.id
    elif actor.type is ActorType.AGENT:
        via_agent = names.agent(actor.id)
        user = entry.details.get("user")
        subject = user if isinstance(user, str) else None
    elif actor.type is ActorType.ADMIN:
        subject = actor.id
    if via_agent is None and execution is not None:
        via_agent = names.agent(execution.agent_id)
    outcome = _OUTCOMES.get(entry.event, "ok")
    detail_outcome = entry.details.get("outcome")
    if isinstance(detail_outcome, str):
        outcome = detail_outcome
    target = entry.execution_id or (
        names.resource(entry.resource_id) if entry.resource_id is not None else None
    )
    details: dict[str, Any] = dict(entry.details)
    if entry.action is not None:
        details.setdefault("action", entry.action)
    if entry.resource_id is not None:
        details.setdefault("resource", names.resource(entry.resource_id))
    return AuditEntryView(
        seq=entry.seq,
        at=to_rfc3339(entry.ts),
        event=entry.event.value,
        actor=AuditActor(kind=_ACTOR_KIND[actor.type], subject=subject, via_agent=via_agent),
        target=target or _target_from_details(entry.details),
        outcome=outcome,
        details=details,
    )


def _target_from_details(details: dict[str, Any]) -> str | None:
    for key in ("plan_id", "approval_id", "policy_id", "user_id", "role", "agent_id"):
        value = details.get(key)
        if isinstance(value, str):
            return value
    return None
