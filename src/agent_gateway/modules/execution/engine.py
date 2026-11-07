"""The single execution pipeline behind REST and MCP (SPEC §12, P6).

submit: idempotency -> resolve action -> validate params -> resolve resource ->
authorize -> (approval) -> run broker -> audit. Every step that changes state is audited
first, so an unavailable audit log stops the pipeline (fail closed, SPEC §14.4).
"""

import asyncio
import logging
from collections import defaultdict
from datetime import timedelta
from typing import Any

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.common.canonical import sha256_digest
from agent_gateway.common.clock import Clock
from agent_gateway.common.errors import (
    ActionNotAllowedError,
    ActionNotFoundError,
    ExecutionNotFoundError,
    GatewayError,
    ResourceNotFoundError,
)
from agent_gateway.common.ids import IdPrefix, new_id
from agent_gateway.config import ExecutionSettings
from agent_gateway.modules.action_registry.models import RegisteredAction
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.approvals.models import Approval, ApprovalStatus
from agent_gateway.modules.approvals.ports import ApprovalService
from agent_gateway.modules.audit.models import Actor, ActorType, AuditEventType, AuditRecord
from agent_gateway.modules.audit.ports import AuditLog
from agent_gateway.modules.authorization.engine import grants, selector_matches
from agent_gateway.modules.authorization.models import (
    AuthorizationRequest,
    Decision,
    Policy,
    PolicyEffect,
    Role,
)
from agent_gateway.modules.authorization.ports import PolicyEngine
from agent_gateway.modules.credentials.models import SecretPayload
from agent_gateway.modules.credentials.ports import CredentialStore
from agent_gateway.modules.elevation.service import ElevationService
from agent_gateway.modules.execution.models import Execution, ExecutionRequest, ExecutionStatus
from agent_gateway.modules.execution.ports import ExecutionStore
from agent_gateway.modules.execution.redact import redact
from agent_gateway.modules.identity.models import Principal, TokenKind
from agent_gateway.modules.resources.models import Resource
from agent_gateway.modules.resources.ports import ResourceRegistry
from agent_gateway.modules.storage.ports import Collection

IDEMPOTENCY_WINDOW = timedelta(hours=24)
# How far back the dispatcher looks for decided approvals whose execution still waits.
DISPATCH_WINDOW = timedelta(days=2)
SYSTEM_ACTOR = Actor(type=ActorType.SYSTEM, id="execution")
INTERRUPTED = "interrupted: the gateway stopped while this execution was running"
BROKER_FAILED = "the broker failed; see server logs"
TIMED_OUT = "the action timed out"


class GatewayExecutionEngine:
    def __init__(
        self,
        *,
        executions: ExecutionStore,
        registry: ActionRegistry,
        resources: ResourceRegistry,
        credentials: CredentialStore,
        roles: Collection[Role],
        policies: Collection[Policy],
        policy_engine: PolicyEngine,
        approvals: ApprovalService,
        audit: AuditLog,
        clock: Clock,
        settings: ExecutionSettings,
        elevations: ElevationService | None = None,
        elevation_minutes: int = 0,
        logger: logging.Logger | None = None,
    ) -> None:
        self._executions = executions
        self._registry = registry
        self._resources = resources
        self._credentials = credentials
        self._roles = roles
        self._policies = policies
        self._policy_engine = policy_engine
        self._approvals = approvals
        self._audit = audit
        self._clock = clock
        self._settings = settings
        self._elevations = elevations
        self._elevation_minutes = elevation_minutes
        self._log = logger or logging.getLogger("agent_gateway.execution")
        self._global_slots = asyncio.Semaphore(settings.max_concurrent)
        self._resource_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._tasks: set[asyncio.Task[Execution]] = set()
        self._scheduled: set[str] = set()

    # ---- submit -------------------------------------------------------------------------

    async def submit(self, principal: Principal, request: ExecutionRequest) -> Execution:
        agent_id = _require_agent(principal)
        actor = Actor(type=ActorType.AGENT, id=agent_id)

        if request.idempotency_key is not None:
            existing = await self._find_idempotent(
                agent_id,
                principal.user.subject if principal.user else None,
                request.idempotency_key,
            )
            if existing is not None:
                return existing

        registered = self._registry.get(request.action)
        if registered is None:
            await self._reject(actor, request, "action not found")
            raise ActionNotFoundError(f"action {request.action!r} not found")
        try:
            params = self._registry.validate_params(request.action, request.params)
        except GatewayError:
            await self._reject(actor, request, "invalid params")
            raise
        resource = await self._resources.get(request.resource_id)
        if resource is None:
            await self._reject(actor, request, "resource not found")
            raise ResourceNotFoundError(f"resource {request.resource_id!r} not found")

        normalized = params.model_dump(mode="json")
        decision = self._policy_engine.decide(
            AuthorizationRequest(
                principal=principal,
                action=registered.definition,
                resource=resource,
                roles=await self._roles.all(),
                policies=await self._policies.all(),
                now=self._clock.now(),
            )
        )
        decision = await self._apply_elevation(decision, registered, agent_id, resource.id)
        execution = Execution(
            id=new_id(IdPrefix.EXECUTION),
            agent_id=agent_id,
            user_subject=principal.user.subject if principal.user else None,
            action=request.action,
            resource_id=resource.id,
            params=normalized,
            params_digest=sha256_digest(normalized),
            idempotency_key=request.idempotency_key,
            status=ExecutionStatus.PENDING_APPROVAL,
            decision=decision,
            created_at=self._clock.now(),
        )
        await self._record(
            AuditEventType.EXECUTION_REQUESTED,
            execution,
            actor,
            {"user": execution.user_subject} if execution.user_subject else None,
        )

        if not decision.allowed:
            denied = execution.model_copy(
                update={"status": ExecutionStatus.DENIED, "finished_at": self._clock.now()}
            )
            await self._record(
                AuditEventType.EXECUTION_DENIED, denied, actor, {"reason": decision.reason}
            )
            await self._executions.put(denied)
            raise ActionNotAllowedError(
                "agent is not allowed to run this action on this resource",
                execution_id=denied.id,
            )

        if decision.approval_required:
            await self._executions.put(execution)
            approval = await self._approvals.request(execution.id, execution.params_digest)
            return await self._executions.update(
                execution.id, lambda e: e.model_copy(update={"approval_id": approval.id})
            )

        approved = execution.model_copy(update={"status": ExecutionStatus.APPROVED})
        await self._executions.put(approved)
        return await self._run(approved, registered, resource)

    # ---- queries ------------------------------------------------------------------------

    async def get(self, principal: Principal, execution_id: str) -> Execution:
        execution = await self._executions.get(execution_id)
        if execution is None or not _visible(principal, execution):
            raise ExecutionNotFoundError(f"execution {execution_id} not found")
        return execution

    async def list_for(
        self, principal: Principal, *, cursor: str | None = None, limit: int = 50
    ) -> tuple[list[Execution], str | None]:
        limit = max(1, min(limit, 200))
        agent_id = None if principal.is_admin else _require_agent(principal)
        items = await self._executions.page(agent_id=agent_id, before=cursor, limit=limit + 1)
        next_cursor = items[limit - 1].id if len(items) > limit else None
        return items[:limit], next_cursor

    async def visible_actions(self, principal: Principal) -> list[RegisteredAction]:
        """Actions covered by the caller's roles. Policies still decide per resource."""
        roles = [r for r in await self._roles.all() if r.id in principal.roles]
        return [
            action
            for action in self._registry.all()
            if any(grants(r.actions, action.definition) for r in roles)
        ]

    async def visible_resources(self, principal: Principal) -> list[Resource]:
        """Resources selected by at least one live allow policy for the caller."""
        now = self._clock.now()
        policies = [
            p
            for p in await self._policies.all()
            if p.effect is PolicyEffect.ALLOW
            and (p.expires_at is None or p.expires_at > now)
            and _subject_matches(p, principal)
        ]
        return [
            r
            for r in await self._resources.list()
            if any(selector_matches(p.resources, r) for p in policies)
        ]

    # ---- approvals and lifecycle ----------------------------------------------------------

    async def dispatch_approvals(self) -> None:
        """Move executions forward once their approval is decided or expired.

        Called periodically by the server and right after an approval via the API, so
        decisions made from the CLI (another process) are picked up too.
        """
        await self._approvals.expire_due()
        since = self._clock.now() - DISPATCH_WINDOW
        for approval in await self._approvals.find():
            if approval.status is ApprovalStatus.PENDING or approval.requested_at < since:
                continue
            execution = await self._executions.get(approval.execution_id)
            if execution is None or execution.status is not ExecutionStatus.PENDING_APPROVAL:
                continue
            await self._apply_approval(execution, approval)

    async def recover(self) -> None:
        """At startup: fail executions cut off mid-run, resume approved ones (SPEC §12)."""
        for execution in await self._executions.recent(since=self._clock.now() - DISPATCH_WINDOW):
            if execution.status is ExecutionStatus.RUNNING:
                failed = await self._finish(execution, None, error=INTERRUPTED)
                await self._record(AuditEventType.EXECUTION_FAILED, failed, SYSTEM_ACTOR)
            elif execution.status is ExecutionStatus.APPROVED:
                self._schedule(execution)

    async def drain(self) -> None:
        """Wait for background executions; used by tests and graceful shutdown."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def _apply_approval(self, execution: Execution, approval: Approval) -> None:
        if approval.status is ApprovalStatus.APPROVED:
            if approval.params_digest != execution.params_digest:
                failed = await self._finish(execution, None, error="approval does not match params")
                await self._record(AuditEventType.EXECUTION_FAILED, failed, SYSTEM_ACTOR)
                return
            approved = await self._executions.update(
                execution.id, lambda e: e.model_copy(update={"status": ExecutionStatus.APPROVED})
            )
            await self._open_elevation(approved, approval)
            self._schedule(approved)
            return
        status = (
            ExecutionStatus.REJECTED
            if approval.status is ApprovalStatus.REJECTED
            else ExecutionStatus.EXPIRED
        )
        event = (
            AuditEventType.EXECUTION_REJECTED
            if status is ExecutionStatus.REJECTED
            else AuditEventType.EXECUTION_FAILED
        )
        closed = await self._executions.update(
            execution.id,
            lambda e: e.model_copy(update={"status": status, "finished_at": self._clock.now()}),
        )
        await self._record(event, closed, SYSTEM_ACTOR, {"approval_status": str(approval.status)})

    async def _apply_elevation(
        self, decision: Decision, registered: RegisteredAction, agent_id: str, resource_id: str
    ) -> Decision:
        """Inside an open window, a privileged action that policy allows skips approval.

        A window never turns a deny into an allow, and only covers the exact agent,
        resource, and action it was opened for.
        """
        definition = registered.definition
        if (
            self._elevations is None
            or not definition.privileged
            or not decision.allowed
            or not decision.approval_required
        ):
            return decision
        window = await self._elevations.active_for(agent_id, resource_id, definition.id)
        if window is None:
            return decision
        return decision.model_copy(
            update={
                "approval_required": False,
                "reason": f"{decision.reason}; elevated by {window.id} until "
                f"{window.expires_at.isoformat()}",
            }
        )

    async def _open_elevation(self, execution: Execution, approval: Approval) -> None:
        """Approving a privileged action opens a window for the same agent and resource."""
        registered = self._registry.get(execution.action)
        if (
            self._elevations is None
            or self._elevation_minutes <= 0
            or registered is None
            or not registered.definition.privileged
        ):
            return
        if await self._elevations.active_for(
            execution.agent_id, execution.resource_id, execution.action
        ):
            return
        decided_by = approval.decided_by or "unknown"
        await self._elevations.grant(
            agent_id=execution.agent_id,
            resource_id=execution.resource_id,
            action=execution.action,
            minutes=self._elevation_minutes,
            actor=Actor(type=ActorType.ADMIN, id=decided_by),
            approval_id=approval.id,
        )

    def _schedule(self, execution: Execution) -> None:
        if execution.id in self._scheduled:
            return
        self._scheduled.add(execution.id)
        task = asyncio.create_task(self._run_by_id(execution.id))
        self._tasks.add(task)

        def done(t: asyncio.Task[Execution]) -> None:
            self._tasks.discard(t)
            self._scheduled.discard(execution.id)
            if not t.cancelled() and t.exception() is not None:
                self._log.error(
                    "background execution %s failed", execution.id, exc_info=t.exception()
                )

        task.add_done_callback(done)

    async def _run_by_id(self, execution_id: str) -> Execution:
        execution = await self._executions.get(execution_id)
        if execution is None:
            raise ExecutionNotFoundError(execution_id)
        registered = self._registry.get(execution.action)
        resource = await self._resources.get(execution.resource_id)
        if registered is None or resource is None:
            failed = await self._finish(
                execution, None, error="action or resource no longer exists"
            )
            await self._record(AuditEventType.EXECUTION_FAILED, failed, SYSTEM_ACTOR)
            return failed
        return await self._run(execution, registered, resource)

    # ---- running ------------------------------------------------------------------------

    async def _run(
        self, execution: Execution, registered: RegisteredAction, resource: Resource
    ) -> Execution:
        definition = registered.definition
        async with self._global_slots, self._resource_locks[resource.id]:
            await self._record(AuditEventType.EXECUTION_STARTED, execution, SYSTEM_ACTOR)
            running = await self._executions.update(
                execution.id,
                lambda e: e.model_copy(
                    update={"status": ExecutionStatus.RUNNING, "started_at": self._clock.now()}
                ),
            )
            credential: SecretPayload | None = None
            secrets: list[str] = []
            try:
                if resource.credential_id is not None:
                    credential = await self._credentials.open(resource.credential_id)
                    secrets = credential.secret_values()
                params = definition.input_model.model_validate(running.params)
                ctx = ActionContext(
                    execution_id=running.id,
                    agent_id=running.agent_id,
                    resource=resource,
                    credential=credential,
                    timeout_seconds=definition.timeout_seconds,
                    output_limit_bytes=self._settings.output_limit_bytes,
                    logger=self._log.getChild(definition.broker),
                )
                result = await asyncio.wait_for(
                    registered.handler(ctx, params), timeout=definition.timeout_seconds
                )
                if not isinstance(result, ActionResult):
                    raise TypeError(f"{definition.id} returned {type(result).__name__}")
            except TimeoutError:
                result = ActionResult(ok=False, error=TIMED_OUT)
            except Exception:
                self._log.exception(
                    "execution %s failed in broker %s", running.id, definition.broker
                )
                result = ActionResult(ok=False, error=BROKER_FAILED)
            finally:
                if credential is not None:
                    credential.wipe()

            safe = ActionResult.model_validate(redact(result.model_dump(mode="json"), secrets))
            finished = await self._finish(running, safe)
            event = (
                AuditEventType.EXECUTION_SUCCEEDED if safe.ok else AuditEventType.EXECUTION_FAILED
            )
            await self._record(event, finished, SYSTEM_ACTOR, {"ok": safe.ok})
            return finished

    async def _finish(
        self, execution: Execution, result: ActionResult | None, *, error: str | None = None
    ) -> Execution:
        ok = result is not None and result.ok
        update: dict[str, Any] = {
            "status": ExecutionStatus.SUCCEEDED if ok else ExecutionStatus.FAILED,
            "result": result,
            "error": error
            if error is not None
            else (None if ok or result is None else result.error),
            "finished_at": self._clock.now(),
        }
        return await self._executions.update(execution.id, lambda e: e.model_copy(update=update))

    # ---- helpers ------------------------------------------------------------------------

    async def _find_idempotent(
        self, agent_id: str, user_subject: str | None, key: str
    ) -> Execution | None:
        since = self._clock.now() - IDEMPOTENCY_WINDOW
        for execution in await self._executions.recent(since=since):
            if (
                execution.agent_id == agent_id
                and execution.user_subject == user_subject
                and execution.idempotency_key == key
            ):
                return execution
        return None

    async def _reject(self, actor: Actor, request: ExecutionRequest, reason: str) -> None:
        await self._audit.append(
            AuditRecord(
                event=AuditEventType.EXECUTION_REJECTED,
                actor=actor,
                action=request.action[:128],
                resource_id=request.resource_id[:64],
                details={"reason": reason},
            )
        )

    async def _record(
        self,
        event: AuditEventType,
        execution: Execution,
        actor: Actor,
        details: dict[str, Any] | None = None,
    ) -> None:
        await self._audit.append(
            AuditRecord(
                event=event,
                actor=actor,
                execution_id=execution.id,
                action=execution.action,
                resource_id=execution.resource_id,
                params_digest=execution.params_digest,
                details=details or {},
            )
        )


def _require_agent(principal: Principal) -> str:
    if principal.kind is not TokenKind.AGENT or principal.agent_id is None:
        raise ActionNotAllowedError("only agent tokens can run actions")
    return principal.agent_id


def _visible(principal: Principal, execution: Execution) -> bool:
    return principal.is_admin or execution.agent_id == principal.agent_id


def _subject_matches(policy: Policy, principal: Principal) -> bool:
    subject = policy.subject
    if subject.agent_id is not None:
        return subject.agent_id == principal.agent_id
    return subject.role in principal.roles
