"""Admin operations shared by the REST admin API and the ``agw`` CLI.

Every method requires an admin principal and writes one audit entry per change. Secrets
go in through ``create_credential`` / ``rotate_credential`` and never come back out.
"""

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from agent_gateway.common.clock import Clock
from agent_gateway.common.errors import (
    AdminRequiredError,
    AgentNotFoundError,
    NotFoundError,
)
from agent_gateway.common.ids import IdPrefix, new_id
from agent_gateway.modules.approvals.models import Approval, ApprovalStatus
from agent_gateway.modules.approvals.ports import ApprovalService
from agent_gateway.modules.audit.models import (
    Actor,
    ActorType,
    AuditEntry,
    AuditEventType,
    AuditRecord,
    VerifyResult,
)
from agent_gateway.modules.audit.ports import AuditLog
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    Policy,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialMeta, SecretPayload
from agent_gateway.modules.credentials.ports import CredentialStore
from agent_gateway.modules.identity.models import (
    Agent,
    AgentStatus,
    IssuedToken,
    Principal,
    Token,
    TokenKind,
)
from agent_gateway.modules.identity.ports import IdentityService
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.modules.resources.ports import ResourceRegistry
from agent_gateway.modules.storage.ports import Collection, ItemNotFoundError

# Principal used by the local CLI: whoever can read the master key file is the admin.
CLI_PRINCIPAL = Principal(kind=TokenKind.ADMIN, token_id="cli")  # noqa: S106 - an actor id, not a secret


class AdminService:
    def __init__(
        self,
        *,
        identity: IdentityService,
        resources: ResourceRegistry,
        credentials: CredentialStore,
        roles: Collection[Role],
        policies: Collection[Policy],
        approvals: ApprovalService,
        audit: AuditLog,
        clock: Clock,
    ) -> None:
        self._identity = identity
        self._resources = resources
        self._credentials = credentials
        self._roles = roles
        self._policies = policies
        self._approvals = approvals
        self._audit = audit
        self._clock = clock

    # ---- agents and tokens ----------------------------------------------------------------

    async def list_agents(self, actor: Principal) -> list[Agent]:
        _require_admin(actor)
        return await self._identity.list_agents()

    async def create_agent(
        self, actor: Principal, name: str, *, description: str = "", roles: Sequence[str] = ()
    ) -> Agent:
        _require_admin(actor)
        agent = await self._identity.create_agent(name, description=description, roles=roles)
        await self._record(actor, AuditEventType.AGENT_CREATED, {"agent_id": agent.id})
        return agent

    async def update_agent(
        self,
        actor: Principal,
        agent_id: str,
        *,
        description: str | None = None,
        roles: Sequence[str] | None = None,
        status: AgentStatus | None = None,
    ) -> Agent:
        _require_admin(actor)
        if await self._identity.get_agent(agent_id) is None:
            raise AgentNotFoundError(f"agent {agent_id} not found")
        agent = await self._identity.update_agent(
            agent_id, description=description, roles=roles, status=status
        )
        await self._record(
            actor,
            AuditEventType.AGENT_UPDATED,
            {"agent_id": agent.id, "status": str(agent.status), "roles": list(agent.roles)},
        )
        return agent

    async def list_tokens(self, actor: Principal, *, agent_id: str | None = None) -> list[Token]:
        _require_admin(actor)
        return await self._identity.list_tokens(agent_id=agent_id)

    async def issue_token(
        self,
        actor: Principal,
        kind: TokenKind,
        *,
        agent_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> IssuedToken:
        _require_admin(actor)
        if agent_id is not None and await self._identity.get_agent(agent_id) is None:
            raise AgentNotFoundError(f"agent {agent_id} not found")
        issued = await self._identity.issue_token(kind, agent_id=agent_id, expires_at=expires_at)
        await self._record(
            actor,
            AuditEventType.TOKEN_CREATED,
            {"token_id": issued.token.id, "kind": str(kind), "agent_id": agent_id},
        )
        return issued

    async def revoke_token(self, actor: Principal, token_id: str) -> Token:
        _require_admin(actor)
        token = await self._identity.revoke_token(token_id)
        await self._record(actor, AuditEventType.TOKEN_REVOKED, {"token_id": token.id})
        return token

    # ---- resources and credentials --------------------------------------------------------

    async def list_resources(
        self, actor: Principal, *, type: ResourceType | None = None
    ) -> list[Resource]:
        _require_admin(actor)
        return await self._resources.list(type=type)

    async def create_resource(
        self,
        actor: Principal,
        type: ResourceType,
        name: str,
        *,
        tags: Sequence[str] = (),
        attributes: Mapping[str, Any] | None = None,
        credential_id: str | None = None,
    ) -> Resource:
        _require_admin(actor)
        await self._require_credential(credential_id)
        resource = await self._resources.create(
            type, name, tags=tags, attributes=attributes, credential_id=credential_id
        )
        await self._record(actor, AuditEventType.RESOURCE_CREATED, {"resource_id": resource.id})
        return resource

    async def update_resource(
        self,
        actor: Principal,
        resource_id: str,
        *,
        name: str | None = None,
        tags: Sequence[str] | None = None,
        attributes: Mapping[str, Any] | None = None,
        credential_id: str | None = None,
    ) -> Resource:
        _require_admin(actor)
        await self._require_credential(credential_id)
        resource = await self._resources.update(
            resource_id, name=name, tags=tags, attributes=attributes, credential_id=credential_id
        )
        await self._record(actor, AuditEventType.RESOURCE_UPDATED, {"resource_id": resource.id})
        return resource

    async def delete_resource(self, actor: Principal, resource_id: str) -> bool:
        _require_admin(actor)
        deleted = await self._resources.delete(resource_id)
        if deleted:
            await self._record(actor, AuditEventType.RESOURCE_DELETED, {"resource_id": resource_id})
        return deleted

    async def list_credentials(self, actor: Principal) -> list[CredentialMeta]:
        _require_admin(actor)
        return await self._credentials.list_meta()

    async def create_credential(
        self, actor: Principal, name: str, payload: SecretPayload
    ) -> CredentialMeta:
        _require_admin(actor)
        meta = await self._credentials.create(name, payload)
        await self._record(actor, AuditEventType.CREDENTIAL_CREATED, {"credential_id": meta.id})
        return meta

    async def rotate_credential(
        self, actor: Principal, credential_id: str, payload: SecretPayload
    ) -> CredentialMeta:
        _require_admin(actor)
        meta = await self._credentials.rotate(credential_id, payload)
        await self._record(
            actor,
            AuditEventType.CREDENTIAL_ROTATED,
            {"credential_id": meta.id, "version": meta.version},
        )
        return meta

    async def delete_credential(self, actor: Principal, credential_id: str) -> bool:
        _require_admin(actor)
        deleted = await self._credentials.delete(credential_id)
        if deleted:
            await self._record(
                actor, AuditEventType.CREDENTIAL_DELETED, {"credential_id": credential_id}
            )
        return deleted

    # ---- roles and policies ---------------------------------------------------------------

    async def list_roles(self, actor: Principal) -> list[Role]:
        _require_admin(actor)
        return sorted(await self._roles.all(), key=lambda r: r.id)

    async def put_role(self, actor: Principal, role: Role) -> Role:
        _require_admin(actor)
        await self._roles.put(role)
        await self._record(
            actor, AuditEventType.ROLE_UPDATED, {"role": role.id, "actions": list(role.actions)}
        )
        return role

    async def delete_role(self, actor: Principal, role_id: str) -> bool:
        _require_admin(actor)
        deleted = await self._roles.delete(role_id)
        if deleted:
            await self._record(
                actor, AuditEventType.ROLE_UPDATED, {"role": role_id, "deleted": True}
            )
        return deleted

    async def list_policies(self, actor: Principal) -> list[Policy]:
        _require_admin(actor)
        return sorted(await self._policies.all(), key=lambda p: p.id)

    async def create_policy(
        self,
        actor: Principal,
        *,
        subject: PolicySubject,
        actions: Sequence[str],
        resources: ResourceSelector,
        effect: PolicyEffect,
        approval: ApprovalMode = ApprovalMode.BY_RISK,
        expires_at: datetime | None = None,
    ) -> Policy:
        _require_admin(actor)
        policy = Policy(
            id=new_id(IdPrefix.POLICY),
            subject=subject,
            actions=tuple(actions),
            resources=resources,
            effect=effect,
            approval=approval,
            expires_at=expires_at,
        )
        await self._policies.put(policy)
        await self._record(actor, AuditEventType.POLICY_CREATED, _policy_details(policy))
        return policy

    async def replace_policy(self, actor: Principal, policy: Policy) -> Policy:
        _require_admin(actor)
        try:
            await self._policies.update(policy.id, lambda _: policy)
        except ItemNotFoundError:
            raise NotFoundError(f"policy {policy.id} not found") from None
        await self._record(actor, AuditEventType.POLICY_UPDATED, _policy_details(policy))
        return policy

    async def delete_policy(self, actor: Principal, policy_id: str) -> bool:
        _require_admin(actor)
        deleted = await self._policies.delete(policy_id)
        if deleted:
            await self._record(actor, AuditEventType.POLICY_DELETED, {"policy_id": policy_id})
        return deleted

    # ---- approvals and audit --------------------------------------------------------------

    async def list_approvals(
        self, actor: Principal, *, status: ApprovalStatus | None = None
    ) -> list[Approval]:
        _require_admin(actor)
        return await self._approvals.find(status=status)

    async def approve(self, actor: Principal, approval_id: str) -> Approval:
        return await self._approvals.approve(approval_id, actor)

    async def reject(
        self, actor: Principal, approval_id: str, reason: str | None = None
    ) -> Approval:
        return await self._approvals.reject(approval_id, actor, reason)

    async def audit_entries(
        self,
        actor: Principal,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        event: AuditEventType | None = None,
    ) -> list[AuditEntry]:
        _require_admin(actor)
        return await self._audit.query(since=since, until=until, event=event)

    async def verify_audit(self, actor: Principal) -> VerifyResult:
        _require_admin(actor)
        return await self._audit.verify()

    # ---- helpers --------------------------------------------------------------------------

    async def _require_credential(self, credential_id: str | None) -> None:
        if credential_id is not None and await self._credentials.get_meta(credential_id) is None:
            raise NotFoundError(f"credential {credential_id} not found")

    async def _record(
        self, actor: Principal, event: AuditEventType, details: dict[str, Any]
    ) -> None:
        await self._audit.append(
            AuditRecord(
                event=event,
                actor=Actor(type=ActorType.ADMIN, id=actor.token_id),
                resource_id=details.get("resource_id"),
                details=details,
            )
        )


def _require_admin(actor: Principal) -> None:
    if not actor.is_admin:
        raise AdminRequiredError("admin token required")


def _policy_details(policy: Policy) -> dict[str, Any]:
    return {"policy_id": policy.id, **policy.model_dump(mode="json", exclude={"id"})}
