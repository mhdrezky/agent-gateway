"""Admin endpoints (SPEC §15.2).

Infra routes take the static admin token only (``AdminDep``); an access admin signed in
through an agent gets ``403 infra_only`` there. The reads in the left column of the admin
contract (SPEC §23) also take an access admin (``AccessAdminDep``) and then answer in the
contract's shapes, scoped to the calling agent; the static admin token gets the same
answers as before.
"""

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query, status

from agent_gateway.apps.api_server import admin_history
from agent_gateway.apps.api_server.deps import (
    AccessAdminDep,
    AdminDep,
    GatewayDep,
    require_static,
)
from agent_gateway.apps.api_server.schemas import (
    AgentCreate,
    AgentUpdate,
    CredentialCreate,
    CredentialSecret,
    IssuedTokenOut,
    PolicyBody,
    RejectBody,
    ResourceCreate,
    ResourceUpdate,
    RoleBody,
    TokenCreate,
)
from agent_gateway.common.errors import InvalidParamsError, NotFoundError
from agent_gateway.modules.administration.access_models import (
    AdminApprovalView,
    AuditPage,
    ResourceView,
    RoleView,
    UserPolicy,
)
from agent_gateway.modules.approvals.models import Approval, ApprovalStatus
from agent_gateway.modules.audit.models import AuditEntry, AuditEventType, VerifyResult
from agent_gateway.modules.authorization.models import Policy, Role
from agent_gateway.modules.credentials.models import CredentialMeta, CredentialType, SecretPayload
from agent_gateway.modules.identity.models import Agent, IssuedToken, Token, TokenKind
from agent_gateway.modules.resources.models import Resource, ResourceType

router = APIRouter(prefix="/v1/admin")


def _issued(issued: IssuedToken) -> IssuedTokenOut:
    return IssuedTokenOut(token=issued.token, plaintext=issued.plaintext.get_secret_value())


def _payload(body: CredentialSecret, type_: CredentialType) -> SecretPayload:
    return SecretPayload(
        type_,
        body.value.get_secret_value(),
        {k: v.get_secret_value() for k, v in body.fields.items()},
    )


def _found(deleted: bool, what: str) -> None:
    if not deleted:
        raise NotFoundError(f"{what} not found")


# ---- agents and tokens ------------------------------------------------------------------


@router.get("/agents")
async def list_agents(gateway: GatewayDep, actor: AdminDep) -> list[Agent]:
    return await gateway.admin.list_agents(actor)


@router.post("/agents", status_code=status.HTTP_201_CREATED)
async def create_agent(body: AgentCreate, gateway: GatewayDep, actor: AdminDep) -> Agent:
    return await gateway.admin.create_agent(
        actor, body.name, description=body.description, roles=body.roles
    )


@router.patch("/agents/{agent_id}")
async def update_agent(
    agent_id: str, body: AgentUpdate, gateway: GatewayDep, actor: AdminDep
) -> Agent:
    return await gateway.admin.update_agent(
        actor, agent_id, description=body.description, roles=body.roles, status=body.status
    )


@router.get("/tokens")
async def list_tokens(
    gateway: GatewayDep, actor: AdminDep, agent_id: str | None = None
) -> list[Token]:
    return await gateway.admin.list_tokens(actor, agent_id=agent_id)


@router.post("/agents/{agent_id}/tokens", status_code=status.HTTP_201_CREATED)
async def issue_agent_token(
    agent_id: str, body: TokenCreate, gateway: GatewayDep, actor: AdminDep
) -> IssuedTokenOut:
    issued = await gateway.admin.issue_token(
        actor, TokenKind.AGENT, agent_id=agent_id, expires_at=body.expires_at
    )
    return _issued(issued)


@router.post("/tokens", status_code=status.HTTP_201_CREATED)
async def issue_admin_token(
    body: TokenCreate, gateway: GatewayDep, actor: AdminDep
) -> IssuedTokenOut:
    return _issued(
        await gateway.admin.issue_token(actor, TokenKind.ADMIN, expires_at=body.expires_at)
    )


@router.delete("/tokens/{token_id}")
async def revoke_token(token_id: str, gateway: GatewayDep, actor: AdminDep) -> Token:
    return await gateway.admin.revoke_token(actor, token_id)


# ---- resources and credentials ----------------------------------------------------------


@router.get("/resources")
async def list_resources(
    gateway: GatewayDep, actor: AccessAdminDep, type: ResourceType | None = None
) -> list[Resource] | list[ResourceView]:
    if not actor.is_admin:
        # An access admin sees no attributes and no credential id (SPEC §23).
        return [v for v in await gateway.access.resource_views() if type is None or v.type == type]
    return await gateway.admin.list_resources(actor, type=type)


@router.post("/resources", status_code=status.HTTP_201_CREATED)
async def create_resource(body: ResourceCreate, gateway: GatewayDep, actor: AdminDep) -> Resource:
    return await gateway.admin.create_resource(
        actor,
        body.type,
        body.name,
        tags=body.tags,
        attributes=body.attributes,
        credential_id=body.credential_id,
    )


@router.patch("/resources/{resource_id}")
async def update_resource(
    resource_id: str, body: ResourceUpdate, gateway: GatewayDep, actor: AdminDep
) -> Resource:
    return await gateway.admin.update_resource(
        actor,
        resource_id,
        name=body.name,
        tags=body.tags,
        attributes=body.attributes,
        credential_id=body.credential_id,
    )


@router.delete("/resources/{resource_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_resource(resource_id: str, gateway: GatewayDep, actor: AdminDep) -> None:
    _found(await gateway.admin.delete_resource(actor, resource_id), f"resource {resource_id}")


@router.get("/credentials")
async def list_credentials(gateway: GatewayDep, actor: AdminDep) -> list[CredentialMeta]:
    return await gateway.admin.list_credentials(actor)


@router.post("/credentials", status_code=status.HTTP_201_CREATED)
async def create_credential(
    body: CredentialCreate, gateway: GatewayDep, actor: AdminDep
) -> CredentialMeta:
    return await gateway.admin.create_credential(actor, body.name, _payload(body, body.type))


@router.put("/credentials/{credential_id}")
async def rotate_credential(
    credential_id: str, body: CredentialSecret, gateway: GatewayDep, actor: AdminDep
) -> CredentialMeta:
    current = next(
        (c for c in await gateway.admin.list_credentials(actor) if c.id == credential_id), None
    )
    if current is None:
        raise NotFoundError(f"credential {credential_id} not found")
    return await gateway.admin.rotate_credential(actor, credential_id, _payload(body, current.type))


@router.delete("/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(credential_id: str, gateway: GatewayDep, actor: AdminDep) -> None:
    _found(
        await gateway.admin.delete_credential(actor, credential_id), f"credential {credential_id}"
    )


# ---- roles and policies -----------------------------------------------------------------


@router.get("/roles")
async def list_roles(gateway: GatewayDep, actor: AccessAdminDep) -> list[Role] | list[RoleView]:
    if not actor.is_admin:
        return await gateway.access.role_views()
    return await gateway.admin.list_roles(actor)


@router.put("/roles/{role_id}")
async def put_role(role_id: str, body: RoleBody, gateway: GatewayDep, actor: AdminDep) -> Role:
    role = Role(id=role_id, description=body.description, actions=tuple(body.actions))
    return await gateway.admin.put_role(actor, role)


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(role_id: str, gateway: GatewayDep, actor: AdminDep) -> None:
    _found(await gateway.admin.delete_role(actor, role_id), f"role {role_id}")


@router.get("/policies")
async def list_policies(
    gateway: GatewayDep,
    actor: AccessAdminDep,
    side: Literal["user", "agent"] | None = None,
) -> list[Policy] | list[UserPolicy]:
    if not actor.is_admin:
        if side == "agent":
            require_static(actor)
        return await gateway.access.user_policies()
    return await gateway.admin.list_policies(actor)


@router.post("/policies", status_code=status.HTTP_201_CREATED)
async def create_policy(body: PolicyBody, gateway: GatewayDep, actor: AdminDep) -> Policy:
    return await gateway.admin.create_policy(
        actor,
        subject=body.subject,
        actions=body.actions,
        resources=body.resources,
        effect=body.effect,
        approval=body.approval,
        expires_at=body.expires_at,
    )


@router.put("/policies/{policy_id}")
async def replace_policy(
    policy_id: str, body: PolicyBody, gateway: GatewayDep, actor: AdminDep
) -> Policy:
    policy = Policy(
        id=policy_id, **body.model_dump(exclude={"actions"}), actions=tuple(body.actions)
    )
    return await gateway.admin.replace_policy(actor, policy)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: str, gateway: GatewayDep, actor: AdminDep) -> None:
    _found(await gateway.admin.delete_policy(actor, policy_id), f"policy {policy_id}")


# ---- approvals and audit ----------------------------------------------------------------


@router.get("/approvals")
async def list_approvals(
    gateway: GatewayDep, actor: AccessAdminDep, status: ApprovalStatus | None = None
) -> list[Approval] | list[AdminApprovalView]:
    if not actor.is_admin:
        return await admin_history.list_approvals(gateway, actor, status)
    return await gateway.admin.list_approvals(actor, status=status)


@router.post("/approvals/{approval_id}/approve")
async def approve(
    approval_id: str, gateway: GatewayDep, actor: AccessAdminDep
) -> Approval | AdminApprovalView:
    if not actor.is_admin:
        return await admin_history.decide_approval(gateway, actor, approval_id, approve=True)
    approval = await gateway.admin.approve(actor, approval_id)
    await gateway.engine.dispatch_approvals()
    return approval


@router.post("/approvals/{approval_id}/reject")
async def reject(
    approval_id: str, body: RejectBody, gateway: GatewayDep, actor: AccessAdminDep
) -> Approval | AdminApprovalView:
    if not actor.is_admin:
        if not body.reason:
            raise InvalidParamsError("reason: an access admin gives a reason to reject")
        return await admin_history.decide_approval(
            gateway, actor, approval_id, approve=False, reason=body.reason
        )
    approval = await gateway.admin.reject(actor, approval_id, body.reason)
    await gateway.engine.dispatch_approvals()
    return approval


@router.get("/audit")
async def audit_entries(
    gateway: GatewayDep,
    actor: AccessAdminDep,
    since: datetime | None = None,
    until: datetime | None = None,
    event: AuditEventType | None = None,
    subject: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: str | None = None,
) -> list[AuditEntry] | AuditPage:
    if not actor.is_admin:
        # An access admin gets pages of what happened through its agent (contract §12).
        return await admin_history.audit_page(
            gateway,
            actor,
            since=since,
            until=until,
            event=event,
            subject=subject,
            limit=limit,
            cursor=cursor,
        )
    return await gateway.admin.audit_entries(actor, since=since, until=until, event=event)


@router.get("/audit/verify")
async def verify_audit(gateway: GatewayDep, actor: AdminDep) -> VerifyResult:
    return await gateway.admin.verify_audit(actor)
