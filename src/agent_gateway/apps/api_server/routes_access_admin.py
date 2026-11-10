"""Endpoints that only ``agentgate-gateway-admin/1`` has (SPEC §23).

Each takes the static admin token or an access admin (agent token + ``X-User-Token`` of a
user holding a role in ``admin.user_roles``). Through an agent, the answers are scoped to
that agent and never show privileged actions.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query

from agent_gateway.apps.api_server import admin_history
from agent_gateway.apps.api_server.deps import AccessAdminDep, GatewayDep
from agent_gateway.common.errors import (
    AgentNotFoundError,
    InvalidParamsError,
    UserNotFoundError,
)
from agent_gateway.modules.administration.access import AdminActor, agent_view_principal
from agent_gateway.modules.administration.access_models import (
    AccessConfig,
    AccessView,
    AdminActionInfo,
    AdminExecutionPage,
    ApplyIn,
    ApplyOut,
    DirectoryGroup,
    DirectoryUser,
    ExecutionDetail,
    InstanceView,
    PlanIn,
    PlanOut,
    PlanStatus,
    UserRecord,
)
from agent_gateway.modules.execution.models import ExecutionStatus
from agent_gateway.modules.identity.models import Principal

router = APIRouter(prefix="/v1/admin")


# ---- the instance (amendment A1) --------------------------------------------------------


@router.get("/instance")
async def instance(gateway: GatewayDep, actor: AccessAdminDep) -> InstanceView:
    settings = gateway.settings.admin
    return InstanceView(
        apply_requires_second_admin=settings.apply_requires_second_admin,
        admin_user_roles=list(settings.user_roles),
    )


# ---- reads (contract §4) ----------------------------------------------------------------


@router.get("/users")
async def list_users(gateway: GatewayDep, actor: AccessAdminDep) -> list[UserRecord]:
    return await gateway.access.user_records()


@router.get("/actions")
async def list_actions(gateway: GatewayDep, actor: AccessAdminDep) -> list[AdminActionInfo]:
    return await gateway.access.action_infos(include_privileged=actor.is_admin)


# ---- directory (contract §5) ------------------------------------------------------------


@router.get("/directory/users")
async def directory_users(
    gateway: GatewayDep,
    actor: AccessAdminDep,
    q: Annotated[str, Query(max_length=200)] = "",
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[DirectoryUser]:
    return await gateway.access.directory.users(q, limit)


@router.get("/directory/groups")
async def directory_groups(
    gateway: GatewayDep,
    actor: AccessAdminDep,
    q: Annotated[str, Query(max_length=200)] = "",
) -> list[DirectoryGroup]:
    return await gateway.access.directory.groups(q)


# ---- effective access (contract §6) -----------------------------------------------------


@router.get("/access")
async def effective_access(
    gateway: GatewayDep,
    actor: AccessAdminDep,
    subject: Annotated[str, Query(min_length=1, max_length=255)],
    agent: Annotated[str | None, Query(max_length=64)] = None,
) -> AccessView:
    """``agent`` (a name) is needed only with the static admin token, which calls through
    no agent; an access admin always sees access through its own agent."""
    through = await _through_agent(gateway, actor, agent)
    user = await gateway.access.directory.user(subject)
    if user is None:
        raise UserNotFoundError(f"user {subject} not found in the directory")
    return await gateway.access.access_view(subject, user.groups, through)


async def _through_agent(gateway: GatewayDep, actor: Principal, name: str | None) -> Principal:
    if not actor.is_admin:
        return actor.model_copy(update={"user": None})
    if name is None:
        raise InvalidParamsError("agent: name the agent to compute access through")
    found = await gateway.access.agent_by_name(name)
    if found is None:
        raise AgentNotFoundError(f"agent {name} not found")
    return agent_view_principal(found)


# ---- access config, plan, apply (contract §8) -------------------------------------------


@router.get("/config")
async def access_config(gateway: GatewayDep, actor: AccessAdminDep) -> AccessConfig:
    return await gateway.access.export()


@router.post("/config/plan")
async def plan_config(body: PlanIn, gateway: GatewayDep, actor: AccessAdminDep) -> PlanOut:
    return await gateway.access.plan(body.config, AdminActor.of(actor))


@router.post("/config/apply")
async def apply_config(body: ApplyIn, gateway: GatewayDep, actor: AccessAdminDep) -> ApplyOut:
    return await gateway.access.apply(body.plan_id, AdminActor.of(actor))


@router.post("/config/plans/{plan_id}/discard")
async def discard_plan(plan_id: str, gateway: GatewayDep, actor: AccessAdminDep) -> PlanOut:
    return await gateway.access.discard(plan_id, AdminActor.of(actor))


@router.get("/config/plans")
async def list_plans(
    gateway: GatewayDep, actor: AccessAdminDep, status: PlanStatus | None = None
) -> list[PlanOut]:
    return await gateway.access.plans(status=status)


# ---- history (contract §11) -------------------------------------------------------------


@router.get("/executions")
async def list_executions(
    gateway: GatewayDep,
    actor: AccessAdminDep,
    since: datetime | None = None,
    until: datetime | None = None,
    status: ExecutionStatus | None = None,
    subject: Annotated[str | None, Query(max_length=255)] = None,
    action: Annotated[str | None, Query(max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=64)] = None,
) -> AdminExecutionPage:
    return await admin_history.execution_page(
        gateway,
        actor,
        since=since,
        until=until,
        status=status,
        subject=subject,
        action=action,
        limit=limit,
        cursor=cursor,
    )


@router.get("/executions/{execution_id}")
async def get_execution(
    execution_id: str, gateway: GatewayDep, actor: AccessAdminDep
) -> ExecutionDetail:
    return await admin_history.execution_detail(gateway, actor, execution_id)
