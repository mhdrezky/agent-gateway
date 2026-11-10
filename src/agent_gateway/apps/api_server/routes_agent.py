"""Endpoints for agents (SPEC §15.1). Admin tokens may read them too."""

from typing import Annotated

from fastapi import APIRouter, Header, Query, Response, status

from agent_gateway import __version__
from agent_gateway.apps.api_server.correlation import resolve_correlation
from agent_gateway.apps.api_server.deps import GatewayDep, PrincipalDep
from agent_gateway.apps.api_server.schemas import (
    ActionInfo,
    ContractOut,
    ExecutionPage,
    Health,
    ResourceInfo,
    WhoAmI,
)
from agent_gateway.apps.api_server.views import action_infos, resource_infos
from agent_gateway.modules.administration.access_models import ADMIN_CONTRACT_VERSION
from agent_gateway.modules.execution.models import Execution, ExecutionRequest, ExecutionStatus
from agent_gateway.modules.resources.models import ResourceType

router = APIRouter(prefix="/v1")

CONTRACT_VERSIONS = ("agentgate-gateway/1", ADMIN_CONTRACT_VERSION)


@router.get("/health")
async def health() -> Health:
    return Health(status="ok", version=__version__)


@router.get("/contract")
async def contract() -> ContractOut:
    return ContractOut(versions=list(CONTRACT_VERSIONS))


@router.get("/whoami")
async def whoami(principal: PrincipalDep) -> WhoAmI:
    return WhoAmI(
        kind=principal.kind,
        token_id=principal.token_id,
        agent_id=principal.agent_id,
        roles=principal.roles,
        user=principal.user,
    )


@router.get("/actions")
async def list_actions(gateway: GatewayDep, principal: PrincipalDep) -> list[ActionInfo]:
    return await action_infos(gateway, principal)


@router.get("/resources")
async def list_resources(
    gateway: GatewayDep, principal: PrincipalDep, type: ResourceType | None = None
) -> list[ResourceInfo]:
    return await resource_infos(gateway, principal, type)


@router.post("/executions")
async def submit_execution(
    body: ExecutionRequest,
    response: Response,
    gateway: GatewayDep,
    principal: PrincipalDep,
    x_correlation_id: Annotated[str | None, Header()] = None,
) -> Execution:
    execution = await gateway.engine.submit(
        principal, body, correlation_id=resolve_correlation(x_correlation_id, None)
    )
    if execution.status is ExecutionStatus.PENDING_APPROVAL:
        response.status_code = status.HTTP_202_ACCEPTED
    return execution


@router.get("/executions/{execution_id}")
async def get_execution(
    execution_id: str, gateway: GatewayDep, principal: PrincipalDep
) -> Execution:
    return await gateway.engine.get(principal, execution_id)


@router.get("/executions")
async def list_executions(
    gateway: GatewayDep,
    principal: PrincipalDep,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ExecutionPage:
    items, next_cursor = await gateway.engine.list_for(principal, cursor=cursor, limit=limit)
    return ExecutionPage(items=items, next_cursor=next_cursor)
