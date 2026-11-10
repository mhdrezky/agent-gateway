"""Catalog and sync endpoints of admin contract §7 (`agentgate-gateway-admin/1`).

Guarded by the static admin token for now (``AdminDep``). The access-admin dependency
(an OIDC user token with an admin role) replaces it when the admin API lands; the
endpoints themselves do not change.
"""

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from agent_gateway.apps.api_server.deps import AdminDep, GatewayDep
from agent_gateway.modules.audit.models import Actor, ActorType
from agent_gateway.modules.catalog.errors import problems_error
from agent_gateway.modules.catalog.models import CatalogOut, SyncOut, catalog_out
from agent_gateway.modules.identity.models import Principal

router = APIRouter(prefix="/v1/admin/resources")


class AcknowledgeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: list[str] = Field(min_length=1, max_length=500)


def _actor(principal: Principal) -> Actor:
    return Actor(type=ActorType.ADMIN, id=principal.token_id)


@router.get("/{resource_id}/catalog")
async def get_catalog(resource_id: str, gateway: GatewayDep, _: AdminDep) -> CatalogOut:
    return catalog_out(await gateway.catalog.catalog(resource_id))


@router.post("/{resource_id}/sync")
async def sync_catalog(resource_id: str, gateway: GatewayDep, admin: AdminDep) -> SyncOut:
    """``502 sync_failed`` when the resource cannot be read (the last snapshot stays);
    ``409`` when tools were left out (the snapshot is stored without them)."""
    report = await gateway.catalog.sync(_actor(admin), resource_id)
    error = problems_error(report.problems)
    if error is not None:
        raise error
    return report.out()


@router.post("/{resource_id}/catalog/acknowledge")
async def acknowledge_catalog(
    resource_id: str, body: AcknowledgeIn, gateway: GatewayDep, admin: AdminDep
) -> CatalogOut:
    snapshot = await gateway.catalog.acknowledge(_actor(admin), resource_id, body.tools)
    return catalog_out(snapshot)
