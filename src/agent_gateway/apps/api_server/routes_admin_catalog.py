"""Catalog and sync endpoints of admin contract §7 (`agentgate-gateway-admin/1`).

The static admin token or an access admin (``AccessAdminDep``). An access admin is audited
as the user (``actor {type: user, id: sub}``) with ``details.via_agent``, like every other
access-admin write. URLs name the resource by id; ``Catalog.resource`` is its name.
"""

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from agent_gateway.apps.api_server.deps import AccessAdminDep, GatewayDep
from agent_gateway.modules.administration.access import AdminActor
from agent_gateway.modules.catalog.models import CatalogOut, SyncOut, catalog_out

router = APIRouter(prefix="/v1/admin/resources")


class AcknowledgeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: list[str] = Field(min_length=1, max_length=500)


@router.get("/{resource_id}/catalog")
async def get_catalog(resource_id: str, gateway: GatewayDep, _: AccessAdminDep) -> CatalogOut:
    return catalog_out(await gateway.catalog.catalog(resource_id))


@router.post("/{resource_id}/sync")
async def sync_catalog(resource_id: str, gateway: GatewayDep, admin: AccessAdminDep) -> SyncOut:
    """``502 sync_failed`` when the resource cannot be read (the last snapshot stays). Tools
    that cannot become actions are listed in ``skipped``; the sync still succeeds."""
    actor = AdminActor.of(admin)
    report = await gateway.catalog.sync(actor.actor, resource_id, context=actor.details())
    return report.out()


@router.post("/{resource_id}/catalog/acknowledge")
async def acknowledge_catalog(
    resource_id: str, body: AcknowledgeIn, gateway: GatewayDep, admin: AccessAdminDep
) -> CatalogOut:
    actor = AdminActor.of(admin)
    snapshot = await gateway.catalog.acknowledge(
        actor.actor, resource_id, body.tools, context=actor.details()
    )
    return catalog_out(snapshot)
