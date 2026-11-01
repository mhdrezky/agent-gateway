"""What an agent may see of actions and resources; shared by REST and ``/mcp``."""

from agent_gateway.apps.api_server.schemas import ActionInfo, ResourceInfo
from agent_gateway.modules.identity.models import Principal
from agent_gateway.modules.resources.models import ResourceType
from agent_gateway.runtime import Gateway


async def action_infos(gateway: Gateway, principal: Principal) -> list[ActionInfo]:
    actions = (
        gateway.registry.all()
        if principal.is_admin
        else await gateway.engine.visible_actions(principal)
    )
    return [
        ActionInfo(
            id=a.definition.id,
            description=a.definition.description,
            risk=a.definition.risk,
            resource_type=a.definition.resource_type,
            params_schema=a.definition.params_schema(),
        )
        for a in sorted(actions, key=lambda a: a.definition.id)
    ]


async def resource_infos(
    gateway: Gateway, principal: Principal, type: ResourceType | None = None
) -> list[ResourceInfo]:
    resources = await gateway.engine.visible_resources(principal)
    return [
        ResourceInfo(id=r.id, type=r.type, name=r.name, tags=r.tags)
        for r in sorted(resources, key=lambda r: r.name)
        if type is None or r.type is type
    ]
