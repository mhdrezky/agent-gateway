"""Model endpoints and the name check at promote (SPEC §15.4, contract §5 and §7)."""

from typing import Annotated, Any

from fastapi import APIRouter, Header
from pydantic import Field, StringConstraints

from agent_gateway.apps.api_server.correlation import META_CORRELATION, resolve_correlation
from agent_gateway.apps.api_server.deps import GatewayDep, PrincipalDep
from agent_gateway.apps.api_server.mcp_actions import tool_name
from agent_gateway.common.errors import (
    ActionNotAllowedError,
    AuthenticationError,
    NamesMissingError,
)
from agent_gateway.common.models import StrictModel
from agent_gateway.modules.audit.models import Actor, ActorType, AuditEventType, AuditRecord
from agent_gateway.modules.identity.models import Principal
from agent_gateway.modules.model_endpoints.models import ChatIn, ChatOut, ModelInfo
from agent_gateway.runtime import Gateway

router = APIRouter(prefix="/v1")

MAX_BIND_NAMES = 500
BindName = Annotated[str, StringConstraints(min_length=1, max_length=255)]


class BindIn(StrictModel):
    """Gateway names a release uses, after the app's per-environment binding."""

    models: list[BindName] = Field(default_factory=list, max_length=MAX_BIND_NAMES)
    tools: list[BindName] = Field(default_factory=list, max_length=MAX_BIND_NAMES)
    resources: list[BindName] = Field(default_factory=list, max_length=MAX_BIND_NAMES)


class BindOut(StrictModel):
    models: dict[str, str]


@router.get("/models")
async def list_models(gateway: GatewayDep, principal: PrincipalDep) -> list[ModelInfo]:
    return await gateway.models.visible(principal)


@router.post("/models/{name}/chat")
async def chat(
    name: str,
    body: ChatIn,
    gateway: GatewayDep,
    principal: PrincipalDep,
    x_correlation_id: Annotated[str | None, Header()] = None,
) -> ChatOut:
    # The body field and the header name the same turn; they may not disagree (SPEC §12).
    meta = {META_CORRELATION: body.correlation_id} if body.correlation_id is not None else None
    correlation_id = resolve_correlation(x_correlation_id, meta)
    if correlation_id != body.correlation_id:
        body = body.model_copy(update={"correlation_id": correlation_id})
    return await gateway.models.chat(principal, name, body)


@router.post("/bind")
async def bind(
    body: BindIn,
    gateway: GatewayDep,
    principal: PrincipalDep,
    x_correlation_id: Annotated[str | None, Header()] = None,
) -> BindOut:
    """Check that the names exist for this agent; the user's own grants do not matter."""
    user = principal.user
    correlation_id = resolve_correlation(x_correlation_id, None)
    details: dict[str, Any] = {
        "user": user.subject if user else None,
        "models": body.models,
        "tools": body.tools,
        "resources": body.resources,
    }
    if correlation_id is not None:
        details["correlation_id"] = correlation_id
    if user is None:
        await _record(gateway, principal, {**details, "outcome": "no_user"})
        raise AuthenticationError("this endpoint needs the user's X-User-Token")
    allowed = gateway.settings.bind.roles
    if set(allowed).isdisjoint(user.roles):
        await _record(gateway, principal, {**details, "outcome": "forbidden"})
        raise ActionNotAllowedError(
            f"binding needs a user with one of the roles: {', '.join(allowed)}"
        )

    agent = principal.model_copy(update={"user": None})
    models = {m.name: m.model_id for m in await gateway.models.visible(agent)}
    tools = {tool_name(a.definition.id) for a in await gateway.engine.visible_actions(agent)}
    resources = {r.id for r in await gateway.engine.visible_resources(agent)}
    missing = {
        "models": sorted(set(body.models) - models.keys()),
        "tools": sorted(set(body.tools) - tools),
        "resources": sorted(set(body.resources) - resources),
    }
    if any(missing.values()):
        await _record(gateway, principal, {**details, "outcome": "missing", "missing": missing})
        raise NamesMissingError("some names do not exist for this agent", missing=missing)
    bound = {name: models[name] for name in body.models}
    await _record(gateway, principal, {**details, "outcome": "ok", "bound_models": bound})
    return BindOut(models=bound)


async def _record(gateway: Gateway, principal: Principal, details: dict[str, Any]) -> None:
    actor = (
        Actor(type=ActorType.AGENT, id=principal.agent_id)
        if principal.agent_id is not None
        else Actor(type=ActorType.ADMIN, id=principal.token_id)
    )
    await gateway.audit.append(
        AuditRecord(event=AuditEventType.BIND_CHECKED, actor=actor, details=details)
    )
