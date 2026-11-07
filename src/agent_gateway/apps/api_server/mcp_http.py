"""MCP over Streamable HTTP at ``/mcp``, inside the gateway (SPEC §16).

Agents need only the URL and their agent token: no repo, no local program. Every HTTP
request is authenticated with ``Authorization: Bearer <agent token>`` before it reaches
the MCP layer, and every tool call authenticates its own request again, so a tool always
acts as the agent that sent it. Tools call the same execution engine as REST (P6).
"""

from collections.abc import Mapping
from typing import Any

from mcp.server.lowlevel import Server
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from agent_gateway.apps.api_server.deps import FailureLimiter, authenticate_request, bearer_token
from agent_gateway.apps.api_server.views import action_infos, resource_infos
from agent_gateway.common.errors import ActionNotAllowedError, GatewayError, InvalidParamsError
from agent_gateway.modules.execution.models import ExecutionRequest
from agent_gateway.modules.identity.models import Principal, TokenKind
from agent_gateway.modules.resources.models import ResourceType
from agent_gateway.runtime import Gateway

MCP_PATH = "/mcp"
LOCAL_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
INSTRUCTIONS = (
    "Agent Gateway runs registered infrastructure actions on your behalf. "
    "Call list_actions and list_resources first, then execute_action. "
    "Some actions need human approval: the result then has status 'pending_approval'; "
    "poll get_execution with its id instead of submitting again."
)
AGENT_ONLY = "only agent tokens can use MCP"


def _error(exc: GatewayError) -> dict[str, Any]:
    body: dict[str, Any] = {"code": exc.code, "message": exc.message}
    if exc.execution_id is not None:
        body["execution_id"] = exc.execution_id
    return {"error": body}


def build_mcp_server(gateway: Gateway) -> MCPServer:
    server = MCPServer("agent-gateway", instructions=INSTRUCTIONS)

    async def agent(ctx: Context) -> Principal:
        headers: Mapping[str, str] = ctx.headers or {}
        principal = await gateway.authenticator.authenticate(
            bearer_token(headers.get("authorization"))
        )
        if principal.kind is not TokenKind.AGENT:
            raise ActionNotAllowedError(AGENT_ONLY)
        return principal

    @server.tool()
    async def list_actions(ctx: Context) -> Any:
        """List the actions you may run, with the JSON schema of their params."""
        try:
            infos = await action_infos(gateway, await agent(ctx))
        except GatewayError as exc:
            return _error(exc)
        return {"actions": [i.model_dump(mode="json") for i in infos]}

    @server.tool()
    async def list_resources(ctx: Context, type: str | None = None) -> Any:
        """List the resources you may target, optionally filtered by resource type."""
        try:
            principal = await agent(ctx)
            try:
                resource_type = ResourceType(type) if type else None
            except ValueError:
                raise InvalidParamsError(f"unknown resource type {type!r}") from None
            infos = await resource_infos(gateway, principal, resource_type)
        except GatewayError as exc:
            return _error(exc)
        return {"resources": [i.model_dump(mode="json") for i in infos]}

    @server.tool()
    async def execute_action(
        ctx: Context,
        action: str,
        resource_id: str,
        params: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        """Run a registered action on a resource.

        The result may have status 'pending_approval'. In that case a human must approve it
        first: call get_execution with the returned id to check the outcome. Do not submit
        the same request again; pass an idempotency_key if you might retry.
        """
        try:
            principal = await agent(ctx)
            try:
                request = ExecutionRequest(
                    action=action,
                    resource_id=resource_id,
                    params=params or {},
                    idempotency_key=idempotency_key,
                )
            except ValidationError as exc:
                raise InvalidParamsError(
                    f"invalid request: {exc.error_count()} problem(s)"
                ) from None
            execution = await gateway.engine.submit(principal, request)
        except GatewayError as exc:
            return _error(exc)
        return execution.model_dump(mode="json")

    @server.tool()
    async def get_execution(ctx: Context, execution_id: str) -> Any:
        """Get the status and result of an execution you submitted."""
        try:
            execution = await gateway.engine.get(await agent(ctx), execution_id)
        except GatewayError as exc:
            return _error(exc)
        return execution.model_dump(mode="json")

    return server


class AgentAuth:
    """Rejects MCP requests without a valid agent token before MCP sees them."""

    def __init__(self, app: ASGIApp, gateway: Gateway, limiter: FailureLimiter) -> None:
        self._app = app
        self._gateway = gateway
        self._limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            try:
                principal = await authenticate_request(Request(scope), self._gateway, self._limiter)
                if principal.kind is not TokenKind.AGENT:
                    raise ActionNotAllowedError(AGENT_ONLY)
            except GatewayError as exc:
                response = JSONResponse(status_code=exc.status_code, content=_error(exc))
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)


def mcp_endpoint(
    server: MCPServer | Server[Any],
    gateway: Gateway,
    limiter: FailureLimiter,
    extra_hosts: list[str],
    path: str = MCP_PATH,
) -> ASGIApp:
    """The authenticated ASGI app to route at ``path``. Run ``server.session_manager``."""
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[*LOCAL_HOSTS, *extra_hosts],
        allowed_origins=[f"http://{h}" for h in LOCAL_HOSTS]
        + [f"https://{h}" for h in extra_hosts],
    )
    starlette_app = server.streamable_http_app(
        streamable_http_path=path,
        stateless_http=True,
        json_response=True,
        transport_security=security,
    )
    [route] = [r for r in starlette_app.routes if getattr(r, "path", None) == path]
    endpoint: ASGIApp = route.endpoint  # type: ignore[attr-defined]
    return AgentAuth(endpoint, gateway, limiter)
