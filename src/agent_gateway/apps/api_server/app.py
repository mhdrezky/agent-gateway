"""FastAPI application factory and error mapping (SPEC §15.3)."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Route

from agent_gateway import __version__
from agent_gateway.apps.admin_ui.setup import install_admin_ui
from agent_gateway.apps.api_server import (
    routes_access_admin,
    routes_admin,
    routes_admin_catalog,
    routes_agent,
    routes_approvals,
    routes_models,
)
from agent_gateway.apps.api_server.deps import FailureLimiter
from agent_gateway.apps.api_server.mcp_actions import MCP_ACTIONS_PATH, build_actions_server
from agent_gateway.apps.api_server.mcp_http import MCP_PATH, build_mcp_server, mcp_endpoint
from agent_gateway.common.errors import GatewayError, NamesMissingError
from agent_gateway.runtime import Gateway

log = logging.getLogger("agent_gateway.api")


def _error(
    status_code: int,
    code: str,
    message: str,
    execution_id: str | None = None,
    missing: dict[str, list[str]] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {"code": code, "message": message}
    if execution_id is not None:
        body["execution_id"] = execution_id
    if missing is not None:
        body["missing"] = missing
    return JSONResponse(status_code=status_code, content={"error": body})


def create_app(gateway: Gateway, *, manage_lifecycle: bool = True) -> FastAPI:
    """Build the app. With ``manage_lifecycle`` the app starts and stops the gateway."""

    mcp_server = build_mcp_server(gateway)
    limiter = FailureLimiter(gateway.settings.rate_limit.auth_failures_per_minute, gateway.clock)
    hosts = gateway.settings.server.public_hosts
    mcp_app = mcp_endpoint(mcp_server, gateway, limiter, hosts)
    actions_server = build_actions_server(gateway)
    actions_app = mcp_endpoint(actions_server, gateway, limiter, hosts, MCP_ACTIONS_PATH)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if manage_lifecycle:
            await gateway.start()
        try:
            async with mcp_server.session_manager.run(), actions_server.session_manager.run():
                yield
        finally:
            if manage_lifecycle:
                await gateway.stop()

    app = FastAPI(title="Agent Gateway", version=__version__, lifespan=lifespan)
    app.state.gateway = gateway
    app.state.limiter = limiter
    app.router.routes.append(Route(MCP_PATH, endpoint=mcp_app))
    app.router.routes.append(Route(MCP_ACTIONS_PATH, endpoint=actions_app))

    @app.exception_handler(GatewayError)
    async def gateway_error(_: Request, exc: GatewayError) -> JSONResponse:
        missing = exc.missing if isinstance(exc, NamesMissingError) else None
        return _error(exc.status_code, exc.code, exc.message, exc.execution_id, missing)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Describe the problem without echoing the rejected input back.
        problems = "; ".join(
            f"{'.'.join(str(p) for p in error.get('loc', ()))}: {error.get('msg', 'invalid')}"
            for error in exc.errors()
        )
        return _error(422, "invalid_params", problems or "invalid request")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "not_found" if exc.status_code == 404 else "http_error"
        return _error(exc.status_code, code, str(exc.detail))

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", exc_info=exc)
        return _error(500, "internal_error", "internal server error")

    app.include_router(routes_agent.router)
    app.include_router(routes_models.router)
    app.include_router(routes_admin.router)
    app.include_router(routes_access_admin.router)
    app.include_router(routes_admin_catalog.router)
    app.include_router(routes_approvals.router)
    install_admin_ui(app, gateway)
    return app
