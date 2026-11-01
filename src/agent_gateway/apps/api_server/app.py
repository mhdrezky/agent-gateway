"""FastAPI application factory and error mapping (SPEC §15.3)."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Route

from agent_gateway import __version__
from agent_gateway.apps.admin_ui.setup import install_admin_ui
from agent_gateway.apps.api_server import routes_admin, routes_agent
from agent_gateway.apps.api_server.deps import FailureLimiter
from agent_gateway.apps.api_server.mcp_http import MCP_PATH, build_mcp_server, mcp_endpoint
from agent_gateway.common.errors import GatewayError
from agent_gateway.runtime import Gateway

log = logging.getLogger("agent_gateway.api")


def _error(
    status_code: int, code: str, message: str, execution_id: str | None = None
) -> JSONResponse:
    body: dict[str, str] = {"code": code, "message": message}
    if execution_id is not None:
        body["execution_id"] = execution_id
    return JSONResponse(status_code=status_code, content={"error": body})


def create_app(gateway: Gateway, *, manage_lifecycle: bool = True) -> FastAPI:
    """Build the app. With ``manage_lifecycle`` the app starts and stops the gateway."""

    mcp_server = build_mcp_server(gateway)
    limiter = FailureLimiter(gateway.settings.rate_limit.auth_failures_per_minute, gateway.clock)
    mcp_app = mcp_endpoint(mcp_server, gateway, limiter, gateway.settings.server.public_hosts)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if manage_lifecycle:
            await gateway.start()
        try:
            async with mcp_server.session_manager.run():
                yield
        finally:
            if manage_lifecycle:
                await gateway.stop()

    app = FastAPI(title="Agent Gateway", version=__version__, lifespan=lifespan)
    app.state.gateway = gateway
    app.state.limiter = limiter
    app.router.routes.append(Route(MCP_PATH, endpoint=mcp_app))

    @app.exception_handler(GatewayError)
    async def gateway_error(_: Request, exc: GatewayError) -> JSONResponse:
        return _error(exc.status_code, exc.code, exc.message, exc.execution_id)

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
    app.include_router(routes_admin.router)
    install_admin_ui(app, gateway)
    return app
