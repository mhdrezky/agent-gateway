"""Mounts the admin UI on the gateway's FastAPI app."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from agent_gateway.apps.admin_ui.routes import (
    SECURITY_HEADERS,
    CsrfFailedError,
    LoginRequiredError,
    router,
)
from agent_gateway.apps.admin_ui.session import SessionStore
from agent_gateway.runtime import Gateway

STATIC_DIR = Path(__file__).parent / "static"


async def _security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
    response = await call_next(request)
    if request.url.path.startswith("/admin"):
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
    return response


def install_admin_ui(app: FastAPI, gateway: Gateway) -> None:
    app.state.admin_sessions = SessionStore(gateway.clock)
    app.include_router(router)
    app.mount("/admin/static", StaticFiles(directory=STATIC_DIR), name="admin-static")
    app.add_middleware(BaseHTTPMiddleware, dispatch=_security_headers)

    @app.exception_handler(LoginRequiredError)
    async def login_required(_: Request, __: LoginRequiredError) -> Response:
        return RedirectResponse("/admin/login", status_code=303)

    @app.exception_handler(CsrfFailedError)
    async def csrf_failed(_: Request, __: CsrfFailedError) -> Response:
        return PlainTextResponse(
            "Form expired or forged (CSRF check failed). Go back, reload, and try again.",
            status_code=403,
        )
