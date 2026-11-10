"""Request dependencies: the gateway, authentication, and the auth-failure rate limit."""

import contextlib
from collections import defaultdict, deque
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, Header, Request

from agent_gateway.common.clock import Clock
from agent_gateway.common.errors import (
    AdminRequiredError,
    AuthenticationError,
    GatewayError,
    InfraOnlyError,
    NotAdminError,
    RateLimitedError,
)
from agent_gateway.modules.audit.models import Actor, ActorType, AuditEventType, AuditRecord
from agent_gateway.modules.identity.authenticator import AUTH_FAILED_MESSAGE
from agent_gateway.modules.identity.models import Principal
from agent_gateway.runtime import Gateway

WINDOW = timedelta(minutes=1)
# The signed-in user's OIDC access token, sent by apps that call for a user (SPEC §9.4).
USER_TOKEN_HEADER = "x-user-token"


class FailureLimiter:
    """Counts authentication failures per client in a sliding one-minute window (SPEC §9.3)."""

    def __init__(self, limit_per_minute: int, clock: Clock) -> None:
        self._limit = limit_per_minute
        self._clock = clock
        self._failures: defaultdict[str, deque[datetime]] = defaultdict(deque)

    def check(self, key: str) -> None:
        failures = self._failures[key]
        cutoff = self._clock.now() - WINDOW
        while failures and failures[0] <= cutoff:
            failures.popleft()
        if len(failures) >= self._limit:
            raise RateLimitedError("too many failed authentication attempts")

    def record(self, key: str) -> None:
        self._failures[key].append(self._clock.now())


def get_gateway(request: Request) -> Gateway:
    gateway: Gateway = request.app.state.gateway
    return gateway


GatewayDep = Annotated[Gateway, Depends(get_gateway)]


def bearer_token(authorization: str | None) -> str:
    """The token from an ``Authorization: Bearer ...`` header; raises 401 otherwise."""
    scheme, _, raw = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not raw.strip():
        raise AuthenticationError(AUTH_FAILED_MESSAGE)
    return raw.strip()


async def principal_from_headers(gateway: Gateway, headers: Mapping[str, str]) -> Principal:
    """The agent of ``Authorization``, acting for the user of ``X-User-Token`` if present."""
    principal = await gateway.authenticator.authenticate(bearer_token(headers.get("authorization")))
    user_token = headers.get(USER_TOKEN_HEADER)
    if user_token is not None:
        principal = await gateway.users.on_behalf_of(principal, user_token.strip())
    return principal


async def authenticate_request(
    request: Request, gateway: Gateway, limiter: FailureLimiter, token: str | None = None
) -> Principal:
    """Rate-limited authentication with failures audited. Used by REST, MCP, and the
    admin UI login. Without ``token`` it reads the request's ``Authorization: Bearer`` and
    ``X-User-Token`` headers.
    """
    client = request.client.host if request.client else "unknown"
    limiter.check(client)
    try:
        if token is None:
            return await principal_from_headers(gateway, request.headers)
        if not token.strip():
            raise AuthenticationError(AUTH_FAILED_MESSAGE)
        return await gateway.authenticator.authenticate(token.strip())
    except AuthenticationError:
        limiter.record(client)
        # Auditing a failure must never turn a 401 into a 503.
        with contextlib.suppress(GatewayError):
            await gateway.audit.append(
                AuditRecord(
                    event=AuditEventType.AUTH_FAILED,
                    actor=Actor(type=ActorType.SYSTEM, id="api"),
                    details={"client": client, "path": request.url.path},
                )
            )
        raise


async def current_principal(
    request: Request,
    gateway: GatewayDep,
    # Declared so the headers show up in the OpenAPI schema; read via the request.
    authorization: Annotated[str | None, Header()] = None,
    x_user_token: Annotated[str | None, Header()] = None,
) -> Principal:
    return await authenticate_request(request, gateway, request.app.state.limiter)


PrincipalDep = Annotated[Principal, Depends(current_principal)]


USER_TOKEN_REQUIRED = "a user token (X-User-Token) is required"
NOT_ADMIN = "this user is not an access admin"
INFRA_ONLY = "only the gateway admin (admin token) can do this"


def _require_access_admin(gateway: Gateway, principal: Principal) -> None:
    """An agent call is an access admin's when its user holds a role in
    ``admin.user_roles`` (SPEC §23). The agent's own grants play no part."""
    if principal.user is None:
        raise AuthenticationError(USER_TOKEN_REQUIRED)
    if not gateway.access.is_access_admin(principal.user.roles):
        raise NotAdminError(NOT_ADMIN)


async def admin_principal(principal: PrincipalDep, gateway: GatewayDep) -> Principal:
    """Infra endpoints: the static admin token only. An access admin gets ``infra_only``."""
    if principal.is_admin:
        return principal
    if principal.user is None:
        raise AdminRequiredError("admin token required")
    _require_access_admin(gateway, principal)
    raise InfraOnlyError(INFRA_ONLY)


AdminDep = Annotated[Principal, Depends(admin_principal)]


async def access_admin_principal(principal: PrincipalDep, gateway: GatewayDep) -> Principal:
    """Endpoints of ``agentgate-gateway-admin/1``: the static admin token, or an agent token
    with the ``X-User-Token`` of an access admin."""
    if not principal.is_admin:
        _require_access_admin(gateway, principal)
    return principal


AccessAdminDep = Annotated[Principal, Depends(access_admin_principal)]


def require_static(principal: Principal) -> None:
    """Refuse an access admin where only the static admin token may go."""
    if not principal.is_admin:
        raise InfraOnlyError(INFRA_ONLY)
