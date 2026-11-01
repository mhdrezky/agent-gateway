"""Request dependencies: the gateway, authentication, and the auth-failure rate limit."""

import contextlib
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, Header, Request

from agent_gateway.common.clock import Clock
from agent_gateway.common.errors import (
    AdminRequiredError,
    AuthenticationError,
    GatewayError,
    RateLimitedError,
)
from agent_gateway.modules.audit.models import Actor, ActorType, AuditEventType, AuditRecord
from agent_gateway.modules.identity.authenticator import AUTH_FAILED_MESSAGE
from agent_gateway.modules.identity.models import Principal
from agent_gateway.runtime import Gateway

WINDOW = timedelta(minutes=1)


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


async def current_principal(
    request: Request,
    gateway: GatewayDep,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    limiter: FailureLimiter = request.app.state.limiter
    client = request.client.host if request.client else "unknown"
    limiter.check(client)

    scheme, _, raw = (authorization or "").partition(" ")
    try:
        if scheme.lower() != "bearer" or not raw:
            raise AuthenticationError(AUTH_FAILED_MESSAGE)
        return await gateway.authenticator.authenticate(raw.strip())
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


PrincipalDep = Annotated[Principal, Depends(current_principal)]


async def admin_principal(principal: PrincipalDep) -> Principal:
    if not principal.is_admin:
        raise AdminRequiredError("admin token required")
    return principal


AdminDep = Annotated[Principal, Depends(admin_principal)]
