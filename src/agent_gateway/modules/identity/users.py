"""Users on whose behalf an agent calls: ``X-User-Token`` verification (SPEC §8.9, §9.4).

The token is an OIDC access token the IdP signed. It is checked against the IdP's JWKS
(signature, ``iss``, ``aud``, ``exp``, ``sub``), then its subject and groups are matched to
``users.json``. Every failure raises ``AuthenticationError`` with one generic message.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Protocol

import httpx
import jwt

from agent_gateway.common.clock import Clock, SystemClock
from agent_gateway.common.errors import ActionNotAllowedError, AuthenticationError
from agent_gateway.config import OidcSettings
from agent_gateway.modules.identity.models import Principal, TokenKind, User, UserIdentity
from agent_gateway.modules.storage.ports import Collection

USER_AUTH_FAILED_MESSAGE = "Invalid or expired user token."
AGENT_ONLY_MESSAGE = "user tokens are accepted only together with an agent token"
# An unknown ``kid`` refetches the JWKS at most this often (key rotation, not a DoS lever).
REFRESH_INTERVAL = timedelta(seconds=30)
FETCH_TIMEOUT_SECONDS = 10

log = logging.getLogger("agent_gateway.identity")


class JwksSource(Protocol):
    async def fetch(self) -> dict[str, Any]: ...


class HttpJwks:
    """Fetches the IdP's JSON Web Key Set over HTTP."""

    def __init__(self, url: str) -> None:
        self._url = url

    async def fetch(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT_SECONDS) as client:
            response = await client.get(self._url)
            response.raise_for_status()
            body = response.json()
        if not isinstance(body, dict):
            raise ValueError("JWKS is not a JSON object")
        return body


class OidcVerifier:
    """Verifies access tokens against a cached JWKS. Returns the token's claims."""

    def __init__(self, settings: OidcSettings, source: JwksSource, clock: Clock) -> None:
        self._settings = settings
        self._source = source
        self._clock = clock
        self._keys: dict[str | None, jwt.PyJWK] = {}
        self._fetched_at: datetime | None = None
        self._lock = asyncio.Lock()

    async def verify(self, raw_token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(raw_token)
        except jwt.PyJWTError:
            raise _failed() from None
        if header.get("alg") not in self._settings.algorithms:
            raise _failed()
        key = await self._key(header.get("kid"))
        try:
            claims: dict[str, Any] = jwt.decode(
                raw_token,
                key,
                algorithms=self._settings.algorithms,
                audience=self._settings.audience,
                issuer=self._settings.issuer,
                leeway=self._settings.leeway_seconds,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError:
            raise _failed() from None
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise _failed()
        return claims

    async def _key(self, kid: Any) -> jwt.PyJWK:
        if not isinstance(kid, str | None):
            raise _failed()
        async with self._lock:
            now = self._clock.now()
            age = None if self._fetched_at is None else now - self._fetched_at
            stale = age is None or age >= timedelta(seconds=self._settings.jwks_cache_seconds)
            unknown = kid not in self._keys and (age is None or age >= REFRESH_INTERVAL)
            if stale or unknown:
                await self._refresh()
            key = self._keys.get(kid)
            if key is None and kid is None and len(self._keys) == 1:
                key = next(iter(self._keys.values()))
        if key is None:
            raise _failed()
        return key

    async def _refresh(self) -> None:
        try:
            jwks = await self._source.fetch()
            signing = [k for k in jwks.get("keys", []) if k.get("use", "sig") == "sig"]
            keys = jwt.PyJWKSet.from_dict({"keys": signing}).keys
        except Exception:
            # Keep the old keys: an IdP hiccup must not lock everyone out until it is back.
            log.warning("could not refresh the OIDC JWKS", exc_info=True)
            if self._fetched_at is None:
                raise _failed() from None
            return
        self._keys = {k.key_id: k for k in keys}
        self._fetched_at = self._clock.now()


class UserDirectory:
    """Turns a verified user token into the user's roles from ``users.json``."""

    def __init__(
        self,
        users: Collection[User],
        verifier: OidcVerifier | None,
        *,
        groups_claim: str = "groups",
    ) -> None:
        self._users = users
        self._verifier = verifier
        self._groups_claim = groups_claim

    async def resolve(self, raw_token: str) -> UserIdentity:
        if self._verifier is None:
            raise _failed()
        claims = await self._verifier.verify(raw_token)
        subject: str = claims["sub"]
        raw_groups = claims.get(self._groups_claim, [])
        groups = (
            {g for g in raw_groups if isinstance(g, str)} if isinstance(raw_groups, list) else set()
        )
        matched = sorted(
            (
                u
                for u in await self._users.all()
                if u.match.subject == subject
                or (u.match.group is not None and u.match.group in groups)
            ),
            key=lambda u: u.id,
        )
        roles = tuple(dict.fromkeys(role for u in matched for role in u.roles))
        return UserIdentity(subject=subject, user_ids=tuple(u.id for u in matched), roles=roles)

    async def on_behalf_of(self, principal: Principal, raw_token: str) -> Principal:
        """The agent ``principal`` acting for the user of ``raw_token``."""
        if principal.kind is not TokenKind.AGENT:
            raise ActionNotAllowedError(AGENT_ONLY_MESSAGE)
        return principal.model_copy(update={"user": await self.resolve(raw_token)})


def build_user_directory(
    users: Collection[User],
    settings: OidcSettings | None,
    *,
    source: JwksSource | None = None,
    clock: Clock | None = None,
) -> UserDirectory:
    if settings is None:
        return UserDirectory(users, None)
    verifier = OidcVerifier(settings, source or HttpJwks(settings.jwks_url), clock or SystemClock())
    return UserDirectory(users, verifier, groups_claim=settings.groups_claim)


def _failed() -> AuthenticationError:
    return AuthenticationError(USER_AUTH_FAILED_MESSAGE)
