"""Bearer token authentication (SPEC §9.2). Rate limiting (§9.3) lives in the API layer."""

from datetime import datetime, timedelta

from agent_gateway.common.clock import Clock, SystemClock
from agent_gateway.common.errors import AuthenticationError
from agent_gateway.modules.crypto.ports import KeyRing, SubkeyPurpose
from agent_gateway.modules.identity.models import Agent, AgentStatus, Principal, Token, TokenKind
from agent_gateway.modules.identity.tokens import new_secret, parse_token, secret_matches
from agent_gateway.modules.storage.ports import Collection, ItemNotFoundError

# The only message any authentication failure ever produces.
AUTH_FAILED_MESSAGE = "Invalid or expired token."
LAST_USED_INTERVAL = timedelta(minutes=1)
# Compared against when the token id is unknown, so that path costs the same HMAC.
_DUMMY_HASH = "0" * 64


class TokenAuthenticator:
    """Verifies ``agw_<token_id>_<secret>`` tokens against their stored HMAC.

    Every failure, whatever the cause, raises ``AuthenticationError`` with
    ``AUTH_FAILED_MESSAGE`` so callers cannot tell a wrong secret from a revoked token.
    """

    def __init__(
        self,
        agents: Collection[Agent],
        tokens: Collection[Token],
        keyring: KeyRing,
        *,
        clock: Clock | None = None,
        last_used_interval: timedelta = LAST_USED_INTERVAL,
    ) -> None:
        self._agents = agents
        self._tokens = tokens
        self._key = keyring.subkey(SubkeyPurpose.TOKEN_HMAC)
        self._clock = clock or SystemClock()
        self._last_used_interval = last_used_interval
        self._dummy_secret = new_secret()

    async def authenticate(self, raw_token: str) -> Principal:
        parsed = parse_token(raw_token)
        if parsed is None:
            raise _failed()
        token = await self._tokens.get(parsed.token_id)
        if token is None:
            secret_matches(self._key, self._dummy_secret, _DUMMY_HASH)
            raise _failed()
        if not secret_matches(self._key, parsed.secret, token.hash):
            raise _failed()

        now = self._clock.now()
        if not _usable(token, now):
            raise _failed()
        roles: tuple[str, ...] = ()
        if token.kind is TokenKind.AGENT:
            agent = await self._agents.get(token.agent_id) if token.agent_id else None
            if agent is None or agent.status is not AgentStatus.ACTIVE:
                raise _failed()
            roles = agent.roles

        token = await self._mark_used(token, now)
        return Principal(kind=token.kind, token_id=token.id, agent_id=token.agent_id, roles=roles)

    async def _mark_used(self, token: Token, now: datetime) -> Token:
        """Record ``last_used_at`` at most once per interval to keep writes rare."""
        if not self._due(token, now):
            return token

        def touch(current: Token) -> Token:
            if not self._due(current, now):
                return current
            return current.model_copy(update={"last_used_at": now})

        try:
            updated = await self._tokens.update(token.id, touch)
        except ItemNotFoundError:
            raise _failed() from None
        # The token may have been revoked between the read and this write.
        if not _usable(updated, now):
            raise _failed()
        return updated

    def _due(self, token: Token, now: datetime) -> bool:
        return token.last_used_at is None or now - token.last_used_at >= self._last_used_interval


def _usable(token: Token, now: datetime) -> bool:
    if token.revoked_at is not None:
        return False
    return token.expires_at is None or now < token.expires_at


def _failed() -> AuthenticationError:
    return AuthenticationError(AUTH_FAILED_MESSAGE)
