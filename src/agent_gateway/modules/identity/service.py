"""Agent and token management (SPEC §8.1, §8.2, §9.1)."""

import asyncio
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from pydantic import SecretStr, ValidationError

from agent_gateway.common.clock import Clock, SystemClock
from agent_gateway.common.errors import (
    AgentNotFoundError,
    ConflictError,
    InvalidParamsError,
    NotFoundError,
)
from agent_gateway.common.ids import IdPrefix, new_id
from agent_gateway.modules.crypto.ports import KeyRing, SubkeyPurpose
from agent_gateway.modules.identity.models import (
    Agent,
    AgentStatus,
    IssuedToken,
    Token,
    TokenKind,
)
from agent_gateway.modules.identity.tokens import (
    display_prefix,
    format_token,
    hash_secret,
    new_secret,
)
from agent_gateway.modules.storage.ports import Collection, ItemNotFoundError


class IdentityManager:
    """CRUD for agents and tokens. Token plaintext exists only in the returned ``IssuedToken``."""

    def __init__(
        self,
        agents: Collection[Agent],
        tokens: Collection[Token],
        keyring: KeyRing,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._agents = agents
        self._tokens = tokens
        self._key = keyring.subkey(SubkeyPurpose.TOKEN_HMAC)
        self._clock = clock or SystemClock()
        # Serialises the name-uniqueness check with the insert inside this process.
        self._create_lock = asyncio.Lock()

    async def create_agent(
        self, name: str, *, description: str = "", roles: Sequence[str] = ()
    ) -> Agent:
        agent = _validated(
            Agent,
            {
                "id": new_id(IdPrefix.AGENT),
                "name": name,
                "description": description,
                "roles": _unique(roles),
                "created_at": self._clock.now(),
            },
        )
        async with self._create_lock:
            if any(existing.name == name for existing in await self._agents.all()):
                raise ConflictError(f"an agent named {name!r} already exists")
            await self._agents.put(agent)
        return agent

    async def get_agent(self, agent_id: str) -> Agent | None:
        return await self._agents.get(agent_id)

    async def list_agents(self) -> list[Agent]:
        return sorted(await self._agents.all(), key=lambda agent: agent.id)

    async def update_agent(
        self,
        agent_id: str,
        *,
        description: str | None = None,
        roles: Sequence[str] | None = None,
        status: AgentStatus | None = None,
    ) -> Agent:
        changes: dict[str, Any] = {}
        if description is not None:
            changes["description"] = description
        if roles is not None:
            changes["roles"] = _unique(roles)
        if status is not None:
            changes["status"] = status

        def apply(agent: Agent) -> Agent:
            return _validated(Agent, {**agent.model_dump(), **changes})

        try:
            return await self._agents.update(agent_id, apply)
        except ItemNotFoundError:
            raise AgentNotFoundError(f"agent {agent_id} not found") from None

    async def issue_token(
        self,
        kind: TokenKind,
        *,
        agent_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> IssuedToken:
        now = self._clock.now()
        if kind is TokenKind.AGENT:
            if agent_id is None:
                raise InvalidParamsError("agent tokens must reference an agent")
            if await self._agents.get(agent_id) is None:
                raise AgentNotFoundError(f"agent {agent_id} not found")
        elif agent_id is not None:
            raise InvalidParamsError("admin tokens must not reference an agent")
        if expires_at is not None:
            if expires_at.tzinfo is None:
                raise InvalidParamsError("expires_at must be timezone-aware")
            if expires_at <= now:
                raise InvalidParamsError("expires_at must be in the future")

        token_id = new_id(IdPrefix.TOKEN)
        secret = new_secret()
        token = Token(
            id=token_id,
            kind=kind,
            agent_id=agent_id,
            hash=hash_secret(self._key, secret),
            prefix=display_prefix(token_id),
            created_at=now,
            expires_at=expires_at,
        )
        await self._tokens.put(token)
        return IssuedToken(token=token, plaintext=SecretStr(format_token(token_id, secret)))

    async def revoke_token(self, token_id: str) -> Token:
        """Revoke a token. Revoking an already revoked token keeps the first ``revoked_at``."""
        now = self._clock.now()

        def revoke(token: Token) -> Token:
            if token.revoked_at is not None:
                return token
            return token.model_copy(update={"revoked_at": now})

        try:
            return await self._tokens.update(token_id, revoke)
        except ItemNotFoundError:
            raise NotFoundError(f"token {token_id} not found") from None

    async def list_tokens(self, *, agent_id: str | None = None) -> list[Token]:
        tokens = await self._tokens.all()
        if agent_id is not None:
            tokens = [token for token in tokens if token.agent_id == agent_id]
        return sorted(tokens, key=lambda token: token.id)


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        raise InvalidParamsError("roles must be a sequence of role ids, not a string")
    return tuple(dict.fromkeys(values))


def _validated(model: type[Agent], data: dict[str, Any]) -> Agent:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        fields = sorted({".".join(map(str, err["loc"])) for err in exc.errors()})
        raise InvalidParamsError(f"invalid agent fields: {', '.join(fields)}") from None
