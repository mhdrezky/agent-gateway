"""Identity contracts (SPEC §9)."""

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from agent_gateway.modules.identity.models import (
    Agent,
    AgentStatus,
    IssuedToken,
    Principal,
    Token,
    TokenKind,
)


class Authenticator(Protocol):
    async def authenticate(self, raw_token: str) -> Principal:
        """Raise ``AuthenticationError`` with the same generic message for every failure."""
        ...


class IdentityService(Protocol):
    async def create_agent(
        self, name: str, *, description: str = "", roles: Sequence[str] = ()
    ) -> Agent: ...

    async def get_agent(self, agent_id: str) -> Agent | None: ...

    async def list_agents(self) -> list[Agent]: ...

    async def update_agent(
        self,
        agent_id: str,
        *,
        description: str | None = None,
        roles: Sequence[str] | None = None,
        status: AgentStatus | None = None,
    ) -> Agent: ...

    async def issue_token(
        self,
        kind: TokenKind,
        *,
        agent_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> IssuedToken: ...

    async def revoke_token(self, token_id: str) -> Token: ...

    async def list_tokens(self, *, agent_id: str | None = None) -> list[Token]: ...
