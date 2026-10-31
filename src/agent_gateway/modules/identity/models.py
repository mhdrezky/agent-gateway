"""Agent and token models (SPEC §8.1, §8.2, §9)."""

from enum import StrEnum
from typing import Self

from pydantic import AwareDatetime, Field, SecretStr, model_validator

from agent_gateway.common.models import Record, StrictModel

TOKEN_SCHEME = "agw"
NAME_PATTERN = r"^[a-z0-9][a-z0-9._-]*$"


class AgentStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class Agent(Record):
    name: str = Field(min_length=1, max_length=64, pattern=NAME_PATTERN)
    description: str = Field(default="", max_length=500)
    roles: tuple[str, ...] = ()
    status: AgentStatus = AgentStatus.ACTIVE
    created_at: AwareDatetime


class TokenKind(StrEnum):
    AGENT = "agent"
    ADMIN = "admin"


class Token(Record):
    """Stored token. ``hash`` is HMAC-SHA256 of the secret part; the plaintext is never stored."""

    kind: TokenKind
    agent_id: str | None = None
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    prefix: str
    created_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    last_used_at: AwareDatetime | None = None
    revoked_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _agent_binding(self) -> Self:
        if self.kind is TokenKind.AGENT and self.agent_id is None:
            raise ValueError("agent tokens must reference an agent")
        if self.kind is TokenKind.ADMIN and self.agent_id is not None:
            raise ValueError("admin tokens must not reference an agent")
        return self


class IssuedToken(StrictModel):
    """Returned once on creation. ``plaintext`` has the form ``agw_<token_id>_<secret>``."""

    token: Token
    plaintext: SecretStr


class Principal(StrictModel):
    """The authenticated caller of a request."""

    kind: TokenKind
    token_id: str
    agent_id: str | None = None
    roles: tuple[str, ...] = ()

    @property
    def is_admin(self) -> bool:
        return self.kind is TokenKind.ADMIN
