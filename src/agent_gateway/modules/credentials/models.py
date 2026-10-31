"""Credential metadata and in-memory secret payload (SPEC §7.5, §8.6)."""

from collections.abc import Mapping
from enum import StrEnum
from typing import NoReturn

from pydantic import AwareDatetime, Field

from agent_gateway.common.models import Record

REDACTED = "***"


class CredentialType(StrEnum):
    SSH_PRIVATE_KEY = "ssh_private_key"
    API_TOKEN = "api_token"
    BASIC_AUTH = "basic_auth"
    DOCKER_TLS = "docker_tls"


class CredentialMeta(Record):
    """Everything about a credential except the secret itself."""

    type: CredentialType
    name: str = Field(min_length=1, max_length=100)
    version: int = Field(default=1, ge=1)
    key_version: int = Field(default=1, ge=1)
    created_at: AwareDatetime
    rotated_at: AwareDatetime | None = None


class SecretPayload:
    """A decrypted credential, alive only for the duration of one broker call.

    Deliberately not a Pydantic model so it can never be dumped into a response,
    log line, or audit entry by accident.
    """

    __slots__ = ("_fields", "_value", "type")

    def __init__(
        self, type: CredentialType, value: str, fields: Mapping[str, str] | None = None
    ) -> None:
        self.type = type
        self._value = value
        self._fields = dict(fields or {})

    def reveal(self) -> str:
        return self._value

    def field(self, name: str) -> str:
        return self._fields[name]

    def field_names(self) -> list[str]:
        return list(self._fields)

    def secret_values(self) -> list[str]:
        """Every secret string, for redacting broker output."""
        return [v for v in (self._value, *self._fields.values()) if v]

    def wipe(self) -> None:
        self._value = ""
        self._fields.clear()

    def __repr__(self) -> str:
        return f"SecretPayload(type={self.type.value}, value={REDACTED})"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretPayload cannot be pickled")
