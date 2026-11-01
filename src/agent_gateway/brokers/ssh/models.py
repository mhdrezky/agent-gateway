"""SSH resource attributes and action params.

Every value that reaches a remote command is constrained here by a strict
pattern, and is shell-quoted again when the command is built.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# systemd unit name: no shell metacharacters, no whitespace, cannot start with "-".
SERVICE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$"
HOST_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$"
USERNAME_PATTERN = r"^[a-z_][a-z0-9_-]{0,31}$"
# OpenSSH style SHA-256 fingerprint, base64 without padding.
FINGERPRINT_PATTERN = r"^SHA256:[A-Za-z0-9+/]{43}$"

MAX_LOG_LINES = 500
DEFAULT_LOG_LINES = 100

ServiceName = Annotated[str, StringConstraints(pattern=SERVICE_PATTERN)]


class SshHostAttributes(BaseModel):
    """Schema of ``Resource.attributes`` for ``ssh_host`` resources (SPEC §8.5)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: Annotated[str, StringConstraints(pattern=HOST_PATTERN)]
    port: int = Field(default=22, ge=1, le=65535)
    username: Annotated[str, StringConstraints(pattern=USERNAME_PATTERN)]
    host_key_fingerprint: Annotated[str, StringConstraints(pattern=FINGERPRINT_PATTERN)]
    allowed_services: tuple[ServiceName, ...] = ()
    # Prefix privileged commands (restart) with "sudo -n"; never prompts for a password.
    use_sudo: bool = False


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServiceParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: ServiceName


class LogsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: ServiceName
    lines: int = Field(default=DEFAULT_LOG_LINES, ge=1, le=MAX_LOG_LINES, strict=True)
