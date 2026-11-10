"""Gateway configuration (SPEC §17).

Priority, highest first: ``AGW_*`` environment variables, then the YAML file,
then the defaults below. Nested keys use ``__``, e.g. ``AGW_APPROVALS__TTL_MINUTES``.
"""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

DEFAULT_CONFIG_FILE = Path("config/gateway.yaml")
CONFIG_FILE_ENV = "AGW_CONFIG_FILE"


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerSettings(_Section):
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    # Host names (host[:port], "*" for any port) besides localhost that /mcp accepts in the
    # Host header, e.g. "gateway.example.com". Guards against DNS rebinding.
    public_hosts: list[str] = Field(default_factory=list)


class ApprovalSettings(_Section):
    ttl_minutes: int = Field(default=15, ge=1, le=1440)
    # Approving a privileged action (ssh.sudo) opens a window of this many minutes in which
    # the same agent may run that action on the same resource without asking again.
    # 0 turns windows off: every privileged command then needs its own approval.
    elevation_minutes: int = Field(default=15, ge=0, le=240)


class ExecutionSettings(_Section):
    max_concurrent: int = Field(default=8, ge=1, le=64)
    output_limit_bytes: int = Field(default=65536, ge=1024)


class AuditSettings(_Section):
    daily_anchor: bool = True


class RateLimitSettings(_Section):
    auth_failures_per_minute: int = Field(default=10, ge=1)


class ActionSettings(_Section):
    disabled: list[str] = Field(default_factory=list)


class DockerBrokerSettings(_Section):
    # Off by default: mounting the Docker socket is root-equivalent on the host.
    enabled: bool = False
    socket: str = "unix:///var/run/docker.sock"


class SqlBrokerSettings(_Section):
    # Off by default: only the instance that queries a database turns sql.query on.
    enabled: bool = False


class SmtpBrokerSettings(_Section):
    # Off by default: only the instance that sends mail (agentgate) turns mail.send on.
    enabled: bool = False


class McpBrokerSettings(_Section):
    # Off by default: only an instance that reaches external MCP servers (agentgate)
    # turns on the mcp_server resource type and its tools (SPEC §11.6).
    enabled: bool = False


class BrokerSettings(_Section):
    docker: DockerBrokerSettings = Field(default_factory=DockerBrokerSettings)
    sql: SqlBrokerSettings = Field(default_factory=SqlBrokerSettings)
    smtp: SmtpBrokerSettings = Field(default_factory=SmtpBrokerSettings)
    mcp: McpBrokerSettings = Field(default_factory=McpBrokerSettings)


# Asymmetric only: with HMAC algorithms a public JWKS key would double as a signing secret.
OIDC_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)


class OidcSettings(_Section):
    # The exact ``iss`` claim expected; may differ from the host ``jwks_url`` is fetched from.
    issuer: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    jwks_url: str = Field(min_length=1)
    groups_claim: str = "groups"
    algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"], min_length=1)
    leeway_seconds: int = Field(default=30, ge=0, le=300)
    jwks_cache_seconds: int = Field(default=300, ge=10, le=86400)

    @field_validator("algorithms")
    @classmethod
    def _asymmetric(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - OIDC_ALGORITHMS)
        if unknown:
            raise ValueError(f"unsupported OIDC algorithms: {', '.join(unknown)}")
        return value


class UserSettings(_Section):
    # Without OIDC settings every X-User-Token is refused (SPEC §9.4).
    oidc: OidcSettings | None = None


class BindSettings(_Section):
    # User roles allowed to call POST /v1/bind: authors bind at promote, reviewers at approval.
    roles: list[str] = Field(default_factory=lambda: ["author", "reviewer"])


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGW_",
        env_nested_delimiter="__",
        extra="forbid",
    )

    server: ServerSettings = Field(default_factory=ServerSettings)
    var_dir: Path = Path("var")
    master_key_file: Path = Path("secrets/master.key")
    approvals: ApprovalSettings = Field(default_factory=ApprovalSettings)
    execution: ExecutionSettings = Field(default_factory=ExecutionSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    actions: ActionSettings = Field(default_factory=ActionSettings)
    brokers: BrokerSettings = Field(default_factory=BrokerSettings)
    users: UserSettings = Field(default_factory=UserSettings)
    bind: BindSettings = Field(default_factory=BindSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # YAML values arrive as init kwargs; environment variables must override them.
        return (env_settings, init_settings)


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return data


def load_settings(config_file: Path | None = None) -> Settings:
    """Load settings. An explicitly named file must exist; the default file is optional."""
    if config_file is None:
        env_path = os.environ.get(CONFIG_FILE_ENV)
        config_file = Path(env_path) if env_path else None
    if config_file is not None:
        return Settings(**_read_yaml(config_file))
    if DEFAULT_CONFIG_FILE.is_file():
        return Settings(**_read_yaml(DEFAULT_CONFIG_FILE))
    return Settings()
