"""Gateway configuration (SPEC §17).

Priority, highest first: ``AGW_*`` environment variables, then the YAML file,
then the defaults below. Nested keys use ``__``, e.g. ``AGW_APPROVALS__TTL_MINUTES``.
"""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

DEFAULT_CONFIG_FILE = Path("config/gateway.yaml")
CONFIG_FILE_ENV = "AGW_CONFIG_FILE"


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServerSettings(_Section):
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)


class ApprovalSettings(_Section):
    ttl_minutes: int = Field(default=15, ge=1, le=1440)


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


class BrokerSettings(_Section):
    docker: DockerBrokerSettings = Field(default_factory=DockerBrokerSettings)


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
