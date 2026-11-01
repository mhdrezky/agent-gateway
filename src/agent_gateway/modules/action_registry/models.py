"""Action definitions (SPEC §11.1)."""

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.modules.resources.models import ResourceType

ACTION_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
DEFAULT_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 600


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True, kw_only=True)
class ActionDefinition:
    id: str
    broker: str
    resource_type: ResourceType
    description: str
    risk: RiskLevel
    input_model: type[BaseModel]
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    # Privileged actions (e.g. ssh.sudo) are never covered by a wildcard: a role and a
    # policy must name them exactly, so granting "ssh.*" never grants them by accident.
    privileged: bool = False

    def __post_init__(self) -> None:
        if not ACTION_ID_PATTERN.fullmatch(self.id):
            raise ValueError(f"invalid action id: {self.id!r}")
        if not self.id.startswith(f"{self.broker}."):
            raise ValueError(f"action id {self.id!r} must start with broker name {self.broker!r}")
        if not 0 < self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"timeout_seconds must be in 1..{MAX_TIMEOUT_SECONDS}")
        if self.privileged and self.risk not in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            raise ValueError(f"privileged action {self.id!r} must be high or critical risk")
        if self.input_model.model_config.get("extra") != "forbid":
            raise ValueError(f"input model of {self.id!r} must set extra='forbid'")

    def params_schema(self) -> dict[str, Any]:
        return self.input_model.model_json_schema()


# Params are typed per action, so the handler accepts the action's own input model.
ActionHandler = Callable[[ActionContext, Any], Awaitable[ActionResult]]


@dataclass(frozen=True, slots=True)
class RegisteredAction:
    definition: ActionDefinition
    handler: ActionHandler
