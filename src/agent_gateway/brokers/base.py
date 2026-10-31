"""Broker contract (SPEC §11.2).

Brokers never receive a command string from an agent. They receive typed,
validated params and a decrypted credential, and return output that is safe
to hand back to the agent.
"""

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, Field

from agent_gateway.common.models import StrictModel
from agent_gateway.modules.credentials.models import SecretPayload
from agent_gateway.modules.resources.models import Resource, ResourceType

if TYPE_CHECKING:
    from agent_gateway.modules.action_registry.ports import ActionRegistry


@dataclass(frozen=True, slots=True, kw_only=True)
class ActionContext:
    execution_id: str
    agent_id: str
    resource: Resource
    credential: SecretPayload | None
    timeout_seconds: int
    output_limit_bytes: int
    logger: logging.Logger


class ActionResult(StrictModel):
    ok: bool
    data: dict[str, Any] = Field(default_factory=dict)
    truncated: bool = False
    error: str | None = None


class Broker(Protocol):
    @property
    def name(self) -> str: ...

    def resource_attribute_models(self) -> Mapping[ResourceType, type[BaseModel]]:
        """Schemas for ``Resource.attributes`` of each resource type this broker serves."""
        ...

    def register(self, registry: "ActionRegistry") -> None:
        """Register every action this broker provides."""
        ...
