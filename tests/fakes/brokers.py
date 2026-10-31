"""A broker with one harmless action, for engine and API tests."""

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.modules.action_registry.models import (
    ActionDefinition,
    RegisteredAction,
    RiskLevel,
)
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.resources.models import ResourceType


class EchoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(max_length=200)


class EchoAttributes(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str


ECHO_ACTION = ActionDefinition(
    id="fake.echo",
    broker="fake",
    resource_type=ResourceType.HTTP_ENDPOINT,
    description="Return the message unchanged.",
    risk=RiskLevel.LOW,
    input_model=EchoParams,
)


class FakeBroker:
    def __init__(self) -> None:
        self.calls: list[tuple[ActionContext, EchoParams]] = []

    @property
    def name(self) -> str:
        return "fake"

    def resource_attribute_models(self) -> Mapping[ResourceType, type[BaseModel]]:
        return {ResourceType.HTTP_ENDPOINT: EchoAttributes}

    def register(self, registry: ActionRegistry) -> None:
        registry.register(RegisteredAction(ECHO_ACTION, self._echo))

    async def _echo(self, ctx: ActionContext, params: Any) -> ActionResult:
        assert isinstance(params, EchoParams)
        self.calls.append((ctx, params))
        return ActionResult(ok=True, data={"message": params.message})
