from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.common.errors import ActionNotFoundError, InvalidParamsError
from agent_gateway.modules.action_registry.decorators import action, collect_actions
from agent_gateway.modules.action_registry.models import RegisteredAction, RiskLevel
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.modules.resources.models import ResourceType
from tests.fakes.brokers import ECHO_ACTION, FakeBroker


class ServiceParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str = Field(pattern=r"^[a-z]+$")


class DemoBroker:
    @action(
        id="demo.service.status",
        resource_type=ResourceType.SSH_HOST,
        risk=RiskLevel.LOW,
        description="Status.",
        input_model=ServiceParams,
    )
    async def status(self, ctx: ActionContext, params: Any) -> ActionResult:
        return ActionResult(ok=True, data={"service": params.service})

    @action(
        id="demo.service.restart",
        resource_type=ResourceType.SSH_HOST,
        risk=RiskLevel.MEDIUM,
        description="Restart.",
        input_model=ServiceParams,
        timeout_seconds=30,
    )
    async def restart(self, ctx: ActionContext, params: Any) -> ActionResult:
        return ActionResult(ok=True)

    async def helper(self) -> None:
        return None


def test_register_and_get() -> None:
    registry: ActionRegistry = InMemoryActionRegistry()
    FakeBroker().register(registry)
    found = registry.get("fake.echo")
    assert found is not None
    assert found.definition == ECHO_ACTION
    assert registry.get("fake.missing") is None


def test_duplicate_rejected() -> None:
    registry = InMemoryActionRegistry()
    FakeBroker().register(registry)
    with pytest.raises(ValueError, match="already registered"):
        FakeBroker().register(registry)


def test_disabled_actions_are_hidden() -> None:
    registry = InMemoryActionRegistry(disabled=["fake.echo", "fake.typo"])
    FakeBroker().register(registry)
    assert registry.get("fake.echo") is None
    assert registry.all() == []
    assert registry.unknown_disabled() == ["fake.typo"]
    with pytest.raises(ActionNotFoundError):
        registry.validate_params("fake.echo", {"message": "hi"})


def test_disabled_action_still_blocks_duplicates() -> None:
    registry = InMemoryActionRegistry(disabled=["fake.echo"])
    FakeBroker().register(registry)
    with pytest.raises(ValueError, match="already registered"):
        FakeBroker().register(registry)


def test_validate_params() -> None:
    registry = InMemoryActionRegistry()
    FakeBroker().register(registry)
    params = registry.validate_params("fake.echo", {"message": "hi"})
    assert params.model_dump() == {"message": "hi"}

    with pytest.raises(ActionNotFoundError):
        registry.validate_params("fake.nope", {})
    with pytest.raises(InvalidParamsError, match="Extra inputs"):
        registry.validate_params("fake.echo", {"message": "hi", "cmd": "rm -rf /"})
    with pytest.raises(InvalidParamsError, match="message"):
        registry.validate_params("fake.echo", {})


def test_invalid_params_message_does_not_echo_input() -> None:
    registry = InMemoryActionRegistry()
    for registered in collect_actions(DemoBroker()):
        registry.register(registered)
    with pytest.raises(InvalidParamsError) as info:
        registry.validate_params("demo.service.status", {"service": "nginx; s3cr3t"})
    assert "s3cr3t" not in info.value.message


async def test_collect_actions_binds_methods() -> None:
    broker = DemoBroker()
    actions = collect_actions(broker)
    assert [a.definition.id for a in actions] == ["demo.service.restart", "demo.service.status"]
    restart, status = actions
    assert restart.definition.broker == "demo"
    assert restart.definition.timeout_seconds == 30
    assert restart.definition.risk is RiskLevel.MEDIUM
    result = await status.handler(None, ServiceParams(service="nginx"))  # type: ignore[arg-type]
    assert result.data == {"service": "nginx"}


def test_all_sorted_by_id() -> None:
    registry = InMemoryActionRegistry()
    for registered in collect_actions(DemoBroker()):
        registry.register(registered)
    FakeBroker().register(registry)
    assert [a.definition.id for a in registry.all()] == [
        "demo.service.restart",
        "demo.service.status",
        "fake.echo",
    ]


async def test_registry_decorator() -> None:
    registry = InMemoryActionRegistry()

    @registry.action(
        id="demo.ping.run",
        resource_type=ResourceType.HTTP_ENDPOINT,
        risk=RiskLevel.LOW,
        description="Ping.",
        input_model=ServiceParams,
    )
    async def ping(ctx: ActionContext, params: Any) -> ActionResult:
        return ActionResult(ok=True)

    found = registry.get("demo.ping.run")
    assert isinstance(found, RegisteredAction)
    assert found.handler is ping


def test_decorator_rejects_sync_handler() -> None:
    with pytest.raises(TypeError, match="async"):
        action(
            id="demo.x.y",
            resource_type=ResourceType.SSH_HOST,
            risk=RiskLevel.LOW,
            description="x",
            input_model=ServiceParams,
        )(lambda ctx, params: None)


def test_decorator_validates_definition() -> None:
    class Loose(BaseModel):
        x: int

    with pytest.raises(ValueError, match="extra='forbid'"):
        action(
            id="demo.x.y",
            resource_type=ResourceType.SSH_HOST,
            risk=RiskLevel.LOW,
            description="x",
            input_model=Loose,
        )
