"""Declare actions next to their handlers (SPEC §11.1).

Brokers mark handler methods with :func:`action`; :func:`collect_actions` turns
the marked methods of a broker instance into ``RegisteredAction`` objects bound
to that instance, ready for ``ActionRegistry.register``.
"""

import inspect
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from agent_gateway.modules.action_registry.models import (
    DEFAULT_TIMEOUT_SECONDS,
    ActionDefinition,
    ActionHandler,
    RegisteredAction,
    RiskLevel,
)
from agent_gateway.modules.resources.models import ResourceType

_MARKER = "__agw_action__"


def action[F: Callable[..., Any]](
    *,
    id: str,
    resource_type: ResourceType,
    risk: RiskLevel,
    description: str,
    input_model: type[BaseModel],
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    privileged: bool = False,
) -> Callable[[F], F]:
    """Attach an ``ActionDefinition`` to a handler. The broker name is the id's first segment."""
    definition = ActionDefinition(
        id=id,
        broker=id.split(".", 1)[0],
        resource_type=resource_type,
        description=description,
        risk=risk,
        input_model=input_model,
        timeout_seconds=timeout_seconds,
        privileged=privileged,
    )

    def mark(fn: F) -> F:
        if not inspect.iscoroutinefunction(fn):
            raise TypeError(f"handler for {id!r} must be async")
        setattr(fn, _MARKER, definition)
        return fn

    return mark


def definition_of(fn: object) -> ActionDefinition | None:
    found = getattr(fn, _MARKER, None)
    return found if isinstance(found, ActionDefinition) else None


def collect_actions(owner: object) -> list[RegisteredAction]:
    """Every handler on ``owner`` marked with :func:`action`, sorted by action id."""
    found: list[RegisteredAction] = []
    for name in dir(type(owner)):
        definition = definition_of(getattr(type(owner), name, None))
        if definition is not None:
            handler: ActionHandler = getattr(owner, name)
            found.append(RegisteredAction(definition, handler))
    return sorted(found, key=lambda registered: registered.definition.id)
