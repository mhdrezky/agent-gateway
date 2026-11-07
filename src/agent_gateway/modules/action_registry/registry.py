"""In-process action registry (SPEC §11.1)."""

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from pydantic import BaseModel, ValidationError

from agent_gateway.common.errors import ActionNotFoundError, InvalidParamsError
from agent_gateway.modules.action_registry.decorators import action as mark_action
from agent_gateway.modules.action_registry.decorators import definition_of
from agent_gateway.modules.action_registry.models import (
    DEFAULT_TIMEOUT_SECONDS,
    ActionHandler,
    RegisteredAction,
    RiskLevel,
)
from agent_gateway.modules.resources.models import ResourceType


class InMemoryActionRegistry:
    """Actions are defined only in code. Config can disable them, never add them."""

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        self._actions: dict[str, RegisteredAction] = {}
        self._disabled = frozenset(disabled)

    def register(self, action: RegisteredAction) -> None:
        action_id = action.definition.id
        if action_id in self._actions:
            raise ValueError(f"action {action_id!r} already registered")
        self._actions[action_id] = action

    def action(
        self,
        *,
        id: str,
        resource_type: ResourceType,
        risk: RiskLevel,
        description: str,
        input_model: type[BaseModel],
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        read_only: bool = False,
    ) -> Callable[[ActionHandler], ActionHandler]:
        """Decorator form of :meth:`register` for module-level handlers."""
        mark = mark_action(
            id=id,
            resource_type=resource_type,
            risk=risk,
            description=description,
            input_model=input_model,
            timeout_seconds=timeout_seconds,
            read_only=read_only,
        )

        def register(fn: ActionHandler) -> ActionHandler:
            marked = mark(fn)
            definition = definition_of(marked)
            if definition is None:  # pragma: no cover - mark_action always sets it
                raise RuntimeError(f"handler for {id!r} was not marked")
            self.register(RegisteredAction(definition, marked))
            return marked

        return register

    def get(self, action_id: str) -> RegisteredAction | None:
        if action_id in self._disabled:
            return None
        return self._actions.get(action_id)

    def all(self) -> list[RegisteredAction]:
        return [
            action
            for action_id, action in sorted(self._actions.items())
            if action_id not in self._disabled
        ]

    def unknown_disabled(self) -> list[str]:
        """Disabled ids that match no registered action, likely typos in config."""
        return sorted(self._disabled - self._actions.keys())

    def validate_params(self, action_id: str, params: Mapping[str, Any]) -> BaseModel:
        action = self.get(action_id)
        if action is None:
            raise ActionNotFoundError(f"action {action_id!r} not found")
        try:
            return action.definition.input_model.model_validate(dict(params))
        except ValidationError as exc:
            # Omit the rejected input so the message never echoes untrusted values back.
            problems = "; ".join(
                f"{'.'.join(str(p) for p in error['loc']) or 'params'}: {error['msg']}"
                for error in exc.errors(include_input=False, include_url=False)
            )
            raise InvalidParamsError(f"invalid params for {action_id!r}: {problems}") from exc
