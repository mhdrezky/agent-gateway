"""Minimal action registry following the contract."""

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ValidationError

from agent_gateway.common.errors import ActionNotFoundError, InvalidParamsError
from agent_gateway.modules.action_registry.models import RegisteredAction


class FakeActionRegistry:
    def __init__(self) -> None:
        self._actions: dict[str, RegisteredAction] = {}

    def register(self, action: RegisteredAction) -> None:
        if action.definition.id in self._actions:
            raise ValueError(f"action {action.definition.id!r} already registered")
        self._actions[action.definition.id] = action

    def get(self, action_id: str) -> RegisteredAction | None:
        return self._actions.get(action_id)

    def all(self) -> list[RegisteredAction]:
        return list(self._actions.values())

    def validate_params(self, action_id: str, params: Mapping[str, Any]) -> BaseModel:
        action = self.get(action_id)
        if action is None:
            raise ActionNotFoundError(f"action {action_id!r} not found")
        try:
            return action.definition.input_model.model_validate(dict(params))
        except ValidationError as exc:
            raise InvalidParamsError(str(exc)) from exc
