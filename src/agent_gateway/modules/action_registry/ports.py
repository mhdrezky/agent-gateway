"""Action registry contract."""

from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import BaseModel

from agent_gateway.modules.action_registry.models import RegisteredAction


class ActionRegistry(Protocol):
    def register(self, action: RegisteredAction) -> None:
        """Raise ``ValueError`` if the action id is already registered."""
        ...

    def get(self, action_id: str) -> RegisteredAction | None:
        """Return ``None`` for unknown or disabled actions."""
        ...

    def all(self) -> list[RegisteredAction]: ...

    def validate_params(self, action_id: str, params: Mapping[str, Any]) -> BaseModel:
        """Raise ``ActionNotFoundError`` or ``InvalidParamsError``."""
        ...
