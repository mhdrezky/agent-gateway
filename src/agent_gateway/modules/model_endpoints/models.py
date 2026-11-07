"""Model resources and the chat wire types (SPEC §8.5, §10.4, §15.4)."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_gateway.common.models import StrictModel
from agent_gateway.modules.action_registry.models import (
    MAX_TIMEOUT_SECONDS,
    ActionDefinition,
    RiskLevel,
)
from agent_gateway.modules.resources.models import ResourceType

# Body fields the gateway sets itself; options may not replace the model or turn on streaming.
RESERVED_OPTIONS = frozenset({"model", "messages", "tools", "tool_choice", "stream"})


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


# Granted by roles and policies like any action, but never registered: it is not listed in
# /v1/actions, is not an MCP tool, and cannot be submitted as an execution.
MODEL_CHAT = ActionDefinition(
    id="model.chat",
    broker="model",
    resource_type=ResourceType.MODEL,
    description="Send one chat turn to a model resource.",
    risk=RiskLevel.LOW,
    input_model=NoParams,
)


class ModelAttributes(StrictModel):
    """Schema of ``Resource.attributes`` for ``model`` resources: one exact model."""

    # Root of an OpenAI-compatible server; the gateway calls <base_url>/v1/chat/completions.
    base_url: str = Field(pattern=r"^https?://[^\s/?#]+(/[^\s?#]*)?$", max_length=2048)
    model_id: str = Field(min_length=1, max_length=255)
    options: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=60, ge=1, le=MAX_TIMEOUT_SECONDS)

    @field_validator("base_url")
    @classmethod
    def _no_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("model_id")
    @classmethod
    def _exact(cls, value: str) -> str:
        lowered = value.strip().lower()
        if lowered == "latest" or lowered.endswith(":latest"):
            raise ValueError("model_id must name an exact model, not 'latest'")
        return value

    @field_validator("options")
    @classmethod
    def _not_reserved(cls, value: dict[str, Any]) -> dict[str, Any]:
        reserved = sorted(RESERVED_OPTIONS & set(value))
        if reserved:
            raise ValueError(f"options may not set {', '.join(reserved)}")
        return value


class ModelInfo(StrictModel):
    """One entry of ``GET /v1/models``: a model name and the exact model behind it."""

    name: str
    model_id: str


class ChatIn(StrictModel):
    """``POST /v1/models/{name}/chat``: OpenAI-style messages for one turn."""

    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] = Field(default_factory=list)
    temperature: float | None = None
    max_tokens: int | None = Field(default=None, ge=1)
    correlation_id: str | None = Field(default=None, max_length=200)


class ChatOut(StrictModel):
    status: Literal["ok", "denied", "error"]
    message: dict[str, Any] | None = None
    usage: dict[str, Any] | None = None
    error: str | None = None
    model_id: str | None = None
