"""Execution request and record (SPEC §8.7, §12)."""

from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, Field

from agent_gateway.brokers.base import ActionResult
from agent_gateway.common.models import Record, StrictModel
from agent_gateway.modules.authorization.models import Decision


class ExecutionStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"
    REJECTED = "rejected"
    EXPIRED = "expired"


TERMINAL_STATUSES = frozenset(
    {
        ExecutionStatus.SUCCEEDED,
        ExecutionStatus.FAILED,
        ExecutionStatus.DENIED,
        ExecutionStatus.REJECTED,
        ExecutionStatus.EXPIRED,
    }
)


class ExecutionRequest(StrictModel):
    """Body of ``POST /v1/executions`` and input of the MCP ``execute_action`` tool."""

    action: str = Field(min_length=1, max_length=128)
    resource_id: str = Field(min_length=1, max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=128)


class Execution(Record):
    agent_id: str
    action: str
    resource_id: str
    params: dict[str, Any] = Field(default_factory=dict)
    params_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    idempotency_key: str | None = None
    status: ExecutionStatus
    decision: Decision | None = None
    approval_id: str | None = None
    result: ActionResult | None = None
    error: str | None = None
    created_at: AwareDatetime
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES
