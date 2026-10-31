"""Approval model (SPEC §8.8, §13)."""

from enum import StrEnum

from pydantic import AwareDatetime, Field

from agent_gateway.common.models import Record


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class Approval(Record):
    execution_id: str
    params_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    decided_by: str | None = None
    decided_at: AwareDatetime | None = None
    reason: str | None = Field(default=None, max_length=500)
