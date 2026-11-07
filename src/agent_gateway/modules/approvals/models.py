"""Approval model (SPEC §8.8, §13)."""

from enum import StrEnum

from pydantic import AwareDatetime, Field

from agent_gateway.common.models import Record


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class Approver(StrEnum):
    """Who decides an approval (SPEC §13b)."""

    ADMIN = "admin"
    REQUESTER = "requester"


class Approval(Record):
    execution_id: str
    params_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    decided_by: str | None = None
    decided_at: AwareDatetime | None = None
    reason: str | None = Field(default=None, max_length=500)
    mode: Approver = Approver.ADMIN
    # The requesting user's ``sub``; set only when ``mode`` is ``requester``.
    requester: str | None = None
    # Copied from the execution so approval events can be traced (SPEC §12).
    correlation_id: str | None = Field(default=None, min_length=1, max_length=200)
