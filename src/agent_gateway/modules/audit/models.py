"""Audit entries and hash chain rules (SPEC §14)."""

from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, Field

from agent_gateway.common.canonical import sha256_hex
from agent_gateway.common.models import StrictModel

GENESIS_HASH = "0" * 64
HASH_PATTERN = r"^[0-9a-f]{64}$"


class AuditEventType(StrEnum):
    AUTH_FAILED = "auth.failed"
    AGENT_CREATED = "agent.created"
    AGENT_UPDATED = "agent.updated"
    TOKEN_CREATED = "token.created"
    TOKEN_REVOKED = "token.revoked"
    RESOURCE_CREATED = "resource.created"
    RESOURCE_UPDATED = "resource.updated"
    RESOURCE_DELETED = "resource.deleted"
    CREDENTIAL_CREATED = "credential.created"
    CREDENTIAL_ROTATED = "credential.rotated"
    CREDENTIAL_DELETED = "credential.deleted"
    ROLE_UPDATED = "role.updated"
    POLICY_CREATED = "policy.created"
    POLICY_UPDATED = "policy.updated"
    POLICY_DELETED = "policy.deleted"
    EXECUTION_REQUESTED = "execution.requested"
    EXECUTION_DENIED = "execution.denied"
    EXECUTION_REJECTED = "execution.rejected"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_APPROVED = "approval.approved"
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_EXPIRED = "approval.expired"
    EXECUTION_STARTED = "execution.started"
    EXECUTION_SUCCEEDED = "execution.succeeded"
    EXECUTION_FAILED = "execution.failed"


class ActorType(StrEnum):
    AGENT = "agent"
    ADMIN = "admin"
    SYSTEM = "system"


class Actor(StrictModel):
    type: ActorType
    id: str


class AuditRecord(StrictModel):
    """What a caller submits. Never put raw params or secrets in here; use ``params_digest``."""

    event: AuditEventType
    actor: Actor
    execution_id: str | None = None
    action: str | None = None
    resource_id: str | None = None
    params_digest: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class AuditEntry(AuditRecord):
    """A record after it is placed in the chain."""

    seq: int = Field(ge=1)
    ts: AwareDatetime
    prev_hash: str = Field(pattern=HASH_PATTERN)
    hash: str = Field(pattern=HASH_PATTERN)

    def compute_hash(self) -> str:
        """SHA-256 of the canonical JSON of every field except ``hash``."""
        return sha256_hex(self.model_dump(mode="json", exclude={"hash"}))


class VerifyResult(StrictModel):
    ok: bool
    entries_checked: int
    first_bad_seq: int | None = None
    reason: str | None = None
