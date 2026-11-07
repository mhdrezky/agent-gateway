"""Approval workflow contract (SPEC §13)."""

from typing import Protocol

from agent_gateway.modules.approvals.models import Approval, ApprovalStatus, Approver
from agent_gateway.modules.identity.models import Principal


class ApprovalService(Protocol):
    async def request(
        self,
        execution_id: str,
        params_digest: str,
        *,
        mode: Approver = Approver.ADMIN,
        requester: str | None = None,
        correlation_id: str | None = None,
    ) -> Approval:
        """Create a pending approval that expires after the configured TTL.

        ``requester`` (the user's ``sub``) is required exactly when ``mode`` is ``requester``.
        """
        ...

    async def get(self, approval_id: str) -> Approval | None: ...

    async def find(self, *, status: ApprovalStatus | None = None) -> list[Approval]: ...

    async def approve(self, approval_id: str, actor: Principal) -> Approval:
        """Raise ``AdminRequiredError`` unless ``actor`` is an admin.

        Raise ``ApprovalNotPendingError`` if the approval is not pending or has expired.
        """
        ...

    async def reject(
        self, approval_id: str, actor: Principal, reason: str | None = None
    ) -> Approval:
        """Same rules as ``approve``."""
        ...

    async def decide_as_requester(
        self, approval_id: str, subject: str, *, approve: bool, reason: str | None = None
    ) -> Approval:
        """Decide a ``requester`` approval as the user ``subject`` (SPEC §13b).

        Raise ``ApprovalNotFoundError`` unless it is a ``requester`` approval of ``subject``,
        and ``ApprovalNotPendingError`` if it is decided or expired.
        """
        ...

    async def expire_due(self) -> list[Approval]:
        """Mark every pending approval past ``expires_at`` as expired and return them."""
        ...
