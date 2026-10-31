"""Audit log contract (SPEC §14)."""

from datetime import datetime
from typing import Protocol

from agent_gateway.modules.audit.models import AuditEntry, AuditEventType, AuditRecord, VerifyResult


class AuditLog(Protocol):
    async def append(self, record: AuditRecord) -> AuditEntry:
        """Chain and persist the record. Raise ``AuditUnavailableError`` if it cannot be written;
        callers must then refuse to execute (fail closed).
        """
        ...

    async def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        event: AuditEventType | None = None,
    ) -> list[AuditEntry]: ...

    async def verify(self) -> VerifyResult: ...
