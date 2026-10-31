"""In-memory audit log that follows the real hash chain rules."""

from datetime import datetime

from agent_gateway.common.clock import Clock, SystemClock
from agent_gateway.common.errors import AuditUnavailableError
from agent_gateway.modules.audit.models import (
    GENESIS_HASH,
    AuditEntry,
    AuditEventType,
    AuditRecord,
    VerifyResult,
)


class FakeAuditLog:
    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()
        self.entries: list[AuditEntry] = []
        self.fail_writes = False

    async def append(self, record: AuditRecord) -> AuditEntry:
        if self.fail_writes:
            raise AuditUnavailableError("audit log unavailable")
        prev_hash = self.entries[-1].hash if self.entries else GENESIS_HASH
        draft = AuditEntry(
            **record.model_dump(),
            seq=len(self.entries) + 1,
            ts=self._clock.now(),
            prev_hash=prev_hash,
            hash=GENESIS_HASH,
        )
        entry = draft.model_copy(update={"hash": draft.compute_hash()})
        self.entries.append(entry)
        return entry

    async def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        event: AuditEventType | None = None,
    ) -> list[AuditEntry]:
        return [
            e
            for e in self.entries
            if (since is None or e.ts >= since)
            and (until is None or e.ts <= until)
            and (event is None or e.event == event)
        ]

    async def verify(self) -> VerifyResult:
        prev_hash = GENESIS_HASH
        for index, entry in enumerate(self.entries, start=1):
            if entry.seq != index:
                return VerifyResult(
                    ok=False, entries_checked=index - 1, first_bad_seq=entry.seq, reason="seq gap"
                )
            if entry.prev_hash != prev_hash:
                return VerifyResult(
                    ok=False,
                    entries_checked=index - 1,
                    first_bad_seq=entry.seq,
                    reason="broken link",
                )
            if entry.compute_hash() != entry.hash:
                return VerifyResult(
                    ok=False, entries_checked=index - 1, first_bad_seq=entry.seq, reason="bad hash"
                )
            prev_hash = entry.hash
        return VerifyResult(ok=True, entries_checked=len(self.entries))
