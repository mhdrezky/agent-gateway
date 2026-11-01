"""File-based audit log: daily JSONL files chained by SHA-256 (SPEC §14).

Layout under ``directory``::

    2026-10-31.jsonl   one canonical JSON entry per line, chain continues across days
    head.json          {"seq": ..., "hash": ...} of the newest entry

Every append runs under the ``audit`` lock, is flushed and fsynced before ``head.json``
is replaced, and any failure raises ``AuditUnavailableError`` so callers fail closed.

Crash window: if the process dies after the line is synced but before ``head.json`` is
replaced, the head is exactly one entry behind and that entry links to it. ``append``
rolls the head forward in that case and ``verify`` accepts it; any other mismatch is
reported as tampering.

TODO(§14.3): optional daily anchor ``HMAC(KeyRing.subkey(SubkeyPurpose.AUDIT_ANCHOR),
head_hash)`` written to the server log, so deleting every file is also detectable.
"""

import asyncio
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from pydantic import ValidationError

from agent_gateway.common.canonical import canonical_json
from agent_gateway.common.clock import Clock
from agent_gateway.common.errors import AuditUnavailableError
from agent_gateway.modules.audit.models import (
    GENESIS_HASH,
    AuditEntry,
    AuditEventType,
    AuditRecord,
    VerifyResult,
)
from agent_gateway.modules.storage.ports import Locker

LOCK_NAME = "audit"
HEAD_FILE = "head.json"
_DAY_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")
_TAIL_BLOCK = 4096


class _CorruptLogError(Exception):
    """The files on disk are not a consistent chain; appending would extend a broken log."""


@dataclass(frozen=True, slots=True)
class _Head:
    seq: int
    hash: str


class FileAuditLog:
    def __init__(self, directory: Path, locker: Locker, clock: Clock) -> None:
        self._dir = directory
        self._locker = locker
        self._clock = clock

    async def append(self, record: AuditRecord) -> AuditEntry:
        try:
            async with self._locker.lock(LOCK_NAME):
                return await asyncio.to_thread(self._append_sync, record)
        except AuditUnavailableError:
            raise
        except Exception as exc:
            raise AuditUnavailableError(f"audit log unavailable: {exc}") from exc

    async def query(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        event: AuditEventType | None = None,
    ) -> list[AuditEntry]:
        async with self._locker.lock(LOCK_NAME):
            return await asyncio.to_thread(self._query_sync, since, until, event)

    async def verify(self) -> VerifyResult:
        async with self._locker.lock(LOCK_NAME):
            return await asyncio.to_thread(self._verify_sync)

    # -- append ---------------------------------------------------------------

    def _append_sync(self, record: AuditRecord) -> AuditEntry:
        self._dir.mkdir(parents=True, exist_ok=True)
        files = self._day_files()
        head = self._current_head(files)

        ts = self._clock.now().astimezone(UTC)
        draft = AuditEntry(
            **record.model_dump(),
            seq=head.seq + 1,
            ts=ts,
            prev_hash=head.hash,
            hash=GENESIS_HASH,
        )
        entry = draft.model_copy(update={"hash": draft.compute_hash()})

        # Never write into a file older than the newest one, even if the clock went back,
        # so reading files in name order always yields the chain in order.
        day = ts.date()
        if files and files[-1][0] > day:
            day = files[-1][0]
        path = self._dir / f"{day.isoformat()}.jsonl"
        created = not path.exists()
        with path.open("ab") as fh:
            fh.write(canonical_json(entry) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        if created:
            _fsync_dir(self._dir)
        self._write_head(_Head(entry.seq, entry.hash))
        return entry

    def _current_head(self, files: list[tuple[date, Path]]) -> _Head:
        stored = self._read_head()
        last = self._last_entry(files)
        if last is None:
            if stored is not None and stored.seq != 0:
                raise _CorruptLogError("head.json exists but the log files are missing")
            return _Head(0, GENESIS_HASH)
        tail = _Head(last.seq, last.hash)
        if stored == tail:
            return tail
        if (
            stored is not None
            and last.seq == stored.seq + 1
            and last.prev_hash == stored.hash
            and last.compute_hash() == last.hash
        ):
            # Interrupted append: the line is durable but head.json was not replaced.
            self._write_head(tail)
            return tail
        raise _CorruptLogError("head.json does not match the newest log entry")

    def _last_entry(self, files: list[tuple[date, Path]]) -> AuditEntry | None:
        for _, path in reversed(files):
            line = _last_line(path)
            if line is not None:
                return AuditEntry.model_validate_json(line)
        return None

    def _read_head(self) -> _Head | None:
        path = self._dir / HEAD_FILE
        if not path.exists():
            return None
        data = json.loads(path.read_bytes())
        return _Head(seq=int(data["seq"]), hash=str(data["hash"]))

    def _write_head(self, head: _Head) -> None:
        target = self._dir / HEAD_FILE
        tmp = self._dir / f"{HEAD_FILE}.tmp-{os.getpid()}"
        with tmp.open("wb") as fh:
            fh.write(canonical_json({"seq": head.seq, "hash": head.hash}))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
        _fsync_dir(self._dir)

    # -- read -----------------------------------------------------------------

    def _day_files(self) -> list[tuple[date, Path]]:
        if not self._dir.is_dir():
            return []
        found: list[tuple[date, Path]] = []
        for path in self._dir.iterdir():
            match = _DAY_FILE.match(path.name)
            if match and path.is_file():
                found.append((date.fromisoformat(match.group(1)), path))
        return sorted(found)

    def _query_sync(
        self,
        since: datetime | None,
        until: datetime | None,
        event: AuditEventType | None,
    ) -> list[AuditEntry]:
        result: list[AuditEntry] = []
        for day, path in self._day_files():
            # An entry is never stored in a file dated before its own timestamp.
            if since is not None and day < since.astimezone(UTC).date():
                continue
            for line in path.read_bytes().splitlines():
                if not line.strip():
                    continue
                entry = AuditEntry.model_validate_json(line)
                if (
                    (since is None or entry.ts >= since)
                    and (until is None or entry.ts <= until)
                    and (event is None or entry.event == event)
                ):
                    result.append(entry)
        return result

    # -- verify ---------------------------------------------------------------

    def _verify_sync(self) -> VerifyResult:
        """Check the whole chain. ``first_bad_seq`` is the first chain position that is wrong,
        so a deleted, inserted or swapped line is reported where the gap or intruder sits.
        """
        hashes = [GENESIS_HASH]  # hashes[n] is the hash of entry seq n
        for _, path in self._day_files():
            raw = path.read_bytes()
            for line in raw.splitlines():
                expected = len(hashes)
                try:
                    entry = AuditEntry.model_validate_json(line)
                except ValidationError:
                    return _bad(expected, f"{path.name}: unreadable entry")
                if entry.seq != expected:
                    return _bad(expected, f"expected seq {expected}, found {entry.seq}")
                if entry.prev_hash != hashes[-1]:
                    return _bad(expected, "prev_hash does not match the previous entry")
                if entry.compute_hash() != entry.hash:
                    return _bad(expected, "hash does not match the entry content")
                hashes.append(entry.hash)
            if raw and not raw.endswith(b"\n"):
                return _bad(len(hashes) - 1, f"{path.name}: incomplete last line")

        last_seq = len(hashes) - 1
        try:
            head = self._read_head()
        except (OSError, ValueError, KeyError, TypeError):
            return _bad(None, "head.json is unreadable", checked=last_seq)
        if head is None:
            if last_seq == 0:
                return VerifyResult(ok=True, entries_checked=0)
            return _bad(None, "head.json is missing", checked=last_seq)
        if head.seq > last_seq:
            return _bad(last_seq + 1, f"log ends at seq {last_seq} but head.json says {head.seq}")
        if head.hash != hashes[head.seq]:
            return _bad(head.seq or None, "head.json hash does not match the log", checked=last_seq)
        if head.seq in (last_seq, last_seq - 1):
            # One behind is an interrupted append (see module docstring).
            return VerifyResult(ok=True, entries_checked=last_seq)
        return _bad(head.seq + 1, "entries found beyond head.json", checked=last_seq)


def _bad(seq: int | None, reason: str, *, checked: int | None = None) -> VerifyResult:
    if checked is None:
        checked = seq - 1 if seq is not None else 0
    return VerifyResult(ok=False, entries_checked=checked, first_bad_seq=seq, reason=reason)


def _last_line(path: Path) -> bytes | None:
    """Return the last complete line of ``path``, or ``None`` if the file is empty."""
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size == 0:
            return None
        data = b""
        pos = size
        while pos > 0:
            step = min(_TAIL_BLOCK, pos)
            pos -= step
            fh.seek(pos)
            data = fh.read(step) + data
            if data.count(b"\n") >= 2:
                break
    if not data.endswith(b"\n"):
        raise _CorruptLogError(f"{path.name}: incomplete last line")
    return data[:-1].rsplit(b"\n", 1)[-1]


def _fsync_dir(directory: Path) -> None:
    # Directory fsync makes a new file name durable; Windows does not support it.
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
