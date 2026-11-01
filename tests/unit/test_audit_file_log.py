"""File-based audit log: chaining, durability rules and tamper detection (SPEC §14, §19)."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from agent_gateway.common.errors import AuditUnavailableError
from agent_gateway.modules.audit.file_log import HEAD_FILE, FileAuditLog
from agent_gateway.modules.audit.models import (
    GENESIS_HASH,
    Actor,
    ActorType,
    AuditEntry,
    AuditEventType,
    AuditRecord,
)
from tests.fakes.clock import FixedClock
from tests.fakes.storage import InMemoryLocker


def _record(event: AuditEventType = AuditEventType.AGENT_CREATED, **details: object) -> AuditRecord:
    return AuditRecord(
        event=event, actor=Actor(type=ActorType.SYSTEM, id="test"), details=dict(details)
    )


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    return tmp_path / "audit"


@pytest.fixture
def log(audit_dir: Path, clock: FixedClock) -> FileAuditLog:
    return FileAuditLog(audit_dir, InMemoryLocker(), clock)


async def _fill(log: FileAuditLog, n: int) -> list[AuditEntry]:
    return [await log.append(_record(n=i)) for i in range(1, n + 1)]


def _day_file(audit_dir: Path) -> Path:
    files = sorted(audit_dir.glob("*.jsonl"))
    assert len(files) == 1
    return files[0]


def _day_names(audit_dir: Path) -> list[str]:
    return sorted(p.name for p in audit_dir.glob("*.jsonl"))


def _lines(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines()


def _write_lines(path: Path, lines: list[bytes]) -> None:
    path.write_bytes(b"".join(line + b"\n" for line in lines))


# -- appending ---------------------------------------------------------------


async def test_empty_log_verifies(log: FileAuditLog) -> None:
    result = await log.verify()
    assert result.ok
    assert result.entries_checked == 0


async def test_append_chains_entries(log: FileAuditLog, audit_dir: Path) -> None:
    entries = await _fill(log, 3)

    assert [e.seq for e in entries] == [1, 2, 3]
    assert entries[0].prev_hash == GENESIS_HASH
    assert entries[1].prev_hash == entries[0].hash
    assert all(e.compute_hash() == e.hash for e in entries)

    stored = [AuditEntry.model_validate_json(line) for line in _lines(_day_file(audit_dir))]
    assert stored == entries
    head = json.loads((audit_dir / HEAD_FILE).read_bytes())
    assert head == {"seq": 3, "hash": entries[-1].hash}

    result = await log.verify()
    assert result.ok
    assert result.entries_checked == 3


async def test_lines_are_canonical_json(log: FileAuditLog, audit_dir: Path) -> None:
    await log.append(_record(b=1, a=2))
    line = _lines(_day_file(audit_dir))[0]
    assert b" " not in line
    keys = list(json.loads(line))
    assert keys == sorted(keys)


async def test_chain_continues_across_daily_files(
    log: FileAuditLog, audit_dir: Path, clock: FixedClock
) -> None:
    first = await log.append(_record())
    clock.advance(timedelta(days=1))
    second = await log.append(_record())

    assert _day_names(audit_dir) == ["2026-01-01.jsonl", "2026-01-02.jsonl"]
    assert second.seq == 2
    assert second.prev_hash == first.hash
    assert (await log.verify()).ok


async def test_clock_going_back_never_writes_into_an_older_file(
    log: FileAuditLog, audit_dir: Path, clock: FixedClock
) -> None:
    clock.advance(timedelta(days=1))
    await log.append(_record())
    clock.advance(timedelta(days=-1))
    await log.append(_record())

    assert _day_names(audit_dir) == ["2026-01-02.jsonl"]
    assert (await log.verify()).ok


async def test_new_instance_continues_chain(
    log: FileAuditLog, audit_dir: Path, clock: FixedClock
) -> None:
    await _fill(log, 2)
    reopened = FileAuditLog(audit_dir, InMemoryLocker(), clock)
    entry = await reopened.append(_record())
    assert entry.seq == 3
    assert (await reopened.verify()).ok


async def test_query_filters(log: FileAuditLog, clock: FixedClock) -> None:
    start = clock.now()
    await log.append(_record(AuditEventType.AGENT_CREATED))
    clock.advance(timedelta(days=1))
    await log.append(_record(AuditEventType.TOKEN_CREATED))
    clock.advance(timedelta(days=1))
    await log.append(_record(AuditEventType.AGENT_CREATED))

    assert len(await log.query()) == 3
    assert [e.seq for e in await log.query(event=AuditEventType.AGENT_CREATED)] == [1, 3]
    assert [e.seq for e in await log.query(since=start + timedelta(hours=1))] == [2, 3]
    assert [e.seq for e in await log.query(until=start + timedelta(days=1))] == [1, 2]
    window = await log.query(
        since=start + timedelta(days=1), until=start + timedelta(days=1), event=None
    )
    assert [e.seq for e in window] == [2]


# -- fail closed ---------------------------------------------------------------


async def test_write_failure_raises_audit_unavailable(tmp_path: Path, clock: FixedClock) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    log = FileAuditLog(blocker, InMemoryLocker(), clock)
    with pytest.raises(AuditUnavailableError):
        await log.append(_record())


async def test_refuses_to_append_after_newest_line_deleted(
    log: FileAuditLog, audit_dir: Path
) -> None:
    await _fill(log, 3)
    path = _day_file(audit_dir)
    _write_lines(path, _lines(path)[:-1])
    with pytest.raises(AuditUnavailableError):
        await log.append(_record())


async def test_refuses_to_append_when_head_missing(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 2)
    (audit_dir / HEAD_FILE).unlink()
    with pytest.raises(AuditUnavailableError):
        await log.append(_record())


async def test_refuses_to_append_when_files_deleted(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 2)
    _day_file(audit_dir).unlink()
    with pytest.raises(AuditUnavailableError):
        await log.append(_record())
    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 1


async def test_refuses_to_append_after_torn_write(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 2)
    with _day_file(audit_dir).open("ab") as fh:
        fh.write(b'{"seq":3')
    with pytest.raises(AuditUnavailableError):
        await log.append(_record())
    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 3


async def test_recovers_head_after_interrupted_append(log: FileAuditLog, audit_dir: Path) -> None:
    entries = await _fill(log, 3)
    # Simulate a crash after the line was synced but before head.json was replaced.
    head_path = audit_dir / HEAD_FILE
    head_path.write_text(json.dumps({"seq": 2, "hash": entries[1].hash}))

    assert (await log.verify()).ok
    entry = await log.append(_record())
    assert entry.seq == 4
    assert entry.prev_hash == entries[2].hash
    assert json.loads(head_path.read_bytes())["seq"] == 4


# -- tamper detection (SPEC §19) -------------------------------------------------


async def test_detects_edited_line(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 5)
    path = _day_file(audit_dir)
    lines = _lines(path)
    data = json.loads(lines[2])
    data["details"]["n"] = 999
    lines[2] = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    _write_lines(path, lines)

    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 3
    assert result.entries_checked == 2


async def test_detects_edited_line_with_recomputed_hash(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 5)
    path = _day_file(audit_dir)
    lines = _lines(path)
    forged = AuditEntry.model_validate_json(lines[2]).model_copy(
        update={"actor": Actor(type=ActorType.ADMIN, id="attacker")}
    )
    forged = forged.model_copy(update={"hash": forged.compute_hash()})
    lines[2] = forged.model_dump_json().encode()
    _write_lines(path, lines)

    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 4  # the next link no longer matches


async def test_detects_deleted_line(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 5)
    path = _day_file(audit_dir)
    lines = _lines(path)
    del lines[1]
    _write_lines(path, lines)

    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 2


async def test_detects_inserted_line(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 5)
    path = _day_file(audit_dir)
    lines = _lines(path)
    lines.insert(3, lines[0])
    _write_lines(path, lines)

    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 4


async def test_detects_reordered_lines(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 5)
    path = _day_file(audit_dir)
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    _write_lines(path, lines)

    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 2


async def test_detects_deleted_newest_line_via_head(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 5)
    path = _day_file(audit_dir)
    _write_lines(path, _lines(path)[:-1])

    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 5
    assert result.entries_checked == 4


async def test_detects_deleted_daily_file(
    log: FileAuditLog, audit_dir: Path, clock: FixedClock
) -> None:
    await _fill(log, 2)
    clock.advance(timedelta(days=1))
    await _fill(log, 2)
    (audit_dir / "2026-01-01.jsonl").unlink()

    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 1


async def test_detects_missing_head(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 2)
    (audit_dir / HEAD_FILE).unlink()

    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq is None


async def test_detects_unparseable_line(log: FileAuditLog, audit_dir: Path) -> None:
    await _fill(log, 3)
    path = _day_file(audit_dir)
    lines = _lines(path)
    lines[1] = b"not json"
    _write_lines(path, lines)

    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 2
