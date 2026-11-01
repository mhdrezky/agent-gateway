"""JSON collection, blob store, and file locking (SPEC §6)."""

import asyncio
import json
import multiprocessing
import os
from contextlib import AbstractAsyncContextManager
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from filelock import FileLock

from agent_gateway.modules.storage import atomic
from agent_gateway.modules.storage.atomic import (
    atomic_write_bytes,
    cleanup_stale_temp_files,
    is_safe_name,
)
from agent_gateway.modules.storage.blob_store import FileBlobStore
from agent_gateway.modules.storage.errors import (
    CorruptCollectionError,
    InvalidNameError,
    LockTimeoutError,
    SchemaVersionError,
)
from agent_gateway.modules.storage.json_collection import JsonCollection
from agent_gateway.modules.storage.locking import FileLocker
from agent_gateway.modules.storage.ports import Collection
from tests.contracts.collection import CollectionContract, Item
from tests.fakes.clock import FixedClock
from tests.fakes.storage import InMemoryLocker


def make_collection(var: Path, **kwargs: Any) -> JsonCollection[Item]:
    return JsonCollection(var / "items.json", Item, locker=FileLocker(var / ".locks"), **kwargs)


def temp_files(directory: Path) -> list[Path]:
    return [p for p in directory.iterdir() if atomic.TEMP_MARKER in p.name]


def write_raw(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


class TestJsonCollectionContract(CollectionContract):
    @pytest.fixture
    def collection(self, tmp_path: Path) -> Collection[Item]:
        return make_collection(tmp_path)


class TestJsonCollectionFile:
    async def test_missing_file_reads_as_empty(self, tmp_path: Path) -> None:
        collection = make_collection(tmp_path)
        assert await collection.all() == []
        await collection.check()
        assert not collection.path.exists()

    async def test_envelope_format(self, tmp_path: Path) -> None:
        clock = FixedClock()
        collection = make_collection(tmp_path, clock=clock)
        await collection.put(Item(id="a", value=7))
        document = json.loads(collection.path.read_text(encoding="utf-8"))
        assert document == {
            "schema_version": 1,
            "updated_at": "2026-01-01T00:00:00Z",
            "items": {"a": {"id": "a", "value": 7}},
        }

    async def test_updated_at_follows_clock(self, tmp_path: Path) -> None:
        clock = FixedClock()
        collection = make_collection(tmp_path, clock=clock)
        await collection.put(Item(id="a"))
        clock.advance(timedelta(hours=1))
        await collection.update("a", lambda item: item)
        document = json.loads(collection.path.read_text(encoding="utf-8"))
        assert document["updated_at"] == "2026-01-01T01:00:00Z"

    async def test_persists_across_instances(self, tmp_path: Path) -> None:
        await make_collection(tmp_path).put(Item(id="a", value=1))
        assert await make_collection(tmp_path).get("a") == Item(id="a", value=1)

    async def test_sees_writes_from_another_instance(self, tmp_path: Path) -> None:
        first, second = make_collection(tmp_path), make_collection(tmp_path)
        assert await first.all() == []
        await second.put(Item(id="b"))
        assert await first.get("b") == Item(id="b")

    async def test_delete_missing_does_not_write(self, tmp_path: Path) -> None:
        collection = make_collection(tmp_path)
        assert await collection.delete("nope") is False
        assert not collection.path.exists()

    async def test_failing_update_fn_writes_nothing(self, tmp_path: Path) -> None:
        collection = make_collection(tmp_path)
        await collection.put(Item(id="a", value=1))
        before = collection.path.read_bytes()

        def boom(item: Item) -> Item:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await collection.update("a", boom)
        assert collection.path.read_bytes() == before

    def test_rejects_invalid_schema_version_argument(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="schema_version"):
            make_collection(tmp_path, schema_version=0)


class TestJsonCollectionValidation:
    async def test_newer_schema_version_is_refused(self, tmp_path: Path) -> None:
        collection = make_collection(tmp_path)
        write_raw(
            collection.path,
            {"schema_version": 2, "updated_at": "2026-01-01T00:00:00Z", "items": {}},
        )
        with pytest.raises(SchemaVersionError, match="newer"):
            await collection.check()
        with pytest.raises(SchemaVersionError):
            await collection.put(Item(id="a"))

    async def test_older_schema_version_is_migrated(self, tmp_path: Path) -> None:
        def v1_to_v2(raw: dict[str, Any]) -> dict[str, Any]:
            items = {key: {"id": key, "value": old["n"]} for key, old in raw["items"].items()}
            return {**raw, "items": items}

        collection = make_collection(tmp_path, schema_version=2, migrations={1: v1_to_v2})
        write_raw(
            collection.path,
            {"schema_version": 1, "updated_at": "2026-01-01T00:00:00Z", "items": {"a": {"n": 3}}},
        )
        assert await collection.get("a") == Item(id="a", value=3)
        await collection.put(Item(id="b"))
        document = json.loads(collection.path.read_text(encoding="utf-8"))
        assert document["schema_version"] == 2
        assert document["items"]["a"] == {"id": "a", "value": 3}

    async def test_missing_migration_is_refused(self, tmp_path: Path) -> None:
        collection = make_collection(tmp_path, schema_version=3, migrations={2: lambda raw: raw})
        write_raw(
            collection.path,
            {"schema_version": 1, "updated_at": "2026-01-01T00:00:00Z", "items": {}},
        )
        with pytest.raises(SchemaVersionError, match="no migration from schema version 1"):
            await collection.all()

    @pytest.mark.parametrize(
        "content",
        [
            b"{not json",
            b"\xff\xfe",
            b"[]",
            b'{"updated_at": "2026-01-01T00:00:00Z", "items": {}}',
            b'{"schema_version": true, "updated_at": "2026-01-01T00:00:00Z", "items": {}}',
            b'{"schema_version": 0, "updated_at": "2026-01-01T00:00:00Z", "items": {}}',
            b'{"schema_version": 1, "updated_at": "2026-01-01T00:00:00", "items": {}}',
            b'{"schema_version": 1, "updated_at": "2026-01-01T00:00:00Z", "items": {}, "x": 1}',
        ],
    )
    async def test_corrupt_file_is_refused(self, tmp_path: Path, content: bytes) -> None:
        collection = make_collection(tmp_path)
        collection.path.write_bytes(content)
        with pytest.raises(CorruptCollectionError):
            await collection.all()

    async def test_key_must_match_item_id(self, tmp_path: Path) -> None:
        collection = make_collection(tmp_path)
        write_raw(
            collection.path,
            {
                "schema_version": 1,
                "updated_at": "2026-01-01T00:00:00Z",
                "items": {"a": {"id": "b", "value": 1}},
            },
        )
        with pytest.raises(CorruptCollectionError, match="does not match"):
            await collection.get("a")

    async def test_validation_error_does_not_leak_contents(self, tmp_path: Path) -> None:
        collection = make_collection(tmp_path)
        write_raw(
            collection.path,
            {
                "schema_version": 1,
                "updated_at": "2026-01-01T00:00:00Z",
                "items": {"a": {"id": "a", "value": "s3cr3t-value"}},
            },
        )
        with pytest.raises(CorruptCollectionError) as info:
            await collection.all()
        assert "s3cr3t-value" not in str(info.value)
        assert "items.a.value" in str(info.value)
        assert info.value.__cause__ is None
        assert info.value.__suppress_context__


class TestCrashSafety:
    async def test_failure_before_replace_keeps_old_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        collection = make_collection(tmp_path)
        await collection.put(Item(id="a", value=1))
        before = collection.path.read_bytes()

        def crash(src: object, dst: object) -> None:
            raise OSError("simulated crash before rename")

        monkeypatch.setattr(os, "replace", crash)
        with pytest.raises(OSError, match="simulated crash"):
            await collection.put(Item(id="a", value=2))
        monkeypatch.undo()

        assert collection.path.read_bytes() == before
        assert temp_files(tmp_path) == []
        assert await collection.get("a") == Item(id="a", value=1)

    async def test_failure_during_fsync_keeps_old_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        collection = make_collection(tmp_path)
        await collection.put(Item(id="a", value=1))

        def crash(fd: int) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(os, "fsync", crash)
        with pytest.raises(OSError, match="disk full"):
            await collection.put(Item(id="a", value=2))
        monkeypatch.undo()

        assert temp_files(tmp_path) == []
        assert await collection.get("a") == Item(id="a", value=1)

    async def test_leftover_temp_file_is_ignored_then_cleaned(self, tmp_path: Path) -> None:
        collection = make_collection(tmp_path)
        await collection.put(Item(id="a", value=1))
        # A process killed mid-write leaves a partial temp file behind.
        leftover = tmp_path / "items.json.tmp-abc123"
        leftover.write_bytes(b'{"schema_version": 1, "upd')
        nested = tmp_path / "credentials" / "cred_x.bin.tmp-zz"
        nested.parent.mkdir()
        nested.write_bytes(b"partial")

        assert await collection.get("a") == Item(id="a", value=1)
        removed = cleanup_stale_temp_files(tmp_path)
        assert sorted(removed) == sorted([leftover, nested])
        assert not leftover.exists()
        assert not nested.exists()
        assert collection.path.exists()

    def test_cleanup_respects_age_cutoff(self, tmp_path: Path) -> None:
        old = tmp_path / "a.json.tmp-old"
        fresh = tmp_path / "b.json.tmp-new"
        old.write_bytes(b"")
        fresh.write_bytes(b"")
        now = FixedClock().now()
        os.utime(old, (now.timestamp() - 3600, now.timestamp() - 3600))
        os.utime(fresh, (now.timestamp(), now.timestamp()))

        removed = cleanup_stale_temp_files(tmp_path, older_than=now - timedelta(minutes=1))
        assert removed == [old]
        assert fresh.exists()

    def test_cleanup_skips_directories_and_missing_root(self, tmp_path: Path) -> None:
        (tmp_path / "dir.tmp-x").mkdir()
        assert cleanup_stale_temp_files(tmp_path) == []
        assert cleanup_stale_temp_files(tmp_path / "missing") == []

    def test_atomic_write_creates_parent_and_replaces(self, tmp_path: Path) -> None:
        target = tmp_path / "sub" / "file.bin"
        atomic_write_bytes(target, b"one")
        atomic_write_bytes(target, b"two")
        assert target.read_bytes() == b"two"
        assert temp_files(target.parent) == []


class TestConcurrency:
    async def test_two_instances_do_not_lose_updates(self, tmp_path: Path) -> None:
        # Separate lockers on the same directory behave like two processes.
        first, second = make_collection(tmp_path), make_collection(tmp_path)
        await first.put(Item(id="counter"))

        async def bump(collection: JsonCollection[Item]) -> None:
            await collection.update(
                "counter", lambda item: item.model_copy(update={"value": item.value + 1})
            )

        await asyncio.gather(*(bump(c) for _ in range(20) for c in (first, second)))
        counter = await first.get("counter")
        assert counter is not None
        assert counter.value == 40

    async def test_concurrent_puts_of_different_items_are_kept(self, tmp_path: Path) -> None:
        collection = make_collection(tmp_path)
        await asyncio.gather(*(collection.put(Item(id=f"i{n}", value=n)) for n in range(30)))
        assert sorted(item.value for item in await collection.all()) == list(range(30))

    def test_two_processes_do_not_lose_updates(self, tmp_path: Path) -> None:
        asyncio.run(make_collection(tmp_path).put(Item(id="counter")))
        ctx = multiprocessing.get_context("spawn")
        workers = [ctx.Process(target=bump_in_process, args=(tmp_path, 15)) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=60)
            assert worker.exitcode == 0
        counter = asyncio.run(make_collection(tmp_path).get("counter"))
        assert counter is not None
        assert counter.value == 30


def bump_in_process(var: Path, times: int) -> None:
    async def run() -> None:
        collection = make_collection(var)
        for _ in range(times):
            await collection.update(
                "counter", lambda item: item.model_copy(update={"value": item.value + 1})
            )

    asyncio.run(run())


class TestFileLocker:
    @pytest.mark.parametrize("name", ["", "../x", "a/b", "a\\b", ".hidden", "x.tmp-1", "a" * 200])
    async def test_rejects_unsafe_names(self, tmp_path: Path, name: str) -> None:
        locker = FileLocker(tmp_path / ".locks")
        with pytest.raises(InvalidNameError):
            async with locker.lock(name):
                pass

    async def test_creates_lock_file(self, tmp_path: Path) -> None:
        locker = FileLocker(tmp_path / ".locks")
        async with locker.lock("agents.json"):
            assert (tmp_path / ".locks" / "agents.json.lock").exists()

    async def test_excludes_other_lockers(self, tmp_path: Path) -> None:
        first = FileLocker(tmp_path, poll_interval_seconds=0.001)
        second = FileLocker(tmp_path, poll_interval_seconds=0.001)
        events: list[str] = []

        async def hold(locker: FileLocker, tag: str) -> None:
            async with locker.lock("x"):
                events.append(f"{tag}-in")
                await asyncio.sleep(0.02)
                events.append(f"{tag}-out")

        await asyncio.gather(hold(first, "a"), hold(second, "b"))
        assert events in (["a-in", "a-out", "b-in", "b-out"], ["b-in", "b-out", "a-in", "a-out"])

    async def test_times_out_when_held_elsewhere(self, tmp_path: Path) -> None:
        locker = FileLocker(tmp_path, timeout_seconds=0.05, poll_interval_seconds=0.01)
        other = FileLock(tmp_path / "x.lock", thread_local=False)
        other.acquire()
        try:
            with pytest.raises(LockTimeoutError, match="'x'"):
                async with locker.lock("x"):
                    pass
        finally:
            other.release()
        async with locker.lock("x"):
            pass

    async def test_cancelled_waiter_does_not_keep_lock(self, tmp_path: Path) -> None:
        locker = FileLocker(tmp_path, poll_interval_seconds=0.001)
        other = FileLock(tmp_path / "x.lock", thread_local=False)
        other.acquire()

        async def wait() -> None:
            async with locker.lock("x"):
                pass

        task = asyncio.create_task(wait())
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        other.release()
        assert other.acquire(timeout=0) is not None
        other.release()

    async def test_lock_is_released_on_error(self, tmp_path: Path) -> None:
        locker = FileLocker(tmp_path, timeout_seconds=0.05)
        with pytest.raises(RuntimeError):
            async with locker.lock("x"):
                raise RuntimeError
        async with locker.lock("x"):
            pass

    async def test_lock_many_takes_locks_in_order(self, tmp_path: Path) -> None:
        locker = FileLocker(tmp_path)
        acquired: list[str] = []
        original = locker.lock

        def spy(name: str) -> Any:
            acquired.append(name)
            return original(name)

        locker.lock = spy  # type: ignore[method-assign]
        async with locker.lock_many(["c", "a", "b", "a"]):
            assert all((tmp_path / f"{n}.lock").exists() for n in "abc")
        assert acquired == ["a", "b", "c"]


class RecordingLocker:
    def __init__(self) -> None:
        self._inner = InMemoryLocker()
        self.names: list[str] = []

    def lock(self, name: str) -> AbstractAsyncContextManager[None]:
        self.names.append(name)
        return self._inner.lock(name)


class TestFileBlobStore:
    @pytest.fixture
    def store(self, tmp_path: Path) -> FileBlobStore:
        return FileBlobStore(tmp_path / "credentials", locker=FileLocker(tmp_path / ".locks"))

    async def test_round_trip(self, store: FileBlobStore, tmp_path: Path) -> None:
        assert await store.read("cred_a.bin") is None
        await store.write("cred_a.bin", b"\x00\x01\x02")
        assert (tmp_path / "credentials" / "cred_a.bin").read_bytes() == b"\x00\x01\x02"
        assert await store.read("cred_a.bin") == b"\x00\x01\x02"
        await store.write("cred_a.bin", b"new")
        assert await store.read("cred_a.bin") == b"new"
        assert await store.delete("cred_a.bin") is True
        assert await store.delete("cred_a.bin") is False
        assert await store.read("cred_a.bin") is None

    async def test_uses_per_blob_lock(self, tmp_path: Path) -> None:
        locker = RecordingLocker()
        store = FileBlobStore(tmp_path / "credentials", locker=locker)
        await store.write("cred_a.bin", b"x")
        await store.read("cred_a.bin")
        await store.delete("cred_a.bin")
        assert locker.names == ["credentials.cred_a.bin"] * 3

    @pytest.mark.parametrize("name", ["", "..", "../escape", "a/b", "a\\b", "c:x", "x.tmp-1"])
    async def test_rejects_unsafe_names(self, store: FileBlobStore, name: str) -> None:
        with pytest.raises(InvalidNameError):
            await store.write(name, b"x")
        with pytest.raises(InvalidNameError):
            await store.read(name)
        with pytest.raises(InvalidNameError):
            await store.delete(name)

    async def test_failed_write_keeps_old_blob(
        self, store: FileBlobStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await store.write("cred_a.bin", b"old")

        def crash(src: object, dst: object) -> None:
            raise OSError("simulated crash")

        monkeypatch.setattr(os, "replace", crash)
        with pytest.raises(OSError, match="simulated crash"):
            await store.write("cred_a.bin", b"new")
        monkeypatch.undo()
        assert await store.read("cred_a.bin") == b"old"
        assert temp_files(tmp_path / "credentials") == []


@pytest.mark.parametrize(
    ("name", "safe"),
    [("agents.json", True), ("cred_01J.bin", True), ("-x", False), ("a b", False)],
)
def test_is_safe_name(name: str, safe: bool) -> None:
    assert is_safe_name(name) is safe
