"""File-based execution store: ``<directory>/<yyyy-mm>/exe_<id>.json`` (SPEC §6.1).

The month folder comes from the ULID timestamp inside the id, so a lookup by id never
scans. Ids sort by creation time, which makes "newest first" a reverse name sort.
"""

import asyncio
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path

from ulid import ULID

from agent_gateway.common.errors import ExecutionNotFoundError
from agent_gateway.common.ids import IdPrefix, has_prefix
from agent_gateway.modules.execution.models import Execution
from agent_gateway.modules.storage.atomic import atomic_write_bytes, read_bytes_or_none
from agent_gateway.modules.storage.ports import Locker

_SUFFIX = ".json"
# One lock for all executions: writes are rare and short, and per-id lock files would pile up.
LOCK_NAME = "executions"


def _month(execution_id: str) -> str:
    return ULID.from_str(execution_id.partition("_")[2]).datetime.strftime("%Y-%m")


class FileExecutionStore:
    def __init__(self, directory: Path, *, locker: Locker) -> None:
        self._dir = directory
        self._locker = locker

    def _path(self, execution_id: str) -> Path:
        return self._dir / _month(execution_id) / f"{execution_id}{_SUFFIX}"

    async def get(self, execution_id: str) -> Execution | None:
        if not has_prefix(execution_id, IdPrefix.EXECUTION):
            return None
        return await asyncio.to_thread(self._read, self._path(execution_id))

    async def put(self, execution: Execution) -> None:
        async with self._locker.lock(LOCK_NAME):
            await asyncio.to_thread(self._write, execution)

    async def update(self, execution_id: str, fn: Callable[[Execution], Execution]) -> Execution:
        if not has_prefix(execution_id, IdPrefix.EXECUTION):
            raise ExecutionNotFoundError(f"execution {execution_id} not found")
        async with self._locker.lock(LOCK_NAME):
            current = await asyncio.to_thread(self._read, self._path(execution_id))
            if current is None:
                raise ExecutionNotFoundError(f"execution {execution_id} not found")
            updated = fn(current)
            if updated.id != execution_id:
                raise ValueError("update must not change the execution id")
            await asyncio.to_thread(self._write, updated)
            return updated

    async def recent(self, *, since: datetime) -> list[Execution]:
        floor = since.strftime("%Y-%m")
        return await asyncio.to_thread(
            lambda: [e for e in self._scan(min_month=floor) if e.created_at >= since]
        )

    async def page(
        self,
        *,
        agent_id: str | None,
        before: str | None,
        limit: int,
        user_subject: str | None = None,
    ) -> list[Execution]:
        def collect() -> list[Execution]:
            items: list[Execution] = []
            for execution in self._scan(before=before):
                if (agent_id is None or execution.agent_id == agent_id) and (
                    user_subject is None or execution.user_subject == user_subject
                ):
                    items.append(execution)
                    if len(items) >= limit:
                        break
            return items

        return await asyncio.to_thread(collect)

    def _scan(self, *, min_month: str = "", before: str | None = None) -> Iterator[Execution]:
        if not self._dir.is_dir():
            return
        months = sorted((p for p in self._dir.iterdir() if p.is_dir()), reverse=True)
        for month in months:
            if month.name < min_month:
                break
            for path in sorted(month.glob(f"exe_*{_SUFFIX}"), reverse=True):
                if before is not None and path.stem >= before:
                    continue
                execution = self._read(path)
                if execution is not None:
                    yield execution

    @staticmethod
    def _read(path: Path) -> Execution | None:
        data = read_bytes_or_none(path)
        return None if data is None else Execution.model_validate_json(data)

    def _write(self, execution: Execution) -> None:
        path = self._path(execution.id)
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(path, execution.model_dump_json().encode("utf-8"))
