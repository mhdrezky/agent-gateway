"""Named locks that hold within the process and across processes (SPEC §6.4)."""

import asyncio
import time
from collections.abc import AsyncIterator, Iterable
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

from filelock import FileLock, Timeout

from agent_gateway.modules.storage.atomic import is_safe_name
from agent_gateway.modules.storage.errors import InvalidNameError, LockTimeoutError

DEFAULT_TIMEOUT_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.01


class FileLocker:
    """``asyncio.Lock`` per name, plus a ``filelock`` at ``<lock_dir>/<name>.lock``.

    The file lock is polled without blocking, so waiting never ties up a thread and a
    cancelled waiter cannot leave the lock held.
    """

    def __init__(
        self,
        lock_dir: Path,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        poll_interval_seconds: float = POLL_INTERVAL_SECONDS,
    ) -> None:
        self._lock_dir = lock_dir
        self._timeout = timeout_seconds
        self._poll = poll_interval_seconds
        self._locks: dict[str, tuple[asyncio.Lock, FileLock]] = {}

    @asynccontextmanager
    async def lock(self, name: str) -> AsyncIterator[None]:
        local, file_lock = self._get(name)
        async with local:
            await self._acquire_file_lock(name, file_lock)
            try:
                yield
            finally:
                file_lock.release()

    @asynccontextmanager
    async def lock_many(self, names: Iterable[str]) -> AsyncIterator[None]:
        """Hold several locks, always taken in alphabetical order to avoid deadlock."""
        async with AsyncExitStack() as stack:
            for name in sorted(set(names)):
                await stack.enter_async_context(self.lock(name))
            yield

    def _get(self, name: str) -> tuple[asyncio.Lock, FileLock]:
        if not is_safe_name(name):
            raise InvalidNameError(f"invalid lock name: {name!r}")
        entry = self._locks.get(name)
        if entry is None:
            self._lock_dir.mkdir(parents=True, exist_ok=True)
            file_lock = FileLock(self._lock_dir / f"{name}.lock", thread_local=False)
            entry = (asyncio.Lock(), file_lock)
            self._locks[name] = entry
        return entry

    async def _acquire_file_lock(self, name: str, file_lock: FileLock) -> None:
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                file_lock.acquire(timeout=0)
                return
            except Timeout:
                if time.monotonic() >= deadline:
                    raise LockTimeoutError(f"timed out waiting for lock {name!r}") from None
                await asyncio.sleep(self._poll)
