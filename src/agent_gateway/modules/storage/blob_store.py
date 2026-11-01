"""A ``BlobStore`` of opaque files in one directory, e.g. ``var/credentials/``."""

import asyncio
from pathlib import Path

from agent_gateway.modules.storage.atomic import (
    atomic_write_bytes,
    is_safe_name,
    read_bytes_or_none,
    unlink_durable,
)
from agent_gateway.modules.storage.errors import InvalidNameError
from agent_gateway.modules.storage.ports import Locker


class FileBlobStore:
    """Each blob is ``<directory>/<name>``, written atomically under a per-blob lock.

    Names must be a single safe path component, so a blob can never escape the directory.
    """

    def __init__(self, directory: Path, *, locker: Locker) -> None:
        self._directory = directory
        self._locker = locker

    async def read(self, name: str) -> bytes | None:
        path = self._path(name)
        async with self._locker.lock(self._lock_name(name)):
            return await asyncio.to_thread(read_bytes_or_none, path)

    async def write(self, name: str, data: bytes) -> None:
        path = self._path(name)
        async with self._locker.lock(self._lock_name(name)):
            await asyncio.to_thread(atomic_write_bytes, path, bytes(data))

    async def delete(self, name: str) -> bool:
        path = self._path(name)
        async with self._locker.lock(self._lock_name(name)):
            return await asyncio.to_thread(unlink_durable, path)

    def _path(self, name: str) -> Path:
        if not is_safe_name(name):
            raise InvalidNameError(f"invalid blob name: {name!r}")
        return self._directory / name

    def _lock_name(self, name: str) -> str:
        return f"{self._directory.name}.{name}"
