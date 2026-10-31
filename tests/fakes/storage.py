"""In-memory implementations of the storage contracts."""

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from agent_gateway.common.models import Record
from agent_gateway.modules.storage.ports import ItemNotFoundError


class InMemoryCollection[R: Record]:
    def __init__(self) -> None:
        self._items: dict[str, R] = {}
        self._lock = asyncio.Lock()

    async def get(self, item_id: str) -> R | None:
        return self._items.get(item_id)

    async def all(self) -> list[R]:
        return list(self._items.values())

    async def put(self, item: R) -> None:
        async with self._lock:
            self._items[item.id] = item

    async def delete(self, item_id: str) -> bool:
        async with self._lock:
            return self._items.pop(item_id, None) is not None

    async def update(self, item_id: str, fn: Callable[[R], R]) -> R:
        async with self._lock:
            current = self._items.get(item_id)
            if current is None:
                raise ItemNotFoundError(item_id)
            updated = fn(current)
            if updated.id != item_id:
                raise ValueError("update must not change the item id")
            self._items[item_id] = updated
            return updated


class InMemoryBlobStore:
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    async def read(self, name: str) -> bytes | None:
        return self._blobs.get(name)

    async def write(self, name: str, data: bytes) -> None:
        self._blobs[name] = bytes(data)

    async def delete(self, name: str) -> bool:
        return self._blobs.pop(name, None) is not None


class InMemoryLocker:
    def __init__(self) -> None:
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    @asynccontextmanager
    async def lock(self, name: str) -> AsyncIterator[None]:
        async with self._locks[name]:
            yield
