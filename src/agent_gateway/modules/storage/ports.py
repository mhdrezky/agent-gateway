"""Storage contracts (SPEC §6). Every persistent module goes through these."""

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Protocol

from agent_gateway.common.models import Record


class ItemNotFoundError(LookupError):
    """Raised by ``Collection.update`` when the item does not exist."""


class Collection[R: Record](Protocol):
    """A JSON collection of records keyed by ``id``. Every write is atomic."""

    async def get(self, item_id: str) -> R | None: ...

    async def all(self) -> list[R]: ...

    async def put(self, item: R) -> None:
        """Insert or replace the item with ``item.id``."""
        ...

    async def delete(self, item_id: str) -> bool:
        """Return ``True`` if an item was removed."""
        ...

    async def update(self, item_id: str, fn: Callable[[R], R]) -> R:
        """Read-modify-write under a single lock. ``fn`` must keep the same ``id``."""
        ...


class BlobStore(Protocol):
    """Opaque binary files, e.g. encrypted credential envelopes. Writes are atomic."""

    async def read(self, name: str) -> bytes | None: ...

    async def write(self, name: str, data: bytes) -> None: ...

    async def delete(self, name: str) -> bool: ...


class Locker(Protocol):
    """Named locks that hold across coroutines and across processes (API server vs CLI)."""

    def lock(self, name: str) -> AbstractAsyncContextManager[None]: ...
