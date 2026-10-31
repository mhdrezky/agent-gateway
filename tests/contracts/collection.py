"""Reusable contract tests for ``Collection``.

Any implementation (the in-memory fake, the real JSON collection) subclasses
``CollectionContract`` and provides the ``collection`` fixture.
"""

import asyncio

import pytest

from agent_gateway.common.models import Record
from agent_gateway.modules.storage.ports import Collection, ItemNotFoundError


class Item(Record):
    value: int = 0


class CollectionContract:
    async def test_get_missing_returns_none(self, collection: Collection[Item]) -> None:
        assert await collection.get("nope") is None

    async def test_put_then_get(self, collection: Collection[Item]) -> None:
        await collection.put(Item(id="a", value=1))
        assert await collection.get("a") == Item(id="a", value=1)

    async def test_put_replaces(self, collection: Collection[Item]) -> None:
        await collection.put(Item(id="a", value=1))
        await collection.put(Item(id="a", value=2))
        assert await collection.all() == [Item(id="a", value=2)]

    async def test_delete(self, collection: Collection[Item]) -> None:
        await collection.put(Item(id="a"))
        assert await collection.delete("a") is True
        assert await collection.delete("a") is False
        assert await collection.get("a") is None

    async def test_update_missing_raises(self, collection: Collection[Item]) -> None:
        with pytest.raises(ItemNotFoundError):
            await collection.update("nope", lambda item: item)

    async def test_update_cannot_change_id(self, collection: Collection[Item]) -> None:
        await collection.put(Item(id="a"))
        with pytest.raises(ValueError, match="id"):
            await collection.update("a", lambda item: item.model_copy(update={"id": "b"}))
        assert await collection.get("a") == Item(id="a")

    async def test_concurrent_updates_are_not_lost(self, collection: Collection[Item]) -> None:
        await collection.put(Item(id="counter", value=0))

        async def bump() -> None:
            await collection.update(
                "counter", lambda item: item.model_copy(update={"value": item.value + 1})
            )

        await asyncio.gather(*(bump() for _ in range(50)))
        counter = await collection.get("counter")
        assert counter is not None
        assert counter.value == 50
