"""A ``Collection`` stored as one JSON file per collection (SPEC §6.2, §6.3)."""

import asyncio
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agent_gateway.common.clock import Clock, SystemClock
from agent_gateway.common.models import Record
from agent_gateway.modules.storage.atomic import atomic_write_bytes, read_bytes_or_none
from agent_gateway.modules.storage.errors import CorruptCollectionError, SchemaVersionError
from agent_gateway.modules.storage.models import CollectionFile
from agent_gateway.modules.storage.ports import ItemNotFoundError, Locker

type RawDocument = dict[str, Any]
type Migration = Callable[[RawDocument], RawDocument]


class JsonCollection[R: Record]:
    """Records of one model in ``<path>``, wrapped in a ``CollectionFile`` envelope.

    Every operation, reads included, runs under the file's lock: the file is always
    re-read so writes from another process (the CLI) are never missed, and on Windows a
    reader holding the file open would make ``os.replace`` fail.

    ``migrations[v]`` upgrades a raw document from schema version ``v`` to ``v + 1``.
    Older files are migrated in memory on read and written back at the current version
    on the next write. Newer files are refused.
    """

    def __init__(
        self,
        path: Path,
        model: type[R],
        *,
        locker: Locker,
        schema_version: int = 1,
        migrations: Mapping[int, Migration] | None = None,
        clock: Clock | None = None,
    ) -> None:
        if schema_version < 1:
            raise ValueError("schema_version must be >= 1")
        self._path = path
        self._model = model
        self._file_model: type[CollectionFile[R]] = CollectionFile[model]  # type: ignore[valid-type]
        self._locker = locker
        self._schema_version = schema_version
        self._migrations = dict(migrations or {})
        self._clock = clock or SystemClock()

    @property
    def path(self) -> Path:
        return self._path

    async def check(self) -> None:
        """Load and validate the file once; call at startup to fail fast (SPEC §6.2)."""
        async with self._locker.lock(self._path.name):
            await self._load()

    async def get(self, item_id: str) -> R | None:
        async with self._locker.lock(self._path.name):
            return (await self._load()).get(item_id)

    async def all(self) -> list[R]:
        async with self._locker.lock(self._path.name):
            return list((await self._load()).values())

    async def put(self, item: R) -> None:
        async with self._locker.lock(self._path.name):
            items = await self._load()
            items[item.id] = item
            await self._save(items)

    async def delete(self, item_id: str) -> bool:
        async with self._locker.lock(self._path.name):
            items = await self._load()
            if items.pop(item_id, None) is None:
                return False
            await self._save(items)
            return True

    async def update(self, item_id: str, fn: Callable[[R], R]) -> R:
        async with self._locker.lock(self._path.name):
            items = await self._load()
            current = items.get(item_id)
            if current is None:
                raise ItemNotFoundError(item_id)
            updated = fn(current)
            if updated.id != item_id:
                raise ValueError("update must not change the item id")
            items[item_id] = updated
            await self._save(items)
            return updated

    async def _load(self) -> dict[str, R]:
        data = await asyncio.to_thread(read_bytes_or_none, self._path)
        if data is None:
            return {}
        return self._parse(data)

    def _parse(self, data: bytes) -> dict[str, R]:
        name = self._path.name
        try:
            raw = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CorruptCollectionError(f"{name}: not valid JSON") from None
        if not isinstance(raw, dict):
            raise CorruptCollectionError(f"{name}: top level must be an object")
        raw = self._migrate(raw)
        try:
            document = self._file_model.model_validate(raw)
        except ValidationError as exc:
            # Keep record contents out of the message and the exception chain.
            locations = sorted({".".join(map(str, err["loc"])) for err in exc.errors()})
            raise CorruptCollectionError(
                f"{name}: invalid collection file at {', '.join(locations)}"
            ) from None
        for key, item in document.items.items():
            if key != item.id:
                raise CorruptCollectionError(f"{name}: key {key!r} does not match item id")
        return dict(document.items)

    def _migrate(self, raw: RawDocument) -> RawDocument:
        name = self._path.name
        version = raw.get("schema_version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise CorruptCollectionError(f"{name}: missing or invalid schema_version")
        if version > self._schema_version:
            raise SchemaVersionError(
                f"{name}: schema version {version} is newer than supported "
                f"version {self._schema_version}"
            )
        while version < self._schema_version:
            migration = self._migrations.get(version)
            if migration is None:
                raise SchemaVersionError(f"{name}: no migration from schema version {version}")
            raw = migration(raw)
            version += 1
            raw["schema_version"] = version
        return raw

    async def _save(self, items: dict[str, R]) -> None:
        document = self._file_model(
            schema_version=self._schema_version,
            updated_at=self._clock.now(),
            items=items,
        )
        data = document.model_dump_json(indent=2).encode("utf-8")
        await asyncio.to_thread(atomic_write_bytes, self._path, data)
