"""Resource registry (SPEC §8.5). Attributes are validated by the schema each broker registers."""

import asyncio
import re
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ValidationError

from agent_gateway.common.errors import ConflictError, InvalidParamsError, ResourceNotFoundError
from agent_gateway.common.ids import IdPrefix, has_prefix, new_id
from agent_gateway.modules.resources.models import TAG_PATTERN, Resource, ResourceType
from agent_gateway.modules.storage.ports import Collection, ItemNotFoundError

_TAG = re.compile(TAG_PATTERN)


class StoredResourceRegistry:
    """Resources in a collection; ``attributes`` must pass ``schemas[type]``.

    A type without a registered schema cannot be created (default deny). Validated
    attributes are stored in their normalised JSON form, defaults included.
    """

    def __init__(
        self,
        resources: Collection[Resource],
        schemas: Mapping[ResourceType, type[BaseModel]],
    ) -> None:
        self._resources = resources
        self._schemas = dict(schemas)
        # Serialises the name-uniqueness check with the write inside this process.
        self._write_lock = asyncio.Lock()

    async def create(
        self,
        type: ResourceType,
        name: str,
        *,
        tags: Sequence[str] = (),
        attributes: Mapping[str, Any] | None = None,
        credential_id: str | None = None,
    ) -> Resource:
        resource = _resource(
            id=new_id(IdPrefix.RESOURCE),
            type=type,
            name=name,
            tags=_tags(tags),
            attributes=self._attributes(type, attributes or {}),
            credential_id=_credential_id(credential_id),
        )
        async with self._write_lock:
            await self._ensure_name_free(name)
            await self._resources.put(resource)
        return resource

    async def get(self, resource_id: str) -> Resource | None:
        return await self._resources.get(resource_id)

    async def list(self, *, type: ResourceType | None = None) -> list[Resource]:
        resources = await self._resources.all()
        if type is not None:
            resources = [resource for resource in resources if resource.type is type]
        return sorted(resources, key=lambda resource: resource.id)

    async def update(
        self,
        resource_id: str,
        *,
        name: str | None = None,
        tags: Sequence[str] | None = None,
        attributes: Mapping[str, Any] | None = None,
        credential_id: str | None = None,
        detach_credential: bool = False,
    ) -> Resource:
        """Change the given fields; ``None`` leaves a field as it is.

        ``detach_credential`` clears ``credential_id``; passing a new id with it is refused.
        """
        if detach_credential and credential_id is not None:
            raise InvalidParamsError("cannot set and detach a credential at once")
        changes: dict[str, Any] = {}
        if name is not None:
            changes["name"] = name
        if tags is not None:
            changes["tags"] = _tags(tags)
        if detach_credential:
            changes["credential_id"] = None
        elif credential_id is not None:
            changes["credential_id"] = _credential_id(credential_id)

        def apply(resource: Resource) -> Resource:
            update = dict(changes)
            if attributes is not None:
                update["attributes"] = self._attributes(resource.type, attributes)
            return _resource(**{**resource.model_dump(), **update})

        async with self._write_lock:
            if name is not None:
                await self._ensure_name_free(name, except_id=resource_id)
            try:
                return await self._resources.update(resource_id, apply)
            except ItemNotFoundError:
                raise ResourceNotFoundError(f"resource {resource_id} not found") from None

    async def delete(self, resource_id: str) -> bool:
        async with self._write_lock:
            return await self._resources.delete(resource_id)

    def normalized_attributes(
        self, type: ResourceType, attributes: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self._attributes(type, attributes)

    def _attributes(self, type: ResourceType, attributes: Mapping[str, Any]) -> dict[str, Any]:
        schema = self._schemas.get(type)
        if schema is None:
            raise InvalidParamsError(f"no attribute schema is registered for {type.value}")
        try:
            validated = schema.model_validate(dict(attributes))
        except ValidationError as exc:
            raise InvalidParamsError(_describe("attributes", exc)) from None
        return validated.model_dump(mode="json")

    async def _ensure_name_free(self, name: str, *, except_id: str | None = None) -> None:
        for existing in await self._resources.all():
            if existing.name == name and existing.id != except_id:
                raise ConflictError(f"a resource named {name!r} already exists")


def _resource(**fields: Any) -> Resource:
    try:
        return Resource.model_validate(fields)
    except ValidationError as exc:
        raise InvalidParamsError(_describe("resource", exc)) from None


def _tags(tags: Sequence[str]) -> tuple[str, ...]:
    if isinstance(tags, str):
        raise InvalidParamsError("tags must be a sequence of strings, not a string")
    for tag in tags:
        if not isinstance(tag, str) or _TAG.fullmatch(tag) is None:
            raise InvalidParamsError(f"invalid tag {tag!r}; expected 'key:value'")
    return tuple(dict.fromkeys(tags))


def _credential_id(credential_id: str | None) -> str | None:
    if credential_id is not None and not has_prefix(credential_id, IdPrefix.CREDENTIAL):
        raise InvalidParamsError("credential_id must be a credential id (cred_...)")
    return credential_id


def _describe(what: str, exc: ValidationError) -> str:
    # Field locations only: attribute values are never echoed back.
    fields = sorted({".".join(map(str, err["loc"])) or "(root)" for err in exc.errors()})
    return f"invalid {what} fields: {', '.join(fields)}"
