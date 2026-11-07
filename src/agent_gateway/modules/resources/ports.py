"""Resource registry contract."""

from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from agent_gateway.modules.resources.models import Resource, ResourceType


class ResourceRegistry(Protocol):
    async def create(
        self,
        type: ResourceType,
        name: str,
        *,
        tags: Sequence[str] = (),
        attributes: Mapping[str, Any] | None = None,
        credential_id: str | None = None,
    ) -> Resource:
        """Validate ``attributes`` against the schema registered for ``type``."""
        ...

    async def get(self, resource_id: str) -> Resource | None: ...

    async def list(self, *, type: ResourceType | None = None) -> list[Resource]: ...

    async def update(
        self,
        resource_id: str,
        *,
        name: str | None = None,
        tags: Sequence[str] | None = None,
        attributes: Mapping[str, Any] | None = None,
        credential_id: str | None = None,
        detach_credential: bool = False,
    ) -> Resource: ...

    def normalized_attributes(
        self, type: ResourceType, attributes: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Validate ``attributes`` and return the stored form, defaults included."""
        ...

    async def delete(self, resource_id: str) -> bool: ...
