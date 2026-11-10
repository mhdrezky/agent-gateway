"""Catalog contracts: where a catalog comes from, what reads it, and who turns it into actions."""

from collections.abc import Iterable
from typing import Protocol

from agent_gateway.modules.action_registry.models import RegisteredAction
from agent_gateway.modules.catalog.models import (
    CatalogActionInfo,
    CatalogSnapshot,
    CatalogState,
    SourceCatalog,
)
from agent_gateway.modules.credentials.models import SecretPayload
from agent_gateway.modules.resources.models import Resource, ResourceType


class SourceUnavailableError(Exception):
    """A source could not read its resource. The message is safe to show an admin."""


class CatalogSource(Protocol):
    """Reads what one resource type offers. Implemented by brokers (they touch the outside)."""

    @property
    def resource_type(self) -> ResourceType: ...

    async def read(self, resource: Resource, credential: SecretPayload | None) -> SourceCatalog:
        """Raise ``SourceUnavailableError`` with a safe message when the resource fails."""
        ...


class CatalogActions(Protocol):
    """Turns the live tools of a snapshot into actions bound to that resource."""

    @property
    def resource_type(self) -> ResourceType: ...

    def actions_for(self, snapshot: CatalogSnapshot) -> list[RegisteredAction]: ...


class DynamicActionRegistry(Protocol):
    def replace_group(self, group: str, actions: Iterable[RegisteredAction]) -> list[str]: ...


class CatalogPort(Protocol):
    """Read interface for the admin API (resources view, plan checks, actions view)."""

    async def snapshot(self, resource_id: str) -> CatalogSnapshot | None: ...

    async def tables(self, resource_id: str) -> list[str] | None:
        """Table names of the last snapshot; ``None`` when the resource was never synced."""
        ...

    async def state(self, resource: Resource) -> CatalogState:
        """``ResourceView.catalog``: when it was synced and whether it needs review."""
        ...

    async def catalog_actions(self) -> list[CatalogActionInfo]:
        """Every action read from a catalog, with its resource and review state."""
        ...
