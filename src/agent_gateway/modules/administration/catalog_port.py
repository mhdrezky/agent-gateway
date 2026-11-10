"""What the admin API needs from resource catalogs (SPEC §23, contract §7).

The catalog itself (sync, snapshots, MCP tools) lives elsewhere; the admin API only reads
through this port. ``NullCatalog`` is the default until a real catalog is wired in
``runtime``: it knows no snapshot, so nothing is pending review and table checks are skipped.
"""

from dataclasses import dataclass
from typing import Literal, Protocol

from agent_gateway.modules.resources.models import Resource

CatalogActionState = Literal["active", "needs_review"]


@dataclass(frozen=True, slots=True, kw_only=True)
class CatalogSummary:
    """The last snapshot of one resource; all ``None`` when it was never synced."""

    snapshot_id: str | None = None
    synced_at: str | None = None
    pending_review: bool = False


class CatalogPort(Protocol):
    async def summary(self, resource: Resource) -> CatalogSummary:
        """The state of ``resource``'s last snapshot."""
        ...

    async def tables(self, resource: Resource) -> frozenset[str] | None:
        """Table names of the last snapshot of a ``sql_database`` resource, or ``None`` when
        there is no snapshot (plans then skip ``table_not_in_catalog``)."""
        ...

    async def action_state(self, action_id: str) -> CatalogActionState:
        """``needs_review`` while a catalog change to this action waits for an admin."""
        ...

    async def action_resource(self, action_id: str) -> str | None:
        """The resource name an action belongs to (MCP actions only), else ``None``."""
        ...


class NullCatalog:
    """No catalogs: every resource unsynced, every action active."""

    async def summary(self, resource: Resource) -> CatalogSummary:
        return CatalogSummary()

    async def tables(self, resource: Resource) -> frozenset[str] | None:
        return None

    async def action_state(self, action_id: str) -> CatalogActionState:
        return "active"

    async def action_resource(self, action_id: str) -> str | None:
        return None
