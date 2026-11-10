"""Catalog snapshots (SPEC §11.6) and the wire shapes of admin contract §7.

A snapshot is what a resource offered at its last sync. One snapshot per resource is
stored, keyed by the resource id; the diff of each sync is computed against it.
"""

from enum import StrEnum
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, Field

from agent_gateway.common.models import Record, StrictModel
from agent_gateway.modules.resources.models import ResourceType

# ---- what a source reads ---------------------------------------------------------------


class CatalogColumn(StrictModel):
    name: str
    type: str
    nullable: bool
    comment: str = ""


class CatalogTable(StrictModel):
    name: str
    comment: str = ""
    columns: tuple[CatalogColumn, ...] = ()


class ToolSpec(StrictModel):
    """One tool as an MCP server lists it."""

    name: str = Field(min_length=1, max_length=256)
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = None


class SourceCatalog(StrictModel):
    """What one read of a resource returned: tables or tools, by resource type."""

    tables: tuple[CatalogTable, ...] | None = None
    tools: tuple[ToolSpec, ...] | None = None


# ---- what is stored --------------------------------------------------------------------


class ToolState(StrEnum):
    ACTIVE = "active"
    # Every call is denied ("catalog review pending") until an admin acknowledges it.
    NEEDS_REVIEW = "needs_review"
    REMOVED = "removed"


class CatalogTool(StrictModel):
    name: str
    action: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    read_only: bool
    destructive: bool
    state: ToolState
    # What an admin last accepted (or what the tool was when first seen). A tool needs
    # review while its schema differs from this, or while it is a write and this was a read.
    accepted_schema_digest: str
    accepted_read_only: bool


class CatalogSnapshot(Record):
    """The catalog of one resource; ``id`` is the resource id."""

    resource_type: ResourceType
    resource_name: str
    snapshot_id: str
    synced_at: AwareDatetime
    tables: tuple[CatalogTable, ...] | None = None
    tools: tuple[CatalogTool, ...] | None = None
    # Tables seen by an earlier sync and gone now. The SQL broker refuses them even
    # while they are still in ``allowed_tables`` (admin contract §7).
    removed_tables: tuple[str, ...] = ()
    # The diff of the sync that wrote this snapshot.
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()

    def table_names(self) -> list[str]:
        return sorted(t.name for t in self.tables or ())

    def live_tools(self) -> list[CatalogTool]:
        return [t for t in self.tools or () if t.state is not ToolState.REMOVED]

    def tool_for(self, action_id: str) -> CatalogTool | None:
        return next((t for t in self.live_tools() if t.action == action_id), None)


# ---- the read interface (CatalogPort) and wire shapes ----------------------------------


class CatalogState(BaseModel):
    """``ResourceView.catalog`` of admin contract §4."""

    synced_at: str | None = None
    snapshot_id: str | None = None
    pending_review: bool = False


class CatalogOut(BaseModel):
    """``Catalog`` of admin contract §7."""

    resource: str
    snapshot_id: str
    synced_at: str
    tables: list[dict[str, Any]] | None = None
    tools: list[dict[str, Any]] | None = None


class SyncOut(BaseModel):
    snapshot_id: str
    synced_at: str
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)


class SyncProblem(StrictModel):
    """A tool that could not become an action; the rest of the sync still counts."""

    code: Literal["action_collision", "action_too_long", "invalid_action_id"]
    tools: tuple[str, ...]
    message: str


class SyncReport(StrictModel):
    """Result of one sync: the stored snapshot, its diff, and tools that were left out."""

    snapshot: CatalogSnapshot
    problems: tuple[SyncProblem, ...] = ()

    def out(self) -> SyncOut:
        snap = self.snapshot
        return SyncOut(
            snapshot_id=snap.snapshot_id,
            synced_at=snap.synced_at.isoformat(),
            added=list(snap.added),
            removed=list(snap.removed),
            changed=list(snap.changed),
        )


class CatalogActionInfo(StrictModel):
    """What ``ActionInfo`` (admin contract §4) needs about an action read from a catalog."""

    action: str
    resource_id: str
    resource_name: str
    tool: str
    state: Literal["active", "needs_review"]
    read_only: bool
    risk: str


def catalog_out(snapshot: CatalogSnapshot) -> CatalogOut:
    tools = (
        None
        if snapshot.tools is None
        else [
            t.model_dump(mode="json", exclude={"accepted_schema_digest", "accepted_read_only"})
            for t in sorted(snapshot.tools, key=lambda t: t.name)
        ]
    )
    tables = (
        None
        if snapshot.tables is None
        else [t.model_dump(mode="json") for t in sorted(snapshot.tables, key=lambda t: t.name)]
    )
    return CatalogOut(
        resource=snapshot.id,
        snapshot_id=snapshot.snapshot_id,
        synced_at=snapshot.synced_at.isoformat(),
        tables=tables,
        tools=tools,
    )
