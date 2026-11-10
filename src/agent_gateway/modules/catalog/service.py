"""Catalog sync, review, and the read interface (SPEC §11.6, admin contract §7).

Sync never grants anything: it only records what a resource offers. Actions read from a
catalog (MCP tools) are registered from the stored snapshot, at startup and after each
sync, and the server re-reads snapshots on its dispatch tick so a sync from the CLI (another
process) is picked up too.
"""

import asyncio
import logging
from collections.abc import Mapping, Sequence

from ulid import ULID

from agent_gateway.common.clock import Clock, to_rfc3339
from agent_gateway.common.errors import ResourceNotFoundError
from agent_gateway.modules.action_registry.models import ActionDefinition
from agent_gateway.modules.audit.models import Actor, AuditEventType, AuditRecord
from agent_gateway.modules.audit.ports import AuditLog
from agent_gateway.modules.catalog.diff import acknowledge_tools, merge_tables, merge_tools
from agent_gateway.modules.catalog.errors import (
    CatalogNotFoundError,
    CatalogNotSupportedError,
    NotPendingReviewError,
    SyncFailedError,
)
from agent_gateway.modules.catalog.models import (
    CatalogActionInfo,
    CatalogSnapshot,
    CatalogState,
    SourceCatalog,
    SyncReport,
    ToolState,
)
from agent_gateway.modules.catalog.ports import (
    CatalogActions,
    CatalogSource,
    DynamicActionRegistry,
    SourceUnavailableError,
)
from agent_gateway.modules.catalog.rules import tool_risk
from agent_gateway.modules.credentials.models import SecretPayload
from agent_gateway.modules.credentials.ports import CredentialStore
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.modules.resources.ports import ResourceRegistry
from agent_gateway.modules.storage.ports import Collection, ItemNotFoundError

# A sync waits at most this long for the resource; the source's own timeouts are shorter.
SYNC_TIMEOUT_SECONDS = 60
REVIEW_PENDING = "catalog review pending"
NOT_THIS_RESOURCE = "action belongs to another resource"
NOT_IN_CATALOG = "action is no longer in the resource's catalog"
UNREADABLE = "could not read the resource"
GROUP_PREFIX = "catalog:"


def new_snapshot_id() -> str:
    return f"snap_{ULID()}"


class CatalogService:
    def __init__(
        self,
        *,
        snapshots: Collection[CatalogSnapshot],
        resources: ResourceRegistry,
        credentials: CredentialStore,
        sources: Sequence[CatalogSource],
        actions: Sequence[CatalogActions],
        registry: DynamicActionRegistry,
        audit: AuditLog,
        clock: Clock,
        logger: logging.Logger | None = None,
    ) -> None:
        self._snapshots = snapshots
        self._resources = resources
        self._credentials = credentials
        self._sources: Mapping[ResourceType, CatalogSource] = {s.resource_type: s for s in sources}
        self._actions: Mapping[ResourceType, CatalogActions] = {a.resource_type: a for a in actions}
        self._registry = registry
        self._audit = audit
        self._clock = clock
        self._log = logger or logging.getLogger("agent_gateway.catalog")
        self._write_lock = asyncio.Lock()
        # resource id → snapshot id whose actions are registered now.
        self._loaded: dict[str, str] = {}

    def supports(self, type: ResourceType) -> bool:
        return type in self._sources

    # ---- sync ---------------------------------------------------------------------------

    async def sync(
        self, actor: Actor, resource_id: str, *, context: Mapping[str, object] | None = None
    ) -> SyncReport:
        """Read the resource, store the new snapshot, and register its actions.

        Tools that cannot become actions are left out and listed in ``problems``; the rest
        of the sync still counts. A resource that cannot be read raises ``SyncFailedError``
        and the last snapshot stays.
        """
        resource = await self._resource(resource_id)
        source = self._sources.get(resource.type)
        if source is None:
            raise CatalogNotSupportedError(
                f"resources of type {resource.type.value} have no catalog on this gateway"
            )
        try:
            found = await self._read(source, resource)
        except SyncFailedError as exc:
            await self._record(
                AuditEventType.CATALOG_SYNC_FAILED,
                actor,
                resource,
                {**(context or {}), "error": exc.message},
            )
            raise

        async with self._write_lock:
            previous = await self._snapshots.get(resource.id)
            tables = merge_tables(previous, found.tables) if found.tables is not None else None
            tools = (
                merge_tools(previous, resource.name, found.tools)
                if found.tools is not None
                else None
            )
            merged = tables or tools
            snapshot = CatalogSnapshot(
                id=resource.id,
                resource_type=resource.type,
                resource_name=resource.name,
                snapshot_id=new_snapshot_id(),
                synced_at=self._clock.now(),
                tables=tuple(tables.items) if tables is not None else None,
                tools=tuple(tools.items) if tools is not None else None,
                removed_tables=tuple(tables.removed_tables) if tables is not None else (),
                added=tuple(merged.added) if merged else (),
                removed=tuple(merged.removed) if merged else (),
                changed=tuple(merged.changed) if merged else (),
            )
            await self._snapshots.put(snapshot)
        report = SyncReport(snapshot=snapshot, problems=tuple(tools.problems) if tools else ())
        await self._record(
            AuditEventType.CATALOG_SYNCED,
            actor,
            resource,
            {
                **(context or {}),
                "snapshot_id": snapshot.snapshot_id,
                "added": list(snapshot.added),
                "removed": list(snapshot.removed),
                "changed": list(snapshot.changed),
                "problems": [p.model_dump(mode="json") for p in report.problems],
            },
        )
        self._register(snapshot)
        return report

    async def _read(self, source: CatalogSource, resource: Resource) -> SourceCatalog:
        credential: SecretPayload | None = None
        try:
            if resource.credential_id is not None:
                credential = await self._credentials.open(resource.credential_id)
            async with asyncio.timeout(SYNC_TIMEOUT_SECONDS):
                read = await source.read(resource, credential)
        except SourceUnavailableError as exc:
            raise SyncFailedError(str(exc) or UNREADABLE) from None
        except TimeoutError:
            raise SyncFailedError("the resource did not answer in time") from None
        except Exception:
            self._log.exception("catalog sync of %s failed", resource.id)
            raise SyncFailedError(UNREADABLE) from None
        finally:
            if credential is not None:
                credential.wipe()
        return read

    # ---- review -------------------------------------------------------------------------

    async def acknowledge(
        self,
        actor: Actor,
        resource_id: str,
        tools: Sequence[str],
        *,
        context: Mapping[str, object] | None = None,
    ) -> CatalogSnapshot:
        """Accept the current shape of tools in ``needs_review``; all of them or none."""
        resource = await self._resource(resource_id)

        def apply(snapshot: CatalogSnapshot) -> CatalogSnapshot:
            try:
                updated = acknowledge_tools(snapshot.tools or (), tools)
            except KeyError as exc:
                raise NotPendingReviewError(f"'{exc.args[0]}' is not pending review") from None
            return snapshot.model_copy(update={"tools": tuple(updated)})

        async with self._write_lock:
            try:
                snapshot = await self._snapshots.update(resource.id, apply)
            except ItemNotFoundError:
                raise NotPendingReviewError(f"'{tools[0]}' is not pending review") from None
        await self._record(
            AuditEventType.CATALOG_ACKNOWLEDGED,
            actor,
            resource,
            {
                **(context or {}),
                "snapshot_id": snapshot.snapshot_id,
                "tools": sorted(set(tools)),
            },
        )
        return snapshot

    # ---- read interface (CatalogPort) ----------------------------------------------------

    async def snapshot(self, resource_id: str) -> CatalogSnapshot | None:
        return await self._snapshots.get(resource_id)

    async def catalog(self, resource_id: str) -> CatalogSnapshot:
        """The last snapshot of an existing resource; ``CatalogNotFoundError`` if never synced."""
        resource = await self._resource(resource_id)
        snapshot = await self._snapshots.get(resource.id)
        if snapshot is None:
            raise CatalogNotFoundError(f"resource {resource.id} has not been synced")
        return snapshot

    async def tables(self, resource_id: str) -> list[str] | None:
        snapshot = await self._snapshots.get(resource_id)
        if snapshot is None or snapshot.tables is None:
            return None
        return snapshot.table_names()

    async def state(self, resource: Resource) -> CatalogState:
        snapshot = await self._snapshots.get(resource.id)
        if snapshot is None:
            return CatalogState()
        return CatalogState(
            synced_at=to_rfc3339(snapshot.synced_at),
            snapshot_id=snapshot.snapshot_id,
            pending_review=_pending_review(resource, snapshot),
        )

    async def catalog_actions(self) -> list[CatalogActionInfo]:
        infos: list[CatalogActionInfo] = []
        for snapshot in await self._snapshots.all():
            for tool in snapshot.live_tools():
                infos.append(
                    CatalogActionInfo(
                        action=tool.action,
                        resource_id=snapshot.id,
                        resource_name=snapshot.resource_name,
                        tool=tool.name,
                        state="needs_review" if tool.state is ToolState.NEEDS_REVIEW else "active",
                        read_only=tool.read_only,
                        risk=tool_risk(read_only=tool.read_only, destructive=tool.destructive),
                    )
                )
        return sorted(infos, key=lambda i: i.action)

    async def removed_tables(self, resource_id: str) -> frozenset[str]:
        """Tables the last syncs saw disappear; the SQL broker refuses them."""
        snapshot = await self._snapshots.get(resource_id)
        return frozenset(snapshot.removed_tables) if snapshot is not None else frozenset()

    # ---- the engine's guard ------------------------------------------------------------

    async def refusal(self, action: ActionDefinition, resource: Resource) -> str | None:
        """Why a call of a catalog action must be denied now, or ``None``.

        Read from the stored snapshot on every call, so an acknowledgement or a sync made
        by another process counts at once.
        """
        if action.bound_resource is None:
            return None
        if action.bound_resource != resource.id:
            return NOT_THIS_RESOURCE
        snapshot = await self._snapshots.get(resource.id)
        tool = snapshot.tool_for(action.id) if snapshot is not None else None
        if tool is None:
            return NOT_IN_CATALOG
        if tool.state is ToolState.NEEDS_REVIEW:
            return REVIEW_PENDING
        return None

    # ---- registering actions --------------------------------------------------------------

    async def load_actions(self) -> None:
        """Register the actions of every stored snapshot whose resource still exists.

        Cheap when nothing changed: a snapshot is re-registered only when its id changed.
        """
        snapshots = {s.id: s for s in await self._snapshots.all()}
        existing = {r.id for r in await self._resources.list()}
        for resource_id in list(self._loaded):
            if resource_id not in snapshots or resource_id not in existing:
                self._registry.replace_group(GROUP_PREFIX + resource_id, [])
                del self._loaded[resource_id]
        for resource_id, snapshot in snapshots.items():
            if resource_id in existing and self._loaded.get(resource_id) != snapshot.snapshot_id:
                self._register(snapshot)

    def _register(self, snapshot: CatalogSnapshot) -> None:
        provider = self._actions.get(snapshot.resource_type)
        if provider is None:
            return
        skipped = self._registry.replace_group(
            GROUP_PREFIX + snapshot.id, provider.actions_for(snapshot)
        )
        for action_id in skipped:
            self._log.warning(
                "catalog of %s: action %s already exists elsewhere; not registered",
                snapshot.id,
                action_id,
            )
        self._loaded[snapshot.id] = snapshot.snapshot_id

    async def resolve(self, ref: str) -> Resource:
        """The resource with this id, else the one with this name."""
        resource = await self._resources.get(ref)
        if resource is None:
            resource = next((r for r in await self._resources.list() if r.name == ref), None)
        if resource is None:
            raise ResourceNotFoundError(f"resource {ref} not found")
        return resource

    # ---- helpers ------------------------------------------------------------------------

    async def _resource(self, resource_id: str) -> Resource:
        resource = await self._resources.get(resource_id)
        if resource is None:
            raise ResourceNotFoundError(f"resource {resource_id} not found")
        return resource

    async def _record(
        self, event: AuditEventType, actor: Actor, resource: Resource, details: dict[str, object]
    ) -> None:
        await self._audit.append(
            AuditRecord(event=event, actor=actor, resource_id=resource.id, details=details)
        )


def _pending_review(resource: Resource, snapshot: CatalogSnapshot) -> bool:
    if snapshot.tools is not None and any(
        t.state is ToolState.NEEDS_REVIEW for t in snapshot.tools
    ):
        return True
    allowed = resource.attributes.get("allowed_tables") or []
    return bool(set(allowed) & set(snapshot.removed_tables))
