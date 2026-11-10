"""Merge a fresh read into the previous snapshot (admin contract §7). Pure functions.

Tables: ``added``/``removed``/``changed`` by name. A table that disappears is remembered in
``removed_tables`` until it comes back, so the SQL broker keeps refusing it.

Tools: each tool is compared with what an admin last accepted. A changed input schema, or
a read that became a write, puts the tool in ``needs_review``; going back to the accepted
shape clears it. New tools are ``active`` (and granted to nobody). Tools that disappear
stay in the snapshot as ``removed``, with what was accepted, so a tool that comes back
changed is still caught.
"""

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field

from agent_gateway.modules.catalog.models import (
    CatalogSnapshot,
    CatalogTable,
    CatalogTool,
    SyncProblem,
    ToolSpec,
    ToolState,
)
from agent_gateway.modules.catalog.rules import (
    ActionIdTooLongError,
    mcp_action_id,
    schema_digest,
    tool_is_destructive,
    tool_is_read_only,
)


@dataclass
class Merged[T]:
    items: list[T]
    added: list[str] = field(default_factory=list[str])
    removed: list[str] = field(default_factory=list[str])
    changed: list[str] = field(default_factory=list[str])


@dataclass
class MergedTables(Merged[CatalogTable]):
    removed_tables: list[str] = field(default_factory=list[str])


@dataclass
class MergedTools(Merged[CatalogTool]):
    problems: list[SyncProblem] = field(default_factory=list[SyncProblem])


def merge_tables(previous: CatalogSnapshot | None, tables: Sequence[CatalogTable]) -> MergedTables:
    before = {t.name: t for t in (previous.tables or () if previous is not None else ())}
    now = {t.name: t for t in tables}
    merged = MergedTables(items=sorted(now.values(), key=lambda t: t.name))
    merged.added = sorted(now.keys() - before.keys())
    merged.removed = sorted(before.keys() - now.keys())
    merged.changed = sorted(n for n in now.keys() & before.keys() if now[n] != before[n])
    earlier_removed = set(previous.removed_tables) if previous is not None else set[str]()
    merged.removed_tables = sorted((earlier_removed | set(merged.removed)) - now.keys())
    return merged


def _action_ids(
    resource_name: str, specs: Sequence[ToolSpec]
) -> tuple[dict[str, str], list[SyncProblem]]:
    """Tool name → action id for every tool that may become an action, plus the problems."""
    by_action: defaultdict[str, list[str]] = defaultdict(list)
    too_long: list[str] = []
    for spec in specs:
        try:
            action = mcp_action_id(resource_name, spec.name)
        except ActionIdTooLongError:
            too_long.append(spec.name)
            continue
        by_action[action].append(spec.name)

    problems: list[SyncProblem] = []
    ids: dict[str, str] = {}
    for action, names in sorted(by_action.items()):
        if len(names) > 1:
            problems.append(
                SyncProblem(
                    code="action_collision",
                    tools=tuple(sorted(names)),
                    message=f"tools {', '.join(sorted(names))} all become action '{action}'; "
                    "none of them was added",
                )
            )
            continue
        ids[names[0]] = action
    if too_long:
        problems.append(
            SyncProblem(
                code="action_too_long",
                tools=tuple(sorted(too_long)),
                message=f"the action id of {', '.join(sorted(too_long))} would be longer "
                "than 64 characters as a tool name; not added",
            )
        )
    return ids, problems


def merge_tools(
    previous: CatalogSnapshot | None, resource_name: str, specs: Sequence[ToolSpec]
) -> MergedTools:
    ids, problems = _action_ids(resource_name, specs)
    before = {t.name: t for t in (previous.tools or () if previous is not None else ())}
    merged = MergedTools(items=[], problems=problems)

    for spec in sorted(specs, key=lambda s: s.name):
        action = ids.get(spec.name)
        if action is None:
            continue
        read_only = tool_is_read_only(spec.annotations)
        destructive = tool_is_destructive(spec.annotations)
        digest = schema_digest(spec.input_schema)
        old = before.get(spec.name)
        if old is None:
            accepted_digest, accepted_read_only = digest, read_only
            merged.added.append(spec.name)
        else:
            accepted_digest, accepted_read_only = old.accepted_schema_digest, old.accepted_read_only
            if old.state is ToolState.REMOVED:
                merged.added.append(spec.name)
            elif (
                old.input_schema != spec.input_schema
                or old.read_only != read_only
                or old.destructive != destructive
                or old.description != spec.description
                or old.action != action
            ):
                merged.changed.append(spec.name)
        review = digest != accepted_digest or (accepted_read_only and not read_only)
        merged.items.append(
            CatalogTool(
                name=spec.name,
                action=action,
                description=spec.description,
                input_schema=spec.input_schema,
                read_only=read_only,
                destructive=destructive,
                state=ToolState.NEEDS_REVIEW if review else ToolState.ACTIVE,
                accepted_schema_digest=accepted_digest,
                accepted_read_only=accepted_read_only,
            )
        )

    present = {t.name for t in merged.items}
    for name, old in sorted(before.items()):
        if name in present:
            continue
        if old.state is not ToolState.REMOVED:
            merged.removed.append(name)
        merged.items.append(old.model_copy(update={"state": ToolState.REMOVED}))
    merged.items.sort(key=lambda t: t.name)
    return merged


def acknowledge_tools(tools: Sequence[CatalogTool], names: Sequence[str]) -> list[CatalogTool]:
    """Accept the current shape of every named tool. Raises ``KeyError`` with the first
    name that is unknown or not ``needs_review``; then nothing is changed."""
    by_name = {t.name: t for t in tools}
    for name in names:
        tool = by_name.get(name)
        if tool is None or tool.state is not ToolState.NEEDS_REVIEW:
            raise KeyError(name)
    wanted = set(names)
    return [
        t.model_copy(
            update={
                "state": ToolState.ACTIVE,
                "accepted_schema_digest": schema_digest(t.input_schema),
                "accepted_read_only": t.read_only,
            }
        )
        if t.name in wanted
        else t
        for t in tools
    ]
