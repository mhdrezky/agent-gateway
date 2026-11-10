"""Catalog rules (admin contract §7, §7.1) and the merge of a sync into the last snapshot."""

from datetime import UTC, datetime
from typing import Any

import pytest

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.modules.action_registry.models import (
    ActionDefinition,
    RegisteredAction,
    RiskLevel,
)
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.modules.catalog.diff import acknowledge_tools, merge_tables, merge_tools
from agent_gateway.modules.catalog.models import (
    CatalogColumn,
    CatalogSnapshot,
    CatalogTable,
    ToolSpec,
    ToolState,
    catalog_out,
)
from agent_gateway.modules.catalog.rules import (
    ActionIdError,
    ActionIdTooLongError,
    mcp_action_id,
    schema_digest,
    tool_is_destructive,
    tool_is_read_only,
    tool_risk,
)
from agent_gateway.modules.resources.models import ResourceType
from tests.world import NoParams

NOW = datetime(2026, 11, 10, 9, 0, tzinfo=UTC)
SCHEMA = {"type": "object", "properties": {"q": {"type": "string"}}}
READ: dict[str, Any] = {"readOnlyHint": True}
WRITE: dict[str, Any] = {"readOnlyHint": False, "destructiveHint": False}

# ---- §7.1 action ids -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("resource", "tool", "expected"),
    [
        ("tickets", "search", "mcp.tickets.search"),
        ("Ticket-Desk", "Create Ticket!", "mcp.ticket_desk.create_ticket_"),
        ("tickets", "3d_render", "mcp.tickets.t_3d_render"),
        ("2fa", "get", "mcp.t_2fa.get"),
        ("tickets", "über", "mcp.tickets.t__ber"),
        ("tickets", "_private", "mcp.tickets.t__private"),
        ("tickets", "2fa-reset", "mcp.tickets.t_2fa_reset"),
        ("_ops", "get", "mcp.t__ops.get"),
    ],
)
def test_action_ids_follow_the_contract(resource: str, tool: str, expected: str) -> None:
    assert mcp_action_id(resource, tool) == expected


def test_action_id_must_fit_a_64_character_tool_name() -> None:
    # "mcp_" + "r_" + tool: 64 characters exactly is fine, 65 is not.
    assert mcp_action_id("r", "t" * 58).replace(".", "_") == "mcp_r_" + "t" * 58
    with pytest.raises(ActionIdTooLongError):
        mcp_action_id("r", "t" * 59)
    with pytest.raises(ActionIdError):
        mcp_action_id("r", "")


@pytest.mark.parametrize(
    ("annotations", "read_only", "destructive", "risk"),
    [
        (None, False, True, RiskLevel.HIGH),
        ({}, False, True, RiskLevel.HIGH),
        ({"readOnlyHint": True}, True, False, RiskLevel.LOW),
        ({"readOnlyHint": "true"}, False, True, RiskLevel.HIGH),
        ({"readOnlyHint": False, "destructiveHint": False}, False, False, RiskLevel.MEDIUM),
        ({"destructiveHint": True}, False, True, RiskLevel.HIGH),
        ({"readOnlyHint": True, "destructiveHint": True}, True, False, RiskLevel.LOW),
    ],
)
def test_risk_comes_from_the_annotations(
    annotations: dict[str, Any] | None, read_only: bool, destructive: bool, risk: RiskLevel
) -> None:
    assert tool_is_read_only(annotations) is read_only
    assert tool_is_destructive(annotations) is destructive
    assert tool_risk(read_only=read_only, destructive=destructive) is risk


def test_schema_digest_ignores_key_order() -> None:
    assert schema_digest({"a": 1, "b": {"c": 2, "d": 3}}) == schema_digest(
        {"b": {"d": 3, "c": 2}, "a": 1}
    )
    assert schema_digest({"a": 1}) != schema_digest({"a": 2})


# ---- tables -------------------------------------------------------------------------------


def _table(name: str, *columns: str) -> CatalogTable:
    return CatalogTable(
        name=name,
        columns=tuple(CatalogColumn(name=c, type="text", nullable=True) for c in columns),
    )


def _snapshot(**fields: Any) -> CatalogSnapshot:
    base: dict[str, Any] = {
        "id": "res_x",
        "resource_type": ResourceType.SQL_DATABASE,
        "resource_name": "sample",
        "snapshot_id": "snap_1",
        "synced_at": NOW,
    }
    return CatalogSnapshot(**{**base, **fields})


def test_first_table_sync_adds_everything() -> None:
    merged = merge_tables(None, [_table("product", "id"), _table("customer", "id")])
    assert merged.added == ["customer", "product"]
    assert merged.removed == merged.changed == merged.removed_tables == []


def test_removed_tables_are_remembered_until_they_come_back() -> None:
    first = _snapshot(tables=(_table("product", "id"), _table("customer", "id")))
    merged = merge_tables(first, [_table("product", "id", "sku")])
    assert merged.removed == ["customer"]
    assert merged.changed == ["product"]
    assert merged.removed_tables == ["customer"]

    second = _snapshot(tables=tuple(merged.items), removed_tables=("customer",))
    again = merge_tables(second, [_table("product", "id", "sku")])
    assert again.removed == []  # already gone last time
    assert again.removed_tables == ["customer"]

    third = _snapshot(tables=tuple(again.items), removed_tables=("customer",))
    back = merge_tables(third, [_table("product", "id", "sku"), _table("customer", "id")])
    assert back.added == ["customer"]
    assert back.removed_tables == []


# ---- tools --------------------------------------------------------------------------------


def _spec(name: str, schema: dict[str, Any] | None = None, **annotations: bool) -> ToolSpec:
    return ToolSpec(
        name=name,
        description=f"{name} tool",
        input_schema=schema or SCHEMA,
        annotations=annotations or None,
    )


def _tools_snapshot(specs: list[ToolSpec], previous: CatalogSnapshot | None = None) -> Any:
    merged = merge_tools(previous, "desk", specs)
    return merged, _snapshot(
        resource_type=ResourceType.MCP_SERVER, tools=tuple(merged.items), tables=None
    )


def _states(snapshot: CatalogSnapshot) -> dict[str, ToolState]:
    return {t.name: t.state for t in snapshot.tools or ()}


def test_new_tools_are_active_with_contract_action_ids() -> None:
    merged, snap = _tools_snapshot(
        [_spec("search", readOnlyHint=True), _spec("create", readOnlyHint=False), _spec("raw")]
    )
    assert merged.added == ["create", "raw", "search"]
    assert _states(snap) == dict.fromkeys(("create", "raw", "search"), ToolState.ACTIVE)
    tools = {t.name: t for t in snap.tools or ()}
    assert tools["search"].action == "mcp.desk.search"
    assert tools["search"].read_only is True
    assert tools["raw"].read_only is False
    assert tools["raw"].destructive is True


def test_schema_change_and_read_to_write_need_review() -> None:
    _, first = _tools_snapshot([_spec("search", **READ), _spec("lookup", **READ), _spec("w")])
    changed_schema = {"type": "object", "properties": {"q": {"type": "integer"}}}
    merged, second = _tools_snapshot(
        [_spec("search", **WRITE), _spec("lookup", changed_schema, **READ), _spec("w")], first
    )
    assert merged.changed == ["lookup", "search"]
    assert _states(second) == {
        "lookup": ToolState.NEEDS_REVIEW,
        "search": ToolState.NEEDS_REVIEW,
        "w": ToolState.ACTIVE,
    }


def test_write_to_read_and_description_changes_need_no_review() -> None:
    _, first = _tools_snapshot([_spec("w", **WRITE)])
    narrower = ToolSpec(name="w", description="new words", input_schema=SCHEMA, annotations=READ)
    merged, second = _tools_snapshot([narrower], first)
    assert merged.changed == ["w"]
    assert _states(second) == {"w": ToolState.ACTIVE}


def test_review_clears_when_the_tool_goes_back_to_what_was_accepted() -> None:
    _, first = _tools_snapshot([_spec("search", **READ)])
    _, second = _tools_snapshot([_spec("search", **WRITE)], first)
    assert _states(second) == {"search": ToolState.NEEDS_REVIEW}
    _, third = _tools_snapshot([_spec("search", **READ)], second)
    assert _states(third) == {"search": ToolState.ACTIVE}


def test_removed_tools_stay_as_removed_and_are_checked_when_they_return() -> None:
    _, first = _tools_snapshot([_spec("search", **READ), _spec("gone", **READ)])
    merged, second = _tools_snapshot([_spec("search", **READ)], first)
    assert merged.removed == ["gone"]
    assert _states(second)["gone"] is ToolState.REMOVED
    assert [t.name for t in second.live_tools()] == ["search"]

    quiet, third = _tools_snapshot([_spec("search", **READ)], second)
    assert quiet.removed == []  # not reported twice

    back, fourth = _tools_snapshot([_spec("search", **READ), _spec("gone", **WRITE)], third)
    assert back.added == ["gone"]
    assert _states(fourth)["gone"] is ToolState.NEEDS_REVIEW


def test_colliding_tools_are_both_left_out() -> None:
    merged, snap = _tools_snapshot(
        [_spec("create_ticket"), _spec("Create-Ticket"), _spec("search", **READ)]
    )
    assert [t.name for t in snap.tools or ()] == ["search"]
    [problem] = merged.problems
    assert problem.code == "action_collision"
    assert problem.tools == ("Create-Ticket", "create_ticket")


def test_too_long_names_are_left_out_and_underscore_names_kept() -> None:
    merged, snap = _tools_snapshot([_spec("x" * 70), _spec("_private"), _spec("ok")])
    assert [t.name for t in snap.tools or ()] == ["_private", "ok"]
    assert [t.action for t in snap.tools or ()] == ["mcp.desk.t__private", "mcp.desk.ok"]
    assert [(p.code, p.tools) for p in merged.problems] == [("action_too_long", ("x" * 70,))]


def test_acknowledge_accepts_the_current_shape() -> None:
    _, first = _tools_snapshot([_spec("search", **READ), _spec("other", **READ)])
    _, second = _tools_snapshot([_spec("search", **WRITE), _spec("other", **READ)], first)
    acked = acknowledge_tools(second.tools or (), ["search"])
    assert {t.name: t.state for t in acked} == {
        "other": ToolState.ACTIVE,
        "search": ToolState.ACTIVE,
    }
    third_snap = second.model_copy(update={"tools": tuple(acked)})
    # Accepted as a write: staying a write is no longer a change to review.
    _, fourth = _tools_snapshot([_spec("search", **WRITE), _spec("other", **READ)], third_snap)
    assert _states(fourth) == {"other": ToolState.ACTIVE, "search": ToolState.ACTIVE}


@pytest.mark.parametrize("names", [["other"], ["nope"], ["search", "other"]])
def test_acknowledge_refuses_tools_not_in_review(names: list[str]) -> None:
    _, first = _tools_snapshot([_spec("search", **READ), _spec("other", **READ)])
    _, second = _tools_snapshot([_spec("search", **WRITE), _spec("other", **READ)], first)
    with pytest.raises(KeyError):
        acknowledge_tools(second.tools or (), names)


def test_catalog_out_hides_review_bookkeeping() -> None:
    _, snap = _tools_snapshot([_spec("search", **READ)])
    out = catalog_out(snap).model_dump()
    assert out["resource"] == "sample"  # the name; URLs keep the id (amendment A1)
    assert out["tables"] is None
    [tool] = out["tools"]
    assert set(tool) == {
        "name",
        "action",
        "description",
        "input_schema",
        "read_only",
        "destructive",
        "state",
    }


# ---- registry groups ----------------------------------------------------------------------


async def _noop(ctx: ActionContext, params: Any) -> ActionResult:
    return ActionResult(ok=True)


def _registered(action_id: str) -> RegisteredAction:
    definition = ActionDefinition(
        id=action_id,
        broker=action_id.split(".")[0],
        resource_type=ResourceType.MCP_SERVER,
        description="x",
        risk=RiskLevel.LOW,
        input_model=NoParams,
    )
    return RegisteredAction(definition, _noop)


def test_replace_group_swaps_only_its_own_actions() -> None:
    registry = InMemoryActionRegistry(disabled=["mcp.a.off"])
    registry.register(_registered("mcp.static.x"))
    skipped = registry.replace_group(
        "catalog:a",
        [_registered("mcp.a.one"), _registered("mcp.static.x"), _registered("mcp.a.off")],
    )
    assert skipped == ["mcp.static.x"]
    assert registry.get("mcp.a.one") is not None
    assert registry.get("mcp.a.off") is None  # disabled in config still wins
    assert registry.group_of("mcp.a.one") == "catalog:a"
    assert registry.group_of("mcp.static.x") is None

    assert registry.replace_group("catalog:b", [_registered("mcp.a.one")]) == ["mcp.a.one"]
    registry.replace_group("catalog:a", [_registered("mcp.a.two")])
    assert registry.get("mcp.a.one") is None
    assert registry.get("mcp.a.two") is not None
    assert registry.get("mcp.static.x") is not None
    registry.replace_group("catalog:a", [])
    assert [a.definition.id for a in registry.all()] == ["mcp.static.x"]
