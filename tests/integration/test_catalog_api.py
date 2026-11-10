"""Catalog, sync, and MCP tools as actions, end to end (SPEC §11.6, admin contract §7).

A real gateway on a temp ``var/``, the fixture MCP server in-process, and a fake SQL
catalog source. Calls go through REST and the normal engine (policy, approval, audit).
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import types

from agent_gateway.apps.api_server.app import create_app
from agent_gateway.brokers.mcp import McpBroker
from agent_gateway.brokers.sql import SqlBroker
from agent_gateway.cli import CLI_ACTOR
from agent_gateway.config import Settings
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.audit.models import AuditEventType
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.catalog.models import (
    CatalogColumn,
    CatalogTable,
    SourceCatalog,
)
from agent_gateway.modules.catalog.ports import SourceUnavailableError
from agent_gateway.modules.catalog.service import REVIEW_PENDING
from agent_gateway.modules.credentials.models import REDACTED, CredentialType, SecretPayload
from agent_gateway.modules.identity.models import TokenKind
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.runtime import Gateway, build_gateway
from tests.fakes.brokers import FakeBroker
from tests.fixtures.mcp_fixture import FixtureServer
from tests.integration.test_mcp_actions import actions_session
from tests.unit.test_sql_broker import RecordingRunner

TOKEN = "fixture-bearer-token-123"
DESK_ACTIONS = ["mcp.desk.lookup_order", "mcp.desk.list_queues", "mcp.desk.create_ticket"]


@dataclass
class FakeSqlSource:
    tables: list[CatalogTable] = field(default_factory=list[CatalogTable])
    error: str | None = None

    @property
    def resource_type(self) -> ResourceType:
        return ResourceType.SQL_DATABASE

    async def read(self, resource: Resource, credential: SecretPayload | None) -> SourceCatalog:
        assert credential is not None
        assert credential.reveal() == "db-password"
        if self.error is not None:
            raise SourceUnavailableError(self.error)
        return SourceCatalog(tables=tuple(self.tables))


def table(name: str, *columns: str) -> CatalogTable:
    return CatalogTable(
        name=name,
        comment=f"{name} table",
        columns=tuple(CatalogColumn(name=c, type="integer", nullable=False) for c in columns),
    )


@dataclass
class CatalogWorld:
    gateway: Gateway
    api: httpx.AsyncClient
    fixture: FixtureServer
    sql_source: FakeSqlSource
    sql_runner: RecordingRunner
    admin_token: str
    agent_token: str
    desk_id: str
    other_desk_id: str
    sample_id: str
    endpoint_id: str

    def admin(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.admin_token}"}

    def agent(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.agent_token}"}

    async def sync(self, resource_id: str) -> httpx.Response:
        return await self.api.post(f"/v1/admin/resources/{resource_id}/sync", headers=self.admin())

    async def run(self, action: str, resource_id: str, **params: Any) -> httpx.Response:
        body = {"action": action, "resource_id": resource_id, "params": params}
        return await self.api.post("/v1/executions", json=body, headers=self.agent())

    async def grant(self, *actions: str, approval: ApprovalMode = ApprovalMode.NEVER) -> None:
        """Role and policy that name the actions exactly (catalog actions need that)."""
        admin = self.gateway.admin
        role = Role(id="desk-user", actions=("fake.*", "sql.query", *actions))
        await admin.put_role(CLI_PRINCIPAL, role)
        await admin.create_policy(
            CLI_PRINCIPAL,
            subject=PolicySubject(role="desk-user"),
            actions=list(actions),
            resources=ResourceSelector(ids=(self.desk_id, self.other_desk_id)),
            effect=PolicyEffect.ALLOW,
            approval=approval,
        )


async def build_catalog_world(settings: Settings, fixture: FixtureServer) -> CatalogWorld:
    mcp = McpBroker(http_client=fixture.http_client)
    runner = RecordingRunner()
    source = FakeSqlSource(tables=[table("product", "id"), table("customer", "id")])
    gateway = build_gateway(
        settings, brokers=[FakeBroker(), mcp, SqlBroker(runner)], catalog_sources=[mcp, source]
    )
    await gateway.start(background=False)
    admin = gateway.admin
    await admin.put_role(CLI_PRINCIPAL, Role(id="desk-user", actions=("fake.*", "sql.query")))
    agent = await admin.create_agent(CLI_PRINCIPAL, "desk-agent", roles=["desk-user"])
    bearer = await admin.create_credential(
        CLI_PRINCIPAL, "desk token", SecretPayload(CredentialType.API_TOKEN, TOKEN)
    )
    db = await admin.create_credential(
        CLI_PRINCIPAL, "db login", SecretPayload(CredentialType.BASIC_AUTH, "db-password")
    )
    attrs = {"url": "http://fixture.internal/mcp"}
    desk = await admin.create_resource(
        CLI_PRINCIPAL, ResourceType.MCP_SERVER, "desk", attributes=attrs, credential_id=bearer.id
    )
    other = await admin.create_resource(
        CLI_PRINCIPAL,
        ResourceType.MCP_SERVER,
        "other-desk",
        attributes=attrs,
        credential_id=bearer.id,
    )
    sample = await admin.create_resource(
        CLI_PRINCIPAL,
        ResourceType.SQL_DATABASE,
        "sample",
        attributes={
            "host": "db.internal",
            "dbname": "sales",
            "username": "agw_reader",
            "schema_name": "sample",
            "allowed_tables": ["product", "customer"],
        },
        credential_id=db.id,
    )
    endpoint = await admin.create_resource(
        CLI_PRINCIPAL, ResourceType.HTTP_ENDPOINT, "echo", attributes={"host": "echo.internal"}
    )
    await admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(role="desk-user"),
        actions=["sql.query"],
        resources=ResourceSelector(ids=(sample.id,)),
        effect=PolicyEffect.ALLOW,
        approval=ApprovalMode.NEVER,
    )
    agent_token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.AGENT, agent_id=agent.id)
    admin_token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.ADMIN)
    app = create_app(gateway, manage_lifecycle=False)
    api = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway")
    return CatalogWorld(
        gateway=gateway,
        api=api,
        fixture=fixture,
        sql_source=source,
        sql_runner=runner,
        admin_token=admin_token.plaintext.get_secret_value(),
        agent_token=agent_token.plaintext.get_secret_value(),
        desk_id=desk.id,
        other_desk_id=other.id,
        sample_id=sample.id,
        endpoint_id=endpoint.id,
    )


@pytest.fixture
async def cw(settings: Settings) -> AsyncIterator[CatalogWorld]:
    fixture = FixtureServer(token=TOKEN)
    w = await build_catalog_world(settings, fixture)
    yield w
    await w.api.aclose()
    await w.gateway.stop()


def error_code(response: httpx.Response) -> str:
    return str(response.json()["error"]["code"])


# ---- MCP sync -----------------------------------------------------------------------------


async def test_sync_turns_tools_into_actions(cw: CatalogWorld) -> None:
    response = await cw.sync(cw.desk_id)
    assert response.status_code == 200, response.text
    out = response.json()
    assert out["added"] == ["create_ticket", "list_queues", "lookup_order", "ping_raw"]
    assert out["removed"] == out["changed"] == []
    assert out["snapshot_id"].startswith("snap_")

    catalog = await cw.api.get(f"/v1/admin/resources/{cw.desk_id}/catalog", headers=cw.admin())
    body = catalog.json()
    assert body["resource"] == cw.desk_id
    assert body["snapshot_id"] == out["snapshot_id"]
    assert body["tables"] is None
    tools = {t["name"]: t for t in body["tools"]}
    assert tools["lookup_order"] == {
        "name": "lookup_order",
        "action": "mcp.desk.lookup_order",
        "description": "Look up one order by id.",
        "input_schema": tools["lookup_order"]["input_schema"],
        "read_only": True,
        "destructive": False,
        "state": "active",
    }
    assert (tools["create_ticket"]["read_only"], tools["create_ticket"]["destructive"]) == (
        False,
        False,
    )
    assert (tools["ping_raw"]["read_only"], tools["ping_raw"]["destructive"]) == (False, True)

    registry = cw.gateway.registry
    risks = {
        a: (registry.get(a).definition.risk.value, registry.get(a).definition.read_only)  # type: ignore[union-attr]
        for a in [*DESK_ACTIONS, "mcp.desk.ping_raw"]
    }
    assert risks == {
        "mcp.desk.lookup_order": ("low", True),
        "mcp.desk.list_queues": ("low", True),
        "mcp.desk.create_ticket": ("medium", False),
        "mcp.desk.ping_raw": ("high", False),
    }
    infos = {i.action: i for i in await cw.gateway.catalog.catalog_actions()}
    assert infos["mcp.desk.ping_raw"].resource_name == "desk"
    assert infos["mcp.desk.ping_raw"].state == "active"


async def test_new_tools_are_granted_to_nobody(cw: CatalogWorld) -> None:
    # A wildcard role and policy do not cover catalog actions: they must be named exactly.
    admin = cw.gateway.admin
    await admin.put_role(CLI_PRINCIPAL, Role(id="desk-user", actions=("mcp.*", "mcp.desk.*")))
    await admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(role="desk-user"),
        actions=["mcp.*"],
        resources=ResourceSelector(ids=(cw.desk_id,)),
        effect=PolicyEffect.ALLOW,
        approval=ApprovalMode.NEVER,
    )
    assert (await cw.sync(cw.desk_id)).status_code == 200
    response = await cw.run("mcp.desk.list_queues", cw.desk_id)
    assert response.status_code == 403
    assert error_code(response) == "action_not_allowed"
    listed = await cw.api.get("/v1/actions", headers=cw.agent())
    assert not [a for a in listed.json() if a["id"].startswith("mcp.")]
    assert cw.fixture.calls == []


async def test_a_granted_tool_runs_through_the_engine(cw: CatalogWorld) -> None:
    await cw.sync(cw.desk_id)
    await cw.grant("mcp.desk.lookup_order")
    cw.fixture.secret_in_output = TOKEN
    response = await cw.run("mcp.desk.lookup_order", cw.desk_id, order_id="A-1")
    assert response.status_code == 200, response.text
    execution = response.json()
    assert execution["status"] == "succeeded"
    assert execution["result"]["data"] == {
        "content": [f"order A-1 is open (key {REDACTED})"],
        "structured": {"order_id": "A-1", "status": "open"},
    }
    assert cw.fixture.calls == [("lookup_order", {"order_id": "A-1"})]

    failed = await cw.run("mcp.desk.lookup_order", cw.desk_id, order_id="missing")
    assert failed.json()["status"] == "failed"
    assert failed.json()["error"] == "the tool reported an error: order missing not found"

    bad = await cw.run("mcp.desk.lookup_order", cw.desk_id, order_id="")
    assert bad.status_code == 422
    assert error_code(bad) == "invalid_params"
    assert len(cw.fixture.calls) == 2


async def test_a_tool_runs_only_on_its_own_resource(cw: CatalogWorld) -> None:
    await cw.sync(cw.desk_id)
    await cw.grant("mcp.desk.lookup_order")
    response = await cw.run("mcp.desk.lookup_order", cw.other_desk_id, order_id="A-1")
    assert response.status_code == 403
    assert response.json()["error"]["message"] == "action belongs to another resource"
    assert cw.fixture.calls == []


async def test_changed_tools_are_denied_until_acknowledged(cw: CatalogWorld) -> None:
    await cw.sync(cw.desk_id)
    await cw.grant(*DESK_ACTIONS, "mcp.desk.ping_raw")
    assert (await cw.run("mcp.desk.list_queues", cw.desk_id)).json()["status"] == "succeeded"

    cw.fixture.variant = "v2"
    response = await cw.sync(cw.desk_id)
    assert response.status_code == 200, response.text
    out = response.json()
    assert out["added"] == ["close_ticket"]
    assert out["removed"] == ["ping_raw"]
    assert out["changed"] == ["list_queues", "lookup_order"]

    catalog = await cw.gateway.catalog.catalog(cw.desk_id)
    assert {t.name: t.state.value for t in catalog.tools or ()} == {
        "close_ticket": "active",
        "create_ticket": "active",
        "list_queues": "needs_review",
        "lookup_order": "needs_review",
        "ping_raw": "removed",
    }
    resource = await cw.gateway.catalog.resolve("desk")
    assert (await cw.gateway.catalog.state(resource)).pending_review is True

    calls = len(cw.fixture.calls)
    for action, params in [
        ("mcp.desk.list_queues", {}),
        ("mcp.desk.lookup_order", {"order_id": "A-1", "include_lines": True}),
    ]:
        denied = await cw.run(action, cw.desk_id, **params)
        assert denied.status_code == 403
        assert denied.json()["error"]["message"] == REVIEW_PENDING
        execution = await cw.gateway.engine.get(
            CLI_PRINCIPAL, denied.json()["error"]["execution_id"]
        )
        assert execution.decision is not None
        assert execution.decision.reason == REVIEW_PENDING
    assert len(cw.fixture.calls) == calls
    # Removed tools stop being actions; unchanged ones keep working.
    assert (await cw.run("mcp.desk.ping_raw", cw.desk_id)).status_code == 404
    created = await cw.run("mcp.desk.create_ticket", cw.desk_id, title="t")
    assert created.json()["status"] == "succeeded"

    ack = await cw.api.post(
        f"/v1/admin/resources/{cw.desk_id}/catalog/acknowledge",
        json={"tools": ["lookup_order"]},
        headers=cw.admin(),
    )
    assert ack.status_code == 200, ack.text
    states = {t["name"]: t["state"] for t in ack.json()["tools"]}
    assert states["lookup_order"] == "active"
    assert states["list_queues"] == "needs_review"
    ok = await cw.run("mcp.desk.lookup_order", cw.desk_id, order_id="A-1", include_lines=True)
    assert ok.json()["status"] == "succeeded"

    for tools in (["lookup_order"], ["nope"], ["ping_raw"], ["list_queues", "create_ticket"]):
        again = await cw.api.post(
            f"/v1/admin/resources/{cw.desk_id}/catalog/acknowledge",
            json={"tools": tools},
            headers=cw.admin(),
        )
        assert again.status_code == 409, tools
        assert error_code(again) == "not_pending_review"
    # A refused acknowledge changes nothing.
    still = await cw.gateway.catalog.catalog(cw.desk_id)
    assert {t.name: t.state.value for t in still.tools or ()}["list_queues"] == "needs_review"

    events = [e.event for e in await cw.gateway.audit.query()]
    assert AuditEventType.CATALOG_SYNCED in events
    assert AuditEventType.CATALOG_ACKNOWLEDGED in events


async def test_review_started_while_waiting_for_approval_stops_the_run(cw: CatalogWorld) -> None:
    await cw.sync(cw.desk_id)
    await cw.grant("mcp.desk.list_queues", approval=ApprovalMode.ALWAYS)
    pending = await cw.run("mcp.desk.list_queues", cw.desk_id)
    assert pending.json()["status"] == "pending_approval"
    cw.fixture.variant = "v2"
    await cw.sync(cw.desk_id)

    approval_id = pending.json()["approval_id"]
    decided = await cw.api.post(f"/v1/admin/approvals/{approval_id}/approve", headers=cw.admin())
    assert decided.status_code == 200, decided.text
    await cw.gateway.engine.dispatch_approvals()
    await cw.gateway.engine.drain()
    execution = await cw.gateway.engine.get(CLI_PRINCIPAL, pending.json()["id"])
    assert execution.status.value == "failed"
    assert execution.error == REVIEW_PENDING
    assert cw.fixture.calls == []


async def test_sync_failure_keeps_the_last_snapshot(cw: CatalogWorld) -> None:
    first = (await cw.sync(cw.desk_id)).json()
    cw.fixture.token = "rotated-elsewhere"
    response = await cw.sync(cw.desk_id)
    assert response.status_code == 502
    assert response.json()["error"] == {
        "code": "sync_failed",
        "message": "could not reach the MCP server",
    }
    assert TOKEN not in response.text
    catalog = await cw.gateway.catalog.catalog(cw.desk_id)
    assert catalog.snapshot_id == first["snapshot_id"]
    assert cw.gateway.registry.get("mcp.desk.lookup_order") is not None
    events = [e.event for e in await cw.gateway.audit.query()]
    assert AuditEventType.CATALOG_SYNC_FAILED in events


async def test_colliding_tools_answer_409_and_are_not_added(cw: CatalogWorld) -> None:
    v1 = cw.fixture.listed()
    clash = types.Tool(name="Create-Ticket", input_schema={"type": "object"})
    cw.fixture.tools = [*v1, clash]
    response = await cw.sync(cw.desk_id)
    assert response.status_code == 409
    assert error_code(response) == "action_collision"
    assert "Create-Ticket, create_ticket" in response.json()["error"]["message"]
    catalog = await cw.gateway.catalog.catalog(cw.desk_id)
    assert sorted(t.name for t in catalog.live_tools()) == [
        "list_queues",
        "lookup_order",
        "ping_raw",
    ]
    assert cw.gateway.registry.get("mcp.desk.create_ticket") is None
    assert cw.gateway.registry.get("mcp.desk.list_queues") is not None


async def test_too_long_tool_answers_409(cw: CatalogWorld) -> None:
    cw.fixture.tools = [types.Tool(name="t" * 60, input_schema={"type": "object"})]
    response = await cw.sync(cw.desk_id)
    assert response.status_code == 409
    assert error_code(response) == "action_too_long"


async def test_actions_come_back_from_the_snapshot_after_a_restart(
    cw: CatalogWorld, settings: Settings
) -> None:
    await cw.sync(cw.desk_id)
    again = build_gateway(
        settings,
        brokers=[FakeBroker(), McpBroker(http_client=cw.fixture.http_client)],
    )
    assert again.registry.get("mcp.desk.lookup_order") is None
    await again.start(background=False)
    try:
        assert again.registry.get("mcp.desk.lookup_order") is not None
    finally:
        await again.stop()


async def test_a_sync_from_another_process_is_picked_up(
    cw: CatalogWorld, settings: Settings
) -> None:
    await cw.sync(cw.desk_id)
    cli = build_gateway(
        settings, brokers=[FakeBroker(), McpBroker(http_client=cw.fixture.http_client)]
    )
    cw.fixture.variant = "v2"
    await cli.catalog.sync(CLI_ACTOR, cw.desk_id)
    registry = cw.gateway.registry
    assert registry.get("mcp.desk.close_ticket") is None
    await cw.gateway.catalog.load_actions()
    assert registry.get("mcp.desk.close_ticket") is not None
    assert registry.get("mcp.desk.ping_raw") is None


async def test_deleting_the_resource_drops_its_actions(cw: CatalogWorld) -> None:
    await cw.sync(cw.desk_id)
    await cw.gateway.admin.delete_resource(CLI_PRINCIPAL, cw.desk_id)
    await cw.gateway.catalog.load_actions()
    assert cw.gateway.registry.get("mcp.desk.lookup_order") is None


async def test_actions_tool_profile_offers_only_the_bound_resource(cw: CatalogWorld) -> None:
    await cw.sync(cw.desk_id)
    await cw.grant("mcp.desk.lookup_order")
    application = create_app(cw.gateway, manage_lifecycle=False)
    async with (
        application.router.lifespan_context(application),
        actions_session(application, cw.agent_token) as session,
    ):
        tools = {t.name: t for t in (await session.list_tools()).tools}
    tool = tools["mcp_desk_lookup_order"]
    assert tool.input_schema["properties"]["resource_id"]["enum"] == [cw.desk_id]
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True


# ---- SQL catalog --------------------------------------------------------------------------


async def test_sql_sync_reads_tables_and_flags_removed_ones(cw: CatalogWorld) -> None:
    response = await cw.sync(cw.sample_id)
    assert response.status_code == 200, response.text
    assert response.json()["added"] == ["customer", "product"]
    catalog = (
        await cw.api.get(f"/v1/admin/resources/{cw.sample_id}/catalog", headers=cw.admin())
    ).json()
    assert catalog["tools"] is None
    assert catalog["tables"][0] == {
        "name": "customer",
        "comment": "customer table",
        "columns": [{"name": "id", "type": "integer", "nullable": False, "comment": ""}],
    }
    port = cw.gateway.catalog
    sample = await port.resolve(cw.sample_id)
    assert await port.tables(cw.sample_id) == ["customer", "product"]
    assert (await port.state(sample)).pending_review is False

    ok = await cw.run("sql.query", cw.sample_id, sql="SELECT id FROM customer")
    assert ok.json()["status"] == "succeeded"

    cw.sql_source.tables = [table("product", "id", "sku")]
    out = (await cw.sync(cw.sample_id)).json()
    assert (out["removed"], out["changed"]) == (["customer"], ["product"])
    assert await port.tables(cw.sample_id) == ["product"]
    state = await port.state(sample)
    assert state.pending_review is True
    assert state.snapshot_id == out["snapshot_id"]
    # Still in allowed_tables, but the broker refuses it now (and sync granted nothing).
    assert sample.attributes["allowed_tables"] == ["product", "customer"]
    calls = len(cw.sql_runner.calls)
    refused = await cw.run("sql.query", cw.sample_id, sql="SELECT id FROM customer")
    assert refused.json()["status"] == "failed"
    assert "'customer' not in your allowed set" in refused.json()["error"]
    assert len(cw.sql_runner.calls) == calls

    # A plan (here: an infra update) removing the table clears the flag.
    updated = await cw.gateway.admin.update_resource(
        CLI_PRINCIPAL, cw.sample_id, attributes={**sample.attributes, "allowed_tables": ["product"]}
    )
    assert (await port.state(updated)).pending_review is False


async def test_sql_sync_failure_is_502(cw: CatalogWorld) -> None:
    first = (await cw.sync(cw.sample_id)).json()
    cw.sql_source.error = "could not connect to the database"
    response = await cw.sync(cw.sample_id)
    assert response.status_code == 502
    assert response.json()["error"]["message"] == "could not connect to the database"
    assert (await cw.gateway.catalog.catalog(cw.sample_id)).snapshot_id == first["snapshot_id"]


# ---- errors and access --------------------------------------------------------------------


async def test_catalog_endpoints_need_the_admin_token(cw: CatalogWorld) -> None:
    for method, path in [
        ("GET", f"/v1/admin/resources/{cw.desk_id}/catalog"),
        ("POST", f"/v1/admin/resources/{cw.desk_id}/sync"),
        ("POST", f"/v1/admin/resources/{cw.desk_id}/catalog/acknowledge"),
    ]:
        response = await cw.api.request(method, path, json={"tools": ["x"]}, headers=cw.agent())
        assert response.status_code == 403, path
        assert error_code(response) == "admin_required"


async def test_catalog_errors(cw: CatalogWorld) -> None:
    missing = await cw.api.get("/v1/admin/resources/res_nope/catalog", headers=cw.admin())
    assert (missing.status_code, error_code(missing)) == (404, "resource_not_found")
    never = await cw.api.get(f"/v1/admin/resources/{cw.desk_id}/catalog", headers=cw.admin())
    assert (never.status_code, error_code(never)) == (404, "catalog_not_found")
    unsupported = await cw.sync(cw.endpoint_id)
    assert (unsupported.status_code, error_code(unsupported)) == (422, "catalog_not_supported")
    ack = await cw.api.post(
        f"/v1/admin/resources/{cw.desk_id}/catalog/acknowledge",
        json={"tools": ["lookup_order"]},
        headers=cw.admin(),
    )
    assert (ack.status_code, error_code(ack)) == (409, "not_pending_review")
    empty = await cw.api.post(
        f"/v1/admin/resources/{cw.desk_id}/catalog/acknowledge",
        json={"tools": []},
        headers=cw.admin(),
    )
    assert empty.status_code == 422


def test_settings_turn_the_mcp_broker_on(tmp_path: Path) -> None:
    from agent_gateway.config import BrokerSettings, McpBrokerSettings
    from agent_gateway.runtime import default_brokers

    assert "mcp" not in {b.name for b in default_brokers(Settings())}
    on = Settings(brokers=BrokerSettings(mcp=McpBrokerSettings(enabled=True)))
    assert "mcp" in {b.name for b in default_brokers(on)}
