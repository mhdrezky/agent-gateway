"""Admin web UI at /admin: session login, CSRF, every page, and the main admin flows."""

import re
from collections.abc import AsyncIterator

import httpx
import pytest

from agent_gateway.apps.api_server.app import create_app
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from tests.world import SECRET, World

BASE = "http://127.0.0.1:8080"
CSRF = re.compile(r'name="csrf" value="([^"]+)"')
CSRF_ANY = re.compile(r'name="csrf" value="([^"]*)"')
PAGES = [
    "/admin",
    "/admin/approvals",
    "/admin/approvals?status=all&auto=1",
    "/admin/executions",
    "/admin/agents",
    "/admin/tokens",
    "/admin/resources",
    "/admin/roles",
    "/admin/policies",
    "/admin/credentials",
    "/admin/audit",
]


@pytest.fixture
async def ui(world: World) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(world.gateway, manage_lifecycle=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client:
        yield client


async def login(client: httpx.AsyncClient, token: str) -> httpx.Response:
    return await client.post("/admin/login", data={"token": token})


async def csrf(client: httpx.AsyncClient, page: str = "/admin") -> str:
    match = CSRF.search((await client.get(page)).text)
    assert match is not None
    return match.group(1)


async def test_pages_need_a_session(ui: httpx.AsyncClient) -> None:
    response = await ui.get("/admin/approvals")
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/login"
    login_page = await ui.get("/admin/login")
    assert login_page.status_code == 200
    assert "Admin token" in login_page.text
    assert (await ui.get("/admin/static/admin.css")).status_code == 200


async def test_login_rejects_bad_and_agent_tokens(ui: httpx.AsyncClient, world: World) -> None:
    bad = await login(ui, "agw_tok_nope_x")
    assert bad.status_code == 401
    agent = await login(ui, world.agent_token)
    assert agent.status_code == 403
    assert "agent token" in agent.text
    assert "agw_admin" not in ui.cookies


async def test_login_sets_a_strict_httponly_cookie(ui: httpx.AsyncClient, world: World) -> None:
    response = await login(ui, world.admin_token)
    assert response.status_code == 303
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/admin" in cookie
    assert world.admin_token not in cookie


@pytest.mark.parametrize("page", PAGES)
async def test_every_page_renders_with_security_headers(
    ui: httpx.AsyncClient, world: World, page: str
) -> None:
    await login(ui, world.admin_token)
    response = await ui.get(page)
    assert response.status_code == 200, response.text
    assert "script-src" not in response.headers["content-security-policy"]  # no scripts at all
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "<script" not in response.text
    # Every POST form carries this session's CSRF token (not an empty one).
    posts = response.text.count('method="post"')
    tokens = CSRF_ANY.findall(response.text)
    assert len(tokens) == posts
    assert len(set(tokens)) == 1
    assert all(tokens)


async def test_resource_and_execution_detail_pages(ui: httpx.AsyncClient, world: World) -> None:
    submitted = await world.api.post(
        "/v1/executions",
        json={"action": "fake.echo", "resource_id": world.resource_id, "params": {"message": "hi"}},
        headers=world.agent(),
    )
    await login(ui, world.admin_token)
    execution = await ui.get(f"/admin/executions/{submitted.json()['id']}")
    assert execution.status_code == 200
    assert "fake.echo" in execution.text
    resource = await ui.get(f"/admin/resources/{world.resource_id}")
    assert resource.status_code == 200
    assert "echo-endpoint" in resource.text
    missing = await ui.get("/admin/executions/exe_missing")
    assert missing.status_code == 303


async def test_forms_need_the_csrf_token(ui: httpx.AsyncClient, world: World) -> None:
    await login(ui, world.admin_token)
    forged = await ui.post("/admin/agents", data={"name": "evil-agent"})
    assert forged.status_code == 403
    wrong = await ui.post("/admin/agents", data={"name": "evil-agent", "csrf": "nope"})
    assert wrong.status_code == 403
    assert "evil-agent" not in (await ui.get("/admin/agents")).text


async def test_create_agent_and_issue_a_token_shown_once(
    ui: httpx.AsyncClient, world: World
) -> None:
    await login(ui, world.admin_token)
    token = await csrf(ui)
    created = await ui.post(
        "/admin/agents", data={"name": "web01-agent", "roles": "operator", "csrf": token}
    )
    assert created.status_code == 303
    agents_page = (await ui.get("/admin/agents")).text
    assert "web01-agent" in agents_page
    assert "Agent web01-agent created." in agents_page

    agent_id = next(
        a.id
        for a in await world.gateway.admin.list_agents(CLI_PRINCIPAL)
        if a.name == "web01-agent"
    )
    issued = await ui.post(f"/admin/agents/{agent_id}/tokens", data={"csrf": token})
    assert issued.status_code == 200  # rendered, never redirected or stored
    assert "agw_tok_" in issued.text
    assert f"{BASE}/mcp" in issued.text
    plaintext = re.search(r"agw_tok_[A-Za-z0-9_-]+", issued.text)
    assert plaintext is not None
    assert plaintext.group(0) not in (await ui.get("/admin/tokens")).text


async def test_approve_from_the_ui_runs_the_execution(
    approval_world: World,
) -> None:
    w = approval_world
    submitted = await w.api.post(
        "/v1/executions",
        json={"action": "fake.echo", "resource_id": w.resource_id, "params": {"message": "ui"}},
        headers=w.agent(),
    )
    approval_id = submitted.json()["approval_id"]
    app = create_app(w.gateway, manage_lifecycle=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as ui:
        await login(ui, w.admin_token)
        page = await ui.get("/admin/approvals")
        assert approval_id in page.text
        assert "&#34;message&#34;: &#34;ui&#34;" in page.text or '"message": "ui"' in page.text
        token = await csrf(ui, "/admin/approvals")
        approved = await ui.post(f"/admin/approvals/{approval_id}/approve", data={"csrf": token})
        assert approved.status_code == 303
        await w.gateway.engine.drain()
        done = (
            await w.api.get(f"/v1/executions/{submitted.json()['id']}", headers=w.agent())
        ).json()
        assert done["status"] == "succeeded"
        assert "Approved." in (await ui.get("/admin/approvals?status=all")).text


async def test_credentials_are_write_only(ui: httpx.AsyncClient, world: World) -> None:
    await login(ui, world.admin_token)
    token = await csrf(ui)
    await ui.post(
        "/admin/credentials",
        data={"name": "ui-key", "type": "api_token", "value": "ui-secret-value-123", "csrf": token},
    )
    for page in PAGES:
        text = (await ui.get(page)).text
        assert "ui-secret-value-123" not in text
        assert SECRET not in text


async def test_sudo_toggle_and_services(ui: httpx.AsyncClient, world: World) -> None:
    await login(ui, world.admin_token)
    token = await csrf(ui)
    # The world's resource is an http_endpoint: services/sudo only apply to ssh hosts,
    # and its attribute schema rejects unknown keys, so the change is refused cleanly.
    response = await ui.post(
        f"/admin/resources/{world.resource_id}/sudo", data={"allow_sudo": "on", "csrf": token}
    )
    assert response.status_code == 303
    page = (await ui.get(f"/admin/resources/{world.resource_id}")).text
    assert "invalid" in page.lower() or "error" in page.lower()


async def test_revoking_the_admin_token_ends_the_session(
    ui: httpx.AsyncClient, world: World
) -> None:
    await login(ui, world.admin_token)
    token = await csrf(ui)
    own_id = next(
        t.id
        for t in await world.gateway.admin.list_tokens(CLI_PRINCIPAL)
        if t.kind.value == "admin"
    )
    revoked = await ui.post(f"/admin/tokens/{own_id}/revoke", data={"csrf": token})
    assert revoked.status_code == 303
    after = await ui.get("/admin")
    assert after.status_code == 303
    assert after.headers["location"] == "/admin/login"


async def test_logout(ui: httpx.AsyncClient, world: World) -> None:
    await login(ui, world.admin_token)
    out = await ui.post("/admin/logout", data={"csrf": await csrf(ui)})
    assert out.status_code == 303
    assert (await ui.get("/admin")).status_code == 303


async def test_audit_verify_from_the_ui(ui: httpx.AsyncClient, world: World) -> None:
    await login(ui, world.admin_token)
    await ui.post("/admin/audit/verify", data={"csrf": await csrf(ui)})
    assert "Audit chain OK" in (await ui.get("/admin/audit")).text
