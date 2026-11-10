"""`agw sync` and `agw catalog` against the fixture MCP server on a real socket (uvicorn).

Unlike the in-process tests, this goes through the broker's default HTTP client and the
CLI's own gateway, as an admin would run it.
"""

import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.routing import Mount
from typer.testing import CliRunner

from agent_gateway.brokers.mcp import McpBroker
from agent_gateway.cli import app
from agent_gateway.modules.resources.models import Resource, ResourceType
from tests.fixtures.mcp_fixture import FixtureServer

runner = CliRunner()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture(scope="module")
def fixture_url() -> Iterator[str]:
    fixture = FixtureServer()

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with fixture.running():
            yield

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            Starlette(routes=[Mount("/", app=fixture.app)], lifespan=lifespan),
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("fixture server did not start")
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def _variant(base: str, variant: str) -> None:
    response = httpx.post(f"{base}/variant", content=variant)
    assert response.status_code == 200


async def test_default_client_lists_tools_over_http(fixture_url: str) -> None:
    resource = Resource(
        id="res_x",
        type=ResourceType.MCP_SERVER,
        name="desk",
        attributes={"url": f"{fixture_url}/mcp"},
    )
    found = await McpBroker().read(resource, None)
    assert {t.name for t in found.tools or ()} >= {"lookup_order", "create_ticket"}


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    key = tmp_path / "master.key"
    config = tmp_path / "gateway.yaml"
    config.write_text(
        f"var_dir: {(tmp_path / 'var').as_posix()}\n"
        f"master_key_file: {key.as_posix()}\n"
        "brokers:\n  mcp:\n    enabled: true\n",
        encoding="utf-8",
    )
    assert runner.invoke(app, ["keygen", "--out", str(key)]).exit_code == 0
    return {"AGW_CONFIG_FILE": str(config)}


def test_sync_and_review_from_the_cli(fixture_url: str, env: dict[str, str]) -> None:
    _variant(fixture_url, "v1")
    attrs = json.dumps({"url": f"{fixture_url}/mcp"})
    added = runner.invoke(
        app, ["resource", "add", "mcp_server", "desk", "--attributes", attrs], env=env
    )
    assert added.exit_code == 0, added.output
    resource_id = json.loads(added.output)["id"]

    first = runner.invoke(app, ["sync", "desk"], env=env)
    assert first.exit_code == 0, first.output
    [out] = json.loads(first.output)
    assert out["resource"] == resource_id
    assert out["added"] == ["create_ticket", "list_queues", "lookup_order", "ping_raw"]

    _variant(fixture_url, "v2")
    try:
        second = runner.invoke(app, ["sync"], env=env)  # every resource with a catalog
        assert second.exit_code == 0, second.output
        [out] = json.loads(second.output)
        assert (out["added"], out["removed"]) == (["close_ticket"], ["ping_raw"])
        assert out["changed"] == ["list_queues", "lookup_order"]

        show = runner.invoke(app, ["catalog", "show", resource_id], env=env)
        assert show.exit_code == 0, show.output
        states = {t["name"]: t["state"] for t in json.loads(show.output)["tools"]}
        assert states["lookup_order"] == "needs_review"

        ack = runner.invoke(app, ["catalog", "ack", "desk", "lookup_order"], env=env)
        assert ack.exit_code == 0, ack.output
        states = {t["name"]: t["state"] for t in json.loads(ack.output)["tools"]}
        assert (states["lookup_order"], states["list_queues"]) == ("active", "needs_review")

        again = runner.invoke(app, ["catalog", "ack", "desk", "lookup_order"], env=env)
        assert again.exit_code == 1
        assert "not_pending_review" in again.output
    finally:
        _variant(fixture_url, "v1")


def test_sync_reports_an_unreachable_server(env: dict[str, str]) -> None:
    attrs = json.dumps({"url": f"http://127.0.0.1:{_free_port()}/mcp", "timeout_seconds": 2})
    added = runner.invoke(
        app, ["resource", "add", "mcp_server", "gone", "--attributes", attrs], env=env
    )
    assert added.exit_code == 0, added.output
    result = runner.invoke(app, ["sync", "gone"], env=env)
    assert result.exit_code == 1
    [out] = json.loads(result.output)
    assert (out["error"], out["message"]) == ("sync_failed", "could not reach the MCP server")
    missing = runner.invoke(app, ["sync", "no-such-resource"], env=env)
    assert missing.exit_code == 1
    assert "resource_not_found" in missing.output
