"""One test per non-negotiable principle (SPEC §1, §19).

P6 (one engine) and part of P7 (storage) are also covered by
``test_import_boundaries.py``, ``tests/unit/test_storage.py``, and the MCP integration test.
"""

import base64
import json

import pytest

from agent_gateway.config import BrokerSettings, DockerBrokerSettings, Settings
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.runtime import default_brokers
from tests.world import SECRET, World

SHELL_FIELD_NAMES = {"command", "cmd", "script", "shell", "exec", "args", "argv"}


async def _scenario(world: World) -> list[str]:
    """Exercise every agent and admin read endpoint; return all response bodies."""
    bodies: list[str] = []
    calls = [
        ("GET", "/v1/whoami", world.agent(), None),
        ("GET", "/v1/actions", world.agent(), None),
        ("GET", "/v1/resources", world.agent(), None),
        (
            "POST",
            "/v1/executions",
            world.agent(),
            {"action": "test.leak", "resource_id": world.resource_id, "params": {}},
        ),
        (
            "POST",
            "/v1/executions",
            world.agent(),
            {"action": "fake.echo", "resource_id": world.resource_id, "params": {"message": "x"}},
        ),
        ("GET", "/v1/executions", world.agent(), None),
        ("GET", "/v1/admin/agents", world.admin(), None),
        ("GET", "/v1/admin/tokens", world.admin(), None),
        ("GET", "/v1/admin/resources", world.admin(), None),
        ("GET", "/v1/admin/credentials", world.admin(), None),
        ("GET", "/v1/admin/roles", world.admin(), None),
        ("GET", "/v1/admin/policies", world.admin(), None),
        ("GET", "/v1/admin/approvals", world.admin(), None),
        ("GET", "/v1/admin/audit", world.admin(), None),
        ("GET", "/openapi.json", {}, None),
    ]
    for method, path, headers, body in calls:
        response = await world.api.request(method, path, headers=headers, json=body)
        assert response.status_code < 500, (path, response.text)
        bodies.append(response.text)
    return bodies


async def test_p1_master_key_never_leaves_the_gateway(world: World) -> None:
    raw = base64.b64decode(world.master_key)
    needles = {world.master_key, raw.hex(), base64.urlsafe_b64encode(raw).decode().rstrip("=")}
    for body in await _scenario(world):
        for needle in needles:
            assert needle not in body


async def test_p2_credentials_never_reach_agents_or_admin_reads(world: World) -> None:
    bodies = await _scenario(world)
    assert all(SECRET not in body for body in bodies)
    leak = json.loads(bodies[3])
    assert leak["status"] == "succeeded"
    assert leak["result"]["data"]["leaked"] == "value=***"


async def test_p2_audit_files_hold_no_secret_or_raw_params(world: World) -> None:
    await _scenario(world)
    text = "".join(
        p.read_text(encoding="utf-8")
        for p in (world.gateway.settings.var_dir / "audit").glob("*.jsonl")
    )
    assert SECRET not in text
    assert '"params":' not in text


async def test_p2_credential_files_are_encrypted(world: World) -> None:
    for path in (world.gateway.settings.var_dir / "credentials").iterdir():
        assert SECRET.encode() not in path.read_bytes()
    meta = (world.gateway.settings.var_dir / "credentials.json").read_text(encoding="utf-8")
    assert SECRET not in meta


def test_p3_only_privileged_actions_accept_a_command() -> None:
    """P3 (revised): arbitrary commands exist only as explicitly privileged actions."""
    settings = Settings(brokers=BrokerSettings(docker=DockerBrokerSettings(enabled=True)))
    registry = InMemoryActionRegistry()
    for broker in default_brokers(settings):
        broker.register(registry)
    assert registry.all()
    privileged = []
    for action in registry.all():
        definition = action.definition
        fields = set(definition.input_model.model_fields)
        if definition.privileged:
            privileged.append(definition.id)
            assert definition.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL), definition.id
            continue
        assert not fields & SHELL_FIELD_NAMES, definition.id
        for word in ("exec", "shell", "run_command", "sudo"):
            assert word not in definition.id
    assert privileged == ["ssh.sudo"]


async def test_p4_unregistered_action_never_reaches_a_broker(world: World) -> None:
    response = await world.api.post(
        "/v1/executions",
        json={"action": "fake.rm_rf", "resource_id": world.resource_id, "params": {}},
        headers=world.agent(),
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "action_not_found"
    assert world.fake.calls == []


@pytest.mark.parametrize(
    "extra",
    [
        {"approved": True},
        {"decision": {"effect": "allow"}},
        {"agent_id": "agt_someone_else"},
        {"status": "approved"},
    ],
)
async def test_p5_agents_cannot_assert_their_own_authorization(
    world: World, extra: dict[str, object]
) -> None:
    body = {"action": "fake.echo", "resource_id": world.resource_id, "params": {"message": "x"}}
    response = await world.api.post("/v1/executions", json=body | extra, headers=world.agent())
    assert response.status_code == 422
    assert world.fake.calls == []


async def test_p5_agents_cannot_use_admin_endpoints(world: World) -> None:
    for method, path in [
        ("GET", "/v1/admin/agents"),
        ("POST", "/v1/admin/tokens"),
        ("GET", "/v1/admin/audit"),
        ("PUT", "/v1/admin/roles/operator"),
    ]:
        response = await world.api.request(method, path, headers=world.agent(), json={})
        assert response.status_code == 403, path
        assert response.json()["error"]["code"] == "admin_required"


async def test_p5_admin_tokens_cannot_run_actions(world: World) -> None:
    response = await world.api.post(
        "/v1/executions",
        json={"action": "fake.echo", "resource_id": world.resource_id, "params": {"message": "x"}},
        headers=world.admin(),
    )
    assert response.status_code == 403
