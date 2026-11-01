import json
import struct
from typing import Any

import httpx
import pytest

from agent_gateway.brokers.docker import DockerBroker
from agent_gateway.brokers.docker.client import base_url, demux_logs
from agent_gateway.brokers.docker.models import ContainerParams, LogsParams, NoParams
from agent_gateway.common.errors import InvalidParamsError
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.modules.credentials.models import REDACTED, CredentialType, SecretPayload
from agent_gateway.modules.resources.models import ResourceType
from tests.unit.broker_support import make_ctx

TOKEN = SecretPayload(CredentialType.API_TOKEN, "tok-very-secret-123")
MANAGED_ID = "a" * 64
ALLOWED_ID = "b" * 64
FOREIGN_ID = "c" * 64


def _frame(stream: int, data: bytes) -> bytes:
    return struct.pack(">BxxxL", stream, len(data)) + data


class FakeEngine:
    """Enough of the Docker Engine API for the broker's four actions."""

    def __init__(self) -> None:
        self.containers: dict[str, dict[str, Any]] = {
            MANAGED_ID: {"name": "web", "labels": {"agw.managed": "true"}, "tty": False},
            ALLOWED_ID: {"name": "db", "labels": {}, "tty": True},
            FOREIGN_ID: {"name": "vault", "labels": {"agw.managed": "false"}, "tty": False},
        }
        self.logs: dict[str, bytes] = {
            MANAGED_ID: _frame(1, b"hello\n") + _frame(2, b"oops\n"),
            ALLOWED_ID: b"tty output\n",
        }
        self.requests: list[httpx.Request] = []
        self.stopped: set[str] = set()
        self.fail_with: int | None = None

    def _find(self, ref: str) -> str | None:
        for cid, c in self.containers.items():
            if ref in (cid, c["name"]):
                return cid
        return None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_with is not None:
            return httpx.Response(self.fail_with, json={"message": "boom"})
        parts = request.url.path.strip("/").split("/")
        if parts and parts[0].startswith("v1."):
            parts = parts[1:]
        if parts == ["containers", "json"]:
            return httpx.Response(
                200,
                json=[
                    {
                        "Id": cid,
                        "Names": [f"/{c['name']}"],
                        "Image": "nginx:latest",
                        "State": "running",
                        "Status": "Up 2 hours",
                        "Labels": c["labels"],
                    }
                    for cid, c in self.containers.items()
                ],
            )
        if len(parts) == 3 and parts[0] == "containers":
            cid = self._find(parts[1])
            if cid is None:
                return httpx.Response(404, json={"message": "No such container"})
            c = self.containers[cid]
            if parts[2] == "json" and request.method == "GET":
                return httpx.Response(
                    200,
                    json={
                        "Id": cid,
                        "Name": f"/{c['name']}",
                        "Config": {"Labels": c["labels"], "Tty": c["tty"]},
                    },
                )
            if parts[2] == "logs":
                return httpx.Response(200, content=self.logs.get(cid, b""))
            if parts[2] == "restart" and request.method == "POST":
                return httpx.Response(204)
            if parts[2] == "stop" and request.method == "POST":
                if cid in self.stopped:
                    return httpx.Response(304)
                self.stopped.add(cid)
                return httpx.Response(204)
        return httpx.Response(400, json={"message": "unexpected"})

    def mutating_requests(self) -> list[str]:
        return [r.url.path for r in self.requests if r.method == "POST"]


@pytest.fixture
def engine() -> FakeEngine:
    return FakeEngine()


@pytest.fixture
def broker(engine: FakeEngine) -> DockerBroker:
    return DockerBroker(transport_factory=lambda endpoint: httpx.MockTransport(engine.handler))


def _ctx(
    credential: SecretPayload | None = None, output_limit_bytes: int = 65536, **attrs: Any
) -> Any:
    attributes = {"allowed_containers": ["db"], **attrs}
    return make_ctx(
        ResourceType.DOCKER_HOST, attributes, credential, output_limit_bytes=output_limit_bytes
    )


def test_registers_four_actions_with_spec_risks(broker: DockerBroker) -> None:
    registry = InMemoryActionRegistry()
    broker.register(registry)
    assert {a.definition.id: a.definition.risk for a in registry.all()} == {
        "docker.container.list": RiskLevel.LOW,
        "docker.container.logs": RiskLevel.LOW,
        "docker.container.restart": RiskLevel.MEDIUM,
        "docker.container.stop": RiskLevel.HIGH,
    }
    model = broker.resource_attribute_models()[ResourceType.DOCKER_HOST]
    model.model_validate({"endpoint": "tcp://10.0.0.5:2375", "allowed_containers": ["db"]})
    with pytest.raises(ValueError, match="allowed_containers"):
        model.model_validate({"allowed_containers": ["../etc"]})
    with pytest.raises(ValueError, match="endpoint"):
        model.model_validate({"endpoint": "ssh://host"})


async def test_list_shows_only_managed_or_allowlisted(
    broker: DockerBroker, engine: FakeEngine
) -> None:
    result = await broker.container_list(_ctx(), NoParams())
    assert result.ok
    names = [c["names"] for c in result.data["containers"]]
    assert names == [["web"], ["db"]]
    assert result.data["containers"][0]["id"] == MANAGED_ID[:12]
    assert "vault" not in json.dumps(result.data)


async def test_logs_demuxed(broker: DockerBroker, engine: FakeEngine) -> None:
    result = await broker.container_logs(_ctx(), LogsParams(container="web", tail=20))
    assert result.ok
    assert result.data["stdout"] == "hello\n"
    assert result.data["stderr"] == "oops\n"
    logs_request = engine.requests[-1]
    assert logs_request.url.path == f"/containers/{MANAGED_ID}/logs"
    assert logs_request.url.params["tail"] == "20"


async def test_logs_tty_container(broker: DockerBroker) -> None:
    result = await broker.container_logs(_ctx(), LogsParams(container="db"))
    assert result.data["stdout"] == "tty output\n"
    assert result.data["stderr"] == ""


async def test_logs_redact_credential(broker: DockerBroker, engine: FakeEngine) -> None:
    engine.logs[MANAGED_ID] = _frame(1, b"token=tok-very-secret-123\n")
    result = await broker.container_logs(_ctx(TOKEN), LogsParams(container="web"))
    assert result.data["stdout"] == f"token={REDACTED}\n"


async def test_logs_truncated(broker: DockerBroker, engine: FakeEngine) -> None:
    engine.logs[MANAGED_ID] = _frame(1, b"x" * 50_000)
    result = await broker.container_logs(_ctx(output_limit_bytes=1024), LogsParams(container="web"))
    assert result.truncated
    assert len(result.data["stdout"]) == 1024


@pytest.mark.parametrize("container", ["vault", FOREIGN_ID, "missing"])
async def test_unmanaged_or_missing_container_refused(
    broker: DockerBroker, engine: FakeEngine, container: str
) -> None:
    for call in (broker.container_restart, broker.container_stop):
        result = await call(_ctx(), ContainerParams(container=container))
        assert not result.ok
        assert result.error == "container not found or not managed by the gateway"
    result = await broker.container_logs(_ctx(), LogsParams(container=container))
    assert not result.ok
    assert engine.mutating_requests() == []


async def test_restart_uses_resolved_id(broker: DockerBroker, engine: FakeEngine) -> None:
    result = await broker.container_restart(_ctx(), ContainerParams(container="db"))
    assert result.ok
    assert engine.mutating_requests() == [f"/containers/{ALLOWED_ID}/restart"]


async def test_stop_twice(broker: DockerBroker, engine: FakeEngine) -> None:
    first = await broker.container_stop(_ctx(), ContainerParams(container="web"))
    second = await broker.container_stop(_ctx(), ContainerParams(container="web"))
    assert first.data["already_stopped"] is False
    assert second.ok
    assert second.data["already_stopped"] is True


async def test_api_version_and_bearer_token(broker: DockerBroker, engine: FakeEngine) -> None:
    await broker.container_list(_ctx(TOKEN, api_version="v1.43"), NoParams())
    request = engine.requests[-1]
    assert request.url.path == "/v1.43/containers/json"
    assert request.headers["Authorization"] == "Bearer tok-very-secret-123"


async def test_tls_credential_not_supported(broker: DockerBroker, engine: FakeEngine) -> None:
    tls = SecretPayload(CredentialType.DOCKER_TLS, "pem")
    result = await broker.container_list(_ctx(tls), NoParams())
    assert result.error == "credential type 'docker_tls' is not supported for docker"
    assert engine.requests == []


async def test_engine_error_is_safe(broker: DockerBroker, engine: FakeEngine) -> None:
    engine.fail_with = 500
    result = await broker.container_list(_ctx(), NoParams())
    assert result.error == "docker engine returned HTTP 500"


async def test_transport_error_is_wrapped() -> None:
    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no socket")

    broker = DockerBroker(transport_factory=lambda e: httpx.MockTransport(explode))
    result = await broker.container_list(_ctx(), NoParams())
    assert result.error == "docker.container.list failed"


async def test_wrong_resource_type(broker: DockerBroker) -> None:
    ctx = make_ctx(ResourceType.SSH_HOST, {})
    result = await broker.container_list(ctx, NoParams())
    assert result.error == "resource is not a docker_host"


async def test_endpoint_selection() -> None:
    seen: list[str] = []

    def factory(endpoint: str) -> httpx.AsyncBaseTransport:
        seen.append(endpoint)
        return httpx.MockTransport(lambda r: httpx.Response(200, json=[]))

    broker = DockerBroker("unix:///run/docker.sock", transport_factory=factory)
    await broker.container_list(_ctx(), NoParams())
    await broker.container_list(_ctx(endpoint="tcp://10.0.0.5:2375"), NoParams())
    assert seen == ["unix:///run/docker.sock", "tcp://10.0.0.5:2375"]
    assert base_url("unix:///run/docker.sock") == "http://docker"
    assert base_url("tcp://10.0.0.5:2375") == "http://10.0.0.5:2375"
    assert base_url("https://docker.lan:2376") == "https://docker.lan:2376"


def test_demux_handles_partial_frame() -> None:
    raw = _frame(1, b"a") + _frame(2, b"b") + _frame(1, b"cdef")[:-2]
    assert demux_logs(raw) == (b"acd", b"b")


@pytest.mark.parametrize(
    "container", ["../etc", "a/b", "web?all=1", "web#x", "%2e%2e", "web;id", "-web", "", "web\n"]
)
def test_container_param_rejected(broker: DockerBroker, container: str) -> None:
    registry = InMemoryActionRegistry()
    broker.register(registry)
    for action_id in ("docker.container.restart", "docker.container.stop"):
        with pytest.raises(InvalidParamsError):
            registry.validate_params(action_id, {"container": container})


@pytest.mark.parametrize("tail", [0, 501, "10", True])
def test_tail_bounds(broker: DockerBroker, tail: object) -> None:
    registry = InMemoryActionRegistry()
    broker.register(registry)
    with pytest.raises(InvalidParamsError):
        registry.validate_params("docker.container.logs", {"container": "web", "tail": tail})
