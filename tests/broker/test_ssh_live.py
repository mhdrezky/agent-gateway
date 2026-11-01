"""SSH broker against a real openssh-server container. See README.md in this folder."""

import os
from pathlib import Path
from typing import Any

import pytest

from agent_gateway.brokers.ssh import SshBroker
from agent_gateway.brokers.ssh.models import NoParams, ServiceParams
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.resources.models import ResourceType
from tests.unit.broker_support import make_ctx

pytestmark = pytest.mark.broker

REQUIRED = [
    "AGW_TEST_SSH_HOST",
    "AGW_TEST_SSH_PORT",
    "AGW_TEST_SSH_USER",
    "AGW_TEST_SSH_KEY_FILE",
    "AGW_TEST_SSH_FINGERPRINT",
]


@pytest.fixture
def env() -> dict[str, str]:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        pytest.skip(f"missing {', '.join(missing)}")
    return {name: os.environ[name] for name in REQUIRED}


def _ctx(env: dict[str, str], **overrides: Any) -> Any:
    attributes: dict[str, Any] = {
        "host": env["AGW_TEST_SSH_HOST"],
        "port": int(env["AGW_TEST_SSH_PORT"]),
        "username": env["AGW_TEST_SSH_USER"],
        "host_key_fingerprint": env["AGW_TEST_SSH_FINGERPRINT"],
        "allowed_services": ["nginx"],
        **overrides,
    }
    key = Path(env["AGW_TEST_SSH_KEY_FILE"]).read_text(encoding="utf-8")
    credential = SecretPayload(CredentialType.SSH_PRIVATE_KEY, key)
    return make_ctx(ResourceType.SSH_HOST, attributes, credential)


async def test_system_info(env: dict[str, str]) -> None:
    result = await SshBroker().system_info(_ctx(env), NoParams())
    assert result.ok, result.error
    assert "load average" in result.data["uptime"]["stdout"]
    assert result.data["disk"]["stdout"]


async def test_wrong_fingerprint_refused(env: dict[str, str]) -> None:
    ctx = _ctx(env, host_key_fingerprint="SHA256:" + "A" * 43)
    result = await SshBroker().system_info(ctx, NoParams())
    assert not result.ok
    assert result.error == "ssh host key does not match host_key_fingerprint"


async def test_service_status_runs_fixed_command(env: dict[str, str]) -> None:
    result = await SshBroker().service_status(_ctx(env), ServiceParams(service="nginx"))
    # No systemd in the container: the command runs but reports failure.
    assert result.data["exit_code"] is not None
    assert "BEGIN OPENSSH PRIVATE KEY" not in result.model_dump_json()
