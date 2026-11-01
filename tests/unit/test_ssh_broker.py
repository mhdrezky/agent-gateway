import asyncio
import shlex
from collections.abc import Sequence
from typing import Any

import pytest

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.ssh import SshBroker
from agent_gateway.brokers.ssh.models import (
    LogsParams,
    NoParams,
    ServiceParams,
    SshHostAttributes,
)
from agent_gateway.brokers.ssh.runner import CommandOutput
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.modules.credentials.models import REDACTED, CredentialType, SecretPayload
from agent_gateway.modules.resources.models import ResourceType
from tests.fakes.registry import FakeActionRegistry
from tests.unit.broker_support import make_ctx, ssh_attributes

KEY = SecretPayload(
    CredentialType.SSH_PRIVATE_KEY,
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"
    "-----END OPENSSH PRIVATE KEY-----\n",
    {"passphrase": "hunter2-passphrase"},
)


class RecordingRunner:
    def __init__(self, *outputs: CommandOutput, error: Exception | None = None) -> None:
        self.outputs = list(outputs)
        self.error = error
        self.commands: list[str] = []
        self.attrs: list[SshHostAttributes] = []

    async def run(
        self,
        attrs: SshHostAttributes,
        credential: SecretPayload | None,
        commands: Sequence[str],
    ) -> list[CommandOutput]:
        if self.error is not None:
            raise self.error
        self.attrs.append(attrs)
        self.commands.extend(commands)
        return [
            self.outputs[i] if i < len(self.outputs) else CommandOutput(0, "", "")
            for i in range(len(commands))
        ]


def _ctx(**kwargs: Any) -> Any:
    attrs = kwargs.pop("attrs", ssh_attributes())
    return make_ctx(ResourceType.SSH_HOST, attrs, kwargs.pop("credential", KEY), **kwargs)


def test_registers_actions_with_spec_risks() -> None:
    registry = InMemoryActionRegistry()
    SshBroker(RecordingRunner()).register(registry)
    risks = {a.definition.id: a.definition.risk for a in registry.all()}
    assert risks == {
        "ssh.logs.tail": RiskLevel.LOW,
        "ssh.service.restart": RiskLevel.MEDIUM,
        "ssh.service.status": RiskLevel.LOW,
        "ssh.system.info": RiskLevel.LOW,
        "ssh.sudo": RiskLevel.HIGH,
    }
    privileged = [a.definition.id for a in registry.all() if a.definition.privileged]
    assert privileged == ["ssh.sudo"]
    assert all(a.definition.resource_type is ResourceType.SSH_HOST for a in registry.all())


def test_resource_attribute_schema() -> None:
    models = SshBroker().resource_attribute_models()
    model = models[ResourceType.SSH_HOST]
    model.model_validate(ssh_attributes())
    with pytest.raises(ValueError, match="host_key_fingerprint"):
        model.model_validate(
            {k: v for k, v in ssh_attributes().items() if k != "host_key_fingerprint"}
        )
    with pytest.raises(ValueError, match="Extra inputs"):
        model.model_validate(ssh_attributes(password="x"))
    with pytest.raises(ValueError, match="allowed_services"):
        model.model_validate(ssh_attributes(allowed_services=["nginx; reboot"]))


async def test_service_restart_runs_quoted_template() -> None:
    runner = RecordingRunner(CommandOutput(0, "", ""))
    result = await SshBroker(runner).service_restart(_ctx(), ServiceParams(service="nginx"))
    assert result.ok
    assert runner.commands == ["systemctl restart -- nginx"]


async def test_service_restart_with_sudo() -> None:
    runner = RecordingRunner()
    ctx = _ctx(attrs=ssh_attributes(use_sudo=True))
    await SshBroker(runner).service_restart(ctx, ServiceParams(service="app"))
    assert shlex.split(runner.commands[0]) == ["sudo", "-n", "systemctl", "restart", "--", "app"]


async def test_service_not_in_allowlist_is_rejected_without_running() -> None:
    runner = RecordingRunner()
    result = await SshBroker(runner).service_restart(_ctx(), ServiceParams(service="sshd"))
    assert not result.ok
    assert result.error is not None
    assert "allowed_services" in result.error
    assert runner.commands == []


async def test_service_status_inactive_is_ok() -> None:
    runner = RecordingRunner(CommandOutput(3, "inactive (dead)", ""))
    result = await SshBroker(runner).service_status(_ctx(), ServiceParams(service="nginx"))
    assert result.ok
    assert result.data["active"] is False
    assert result.data["exit_code"] == 3
    assert runner.commands == ["systemctl status --no-pager -- nginx"]


async def test_service_status_missing_unit_is_not_ok() -> None:
    runner = RecordingRunner(CommandOutput(4, "", "Unit x not found"))
    result = await SshBroker(runner).service_status(_ctx(), ServiceParams(service="nginx"))
    assert not result.ok


async def test_logs_tail_command() -> None:
    runner = RecordingRunner(CommandOutput(0, "line\n", ""))
    result = await SshBroker(runner).logs_tail(_ctx(), LogsParams(service="app", lines=50))
    assert result.ok
    assert shlex.split(runner.commands[0]) == [
        "journalctl",
        "--no-pager",
        "-o",
        "short-iso",
        "-u",
        "app",
        "-n",
        "50",
    ]


async def test_system_info_runs_fixed_commands() -> None:
    runner = RecordingRunner(
        CommandOutput(0, "up 3 days", ""), CommandOutput(0, "disk", ""), CommandOutput(0, "mem", "")
    )
    result = await SshBroker(runner).system_info(_ctx(), NoParams())
    assert result.ok
    assert runner.commands == ["uptime", "df -hP", "free -b"]
    assert result.data["uptime"]["stdout"] == "up 3 days"
    assert set(result.data) == {"uptime", "disk", "memory"}


async def test_output_redacts_credential() -> None:
    leaked = f"key={KEY.reveal()} pass=hunter2-passphrase line=b3BlbnNzaC1rZXktdjEAAAAABG5vbmU"
    runner = RecordingRunner(CommandOutput(0, leaked, "hunter2-passphrase"))
    result = await SshBroker(runner).logs_tail(_ctx(), LogsParams(service="nginx"))
    dumped = result.model_dump_json()
    assert "hunter2" not in dumped
    assert "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU" not in dumped
    assert REDACTED in result.data["stdout"]
    assert result.data["stderr"] == REDACTED


async def test_output_truncated_to_limit() -> None:
    runner = RecordingRunner(CommandOutput(0, "x" * 3000, "y" * 3000))
    ctx = _ctx(output_limit_bytes=4096)
    result = await SshBroker(runner).logs_tail(ctx, LogsParams(service="nginx"))
    assert result.truncated
    total = len(result.data["stdout"].encode()) + len(result.data["stderr"].encode())
    assert total == 4096


async def test_runner_error_message_is_safe() -> None:
    runner = RecordingRunner(error=BrokerError("ssh host key does not match host_key_fingerprint"))
    result = await SshBroker(runner).system_info(_ctx(), NoParams())
    assert result == result.model_copy(
        update={"ok": False, "error": "ssh host key does not match host_key_fingerprint"}
    )


async def test_unexpected_error_is_wrapped(caplog: pytest.LogCaptureFixture) -> None:
    runner = RecordingRunner(error=RuntimeError("internal detail /etc/secret"))
    result = await SshBroker(runner).system_info(_ctx(), NoParams())
    assert not result.ok
    assert result.error == "ssh.system.info failed"
    assert "internal detail" in caplog.text


async def test_timeout() -> None:
    class SlowRunner(RecordingRunner):
        async def run(self, *args: Any) -> list[CommandOutput]:
            await asyncio.sleep(5)
            return []

    ctx = _ctx(timeout_seconds=1)
    result = await asyncio.wait_for(SshBroker(SlowRunner()).system_info(ctx, NoParams()), timeout=3)
    assert result.error == "ssh.system.info timed out"


async def test_invalid_resource_attributes() -> None:
    runner = RecordingRunner()
    ctx = _ctx(attrs={"host": "x"})
    result = await SshBroker(runner).system_info(ctx, NoParams())
    assert result.error == "ssh_host resource attributes are invalid"


async def test_wrong_resource_type() -> None:
    ctx = make_ctx(ResourceType.DOCKER_HOST, ssh_attributes(), KEY)
    result = await SshBroker(RecordingRunner()).system_info(ctx, NoParams())
    assert result.error == "resource is not an ssh_host"


def test_works_with_fake_registry() -> None:
    registry = FakeActionRegistry()
    SshBroker().register(registry)
    params = registry.validate_params("ssh.logs.tail", {"service": "nginx"})
    assert params == LogsParams(service="nginx", lines=100)
