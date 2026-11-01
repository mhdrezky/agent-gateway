"""SSH runner against an in-process asyncssh server: host key pinning and exact commands."""

from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import asyncssh
import pytest

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.ssh import SshBroker
from agent_gateway.brokers.ssh.models import ServiceParams, SshHostAttributes
from agent_gateway.brokers.ssh.runner import AsyncsshRunner
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.resources.models import ResourceType
from tests.unit.broker_support import make_ctx


@dataclass
class SshServer:
    port: int
    host_key: asyncssh.SSHKey
    client_key: asyncssh.SSHKey
    commands: list[str | None] = field(default_factory=list)

    def attributes(self, **overrides: object) -> SshHostAttributes:
        values: dict[str, object] = {
            "host": "127.0.0.1",
            "port": self.port,
            "username": "deploy",
            "host_key_fingerprint": self.host_key.get_fingerprint("sha256"),
            "allowed_services": ["nginx"],
        }
        values.update(overrides)
        return SshHostAttributes.model_validate(values)

    def credential(self, key: asyncssh.SSHKey | None = None) -> SecretPayload:
        pem = (key or self.client_key).export_private_key().decode()
        return SecretPayload(CredentialType.SSH_PRIVATE_KEY, pem)


@pytest.fixture
async def ssh_server() -> AsyncIterator[SshServer]:
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    # Real servers (e.g. OpenSSH) also offer an RSA key, and prefer it by default.
    rsa_host_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    commands: list[str | None] = []

    async def handle(process: asyncssh.SSHServerProcess[str]) -> None:
        commands.append(process.command)
        process.stdout.write(f"ran {process.command}\n")
        process.exit(0)

    acceptor = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_host_keys=[rsa_host_key, host_key],
        authorized_client_keys=asyncssh.import_authorized_keys(
            client_key.export_public_key().decode()
        ),
        process_factory=handle,
    )
    try:
        server = SshServer(acceptor.get_port(), host_key, client_key, commands)
        yield server
    finally:
        acceptor.close()
        await acceptor.wait_closed()


async def test_pinned_fingerprint_connects_and_runs_exact_command(ssh_server: SshServer) -> None:
    outputs = await AsyncsshRunner().run(
        ssh_server.attributes(), ssh_server.credential(), ["systemctl status -- nginx"]
    )
    assert ssh_server.commands == ["systemctl status -- nginx"]
    assert outputs[0].exit_code == 0
    assert outputs[0].stdout == "ran systemctl status -- nginx\n"


async def test_wrong_fingerprint_is_refused(ssh_server: SshServer) -> None:
    other = asyncssh.generate_private_key("ssh-ed25519").get_fingerprint("sha256")
    with pytest.raises(BrokerError, match="host key does not match"):
        await AsyncsshRunner().run(
            ssh_server.attributes(host_key_fingerprint=other), ssh_server.credential(), ["uptime"]
        )
    assert ssh_server.commands == []


async def test_wrong_client_key_is_refused(ssh_server: SshServer) -> None:
    stranger = asyncssh.generate_private_key("ssh-ed25519")
    with pytest.raises(BrokerError, match="authentication failed"):
        await AsyncsshRunner().run(
            ssh_server.attributes(), ssh_server.credential(stranger), ["uptime"]
        )


async def test_missing_or_bad_credential(ssh_server: SshServer) -> None:
    with pytest.raises(BrokerError, match="ssh_private_key"):
        await AsyncsshRunner().run(ssh_server.attributes(), None, ["uptime"])
    junk = SecretPayload(CredentialType.SSH_PRIVATE_KEY, "not a key")
    with pytest.raises(BrokerError, match="not a usable private key"):
        await AsyncsshRunner().run(ssh_server.attributes(), junk, ["uptime"])


async def test_connection_refused() -> None:
    attrs = SshHostAttributes.model_validate(
        {
            "host": "127.0.0.1",
            "port": 1,
            "username": "deploy",
            "host_key_fingerprint": "SHA256:" + "A" * 43,
        }
    )
    key = asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()
    with pytest.raises(BrokerError, match="connection failed"):
        await AsyncsshRunner().run(
            attrs, SecretPayload(CredentialType.SSH_PRIVATE_KEY, key), ["uptime"]
        )


async def test_broker_end_to_end_quotes(ssh_server: SshServer) -> None:
    ctx = make_ctx(
        ResourceType.SSH_HOST,
        ssh_server.attributes(allowed_services=["nginx@1.service"]).model_dump(),
        ssh_server.credential(),
    )
    result = await SshBroker().service_restart(ctx, ServiceParams(service="nginx@1.service"))
    assert result.ok, result.error
    assert ssh_server.commands == ["systemctl restart -- nginx@1.service"]


async def test_pinned_rsa_key_is_requested_by_algorithm(ssh_server: SshServer) -> None:
    attrs = ssh_server.attributes(host_key_algorithm="rsa-sha2-256")
    with pytest.raises(BrokerError, match="host key"):
        # The fingerprint is of the ed25519 key, so asking for RSA must fail closed.
        await AsyncsshRunner().run(attrs, ssh_server.credential(), ["true"])
