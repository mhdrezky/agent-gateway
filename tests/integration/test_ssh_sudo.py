"""The privileged ``ssh.sudo`` action: every layer that grants it can take it away again."""

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from agent_gateway.apps.api_server.app import create_app
from agent_gateway.config import Settings
from agent_gateway.modules.action_registry.models import ActionDefinition, RiskLevel
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.authorization.engine import grants
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.identity.models import TokenKind
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.runtime import Gateway, build_gateway
from tests.integration.test_ssh_runner import SshServer, ssh_server  # noqa: F401 - fixture
from tests.world import NoParams

SUDO = "ssh.sudo"


def test_wildcards_never_grant_a_privileged_action() -> None:
    privileged = ActionDefinition(
        id="ssh.sudo",
        broker="ssh",
        resource_type=ResourceType.SSH_HOST,
        description="x",
        risk=RiskLevel.HIGH,
        input_model=NoParams,
        privileged=True,
    )
    assert not grants(["ssh.*"], privileged)
    assert grants(["ssh.*", "ssh.sudo"], privileged)


def test_privileged_actions_must_be_high_risk() -> None:
    with pytest.raises(ValueError, match="high or critical"):
        ActionDefinition(
            id="ssh.sudo",
            broker="ssh",
            resource_type=ResourceType.SSH_HOST,
            description="x",
            risk=RiskLevel.MEDIUM,
            input_model=NoParams,
            privileged=True,
        )


class Host:
    def __init__(self, gateway: Gateway, api: httpx.AsyncClient, token: str, resource: Resource):
        self.gateway = gateway
        self.api = api
        self.token = token
        self.resource = resource

    async def sudo(self, command: str) -> httpx.Response:
        return await self.api.post(
            "/v1/executions",
            json={"action": SUDO, "resource_id": self.resource.id, "params": {"command": command}},
            headers={"Authorization": f"Bearer {self.token}"},
        )

    async def actions(self) -> list[str]:
        response = await self.api.get(
            "/v1/actions", headers={"Authorization": f"Bearer {self.token}"}
        )
        return [a["id"] for a in response.json()]

    async def set_allow_sudo(self, value: bool) -> None:
        self.resource = await self.gateway.admin.update_resource(
            CLI_PRINCIPAL,
            self.resource.id,
            attributes={**self.resource.attributes, "allow_sudo": value},
        )

    async def set_role(self, *actions: str) -> None:
        await self.gateway.admin.put_role(CLI_PRINCIPAL, Role(id="ops-operator", actions=actions))


@pytest.fixture
async def host(settings: Settings, ssh_server: SshServer) -> AsyncIterator[Host]:  # noqa: F811
    gateway = build_gateway(settings)
    await gateway.start(background=False)
    admin = gateway.admin
    credential = await admin.create_credential(
        CLI_PRINCIPAL,
        "ops-key",
        SecretPayload(
            CredentialType.SSH_PRIVATE_KEY,
            ssh_server.client_key.export_private_key().decode(),
        ),
    )
    resource = await admin.create_resource(
        CLI_PRINCIPAL,
        ResourceType.SSH_HOST,
        "ops-server",
        tags=["env:dev"],
        credential_id=credential.id,
        attributes={
            "host": "127.0.0.1",
            "port": ssh_server.port,
            "username": "agent-gateway",
            "host_key_fingerprint": ssh_server.host_key.get_fingerprint("sha256"),
        },
    )
    await admin.put_role(CLI_PRINCIPAL, Role(id="ops-operator", actions=("ssh.*",)))
    agent = await admin.create_agent(CLI_PRINCIPAL, "ops-agent", roles=["ops-operator"])
    for actions in (["ssh.*"], [SUDO]):
        await admin.create_policy(
            CLI_PRINCIPAL,
            subject=PolicySubject(role="ops-operator"),
            actions=actions,
            resources=ResourceSelector(ids=(resource.id,)),
            effect=PolicyEffect.ALLOW,
            approval=ApprovalMode.NEVER,
        )
    token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.AGENT, agent_id=agent.id)
    api = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(gateway, manage_lifecycle=False)),
        base_url="http://gateway",
    )
    yield Host(gateway, api, token.plaintext.get_secret_value(), resource)
    await api.aclose()
    await gateway.stop()


async def test_every_layer_grants_and_revokes(
    host: Host,
    ssh_server: SshServer,  # noqa: F811
) -> None:
    # 1. "ssh.*" in the role is not enough: privileged actions need their exact name.
    assert SUDO not in await host.actions()
    denied = await host.sudo("id")
    assert denied.status_code == 403

    # 2. Named in the role (and in a policy), but the host has not opted in.
    await host.set_role("ssh.*", SUDO)
    assert SUDO in await host.actions()
    refused: dict[str, Any] = (await host.sudo("id")).json()
    assert refused["status"] == "failed"
    assert "allow_sudo" in refused["error"]
    assert ssh_server.commands == []

    # 3. Host opted in: the command runs as root via sudo -n, shell-quoted as one argument.
    await host.set_allow_sudo(True)
    ran: dict[str, Any] = (await host.sudo("apt-get install -y caddy && echo 'ok'")).json()
    assert ran["status"] == "succeeded", ran
    assert ssh_server.commands[-1] == (
        "sudo -n -- bash -lc 'apt-get install -y caddy && echo '\"'\"'ok'\"'\"''"
    )

    # 4. Revoke on the host flag: refused again at once, nothing reaches the server.
    await host.set_allow_sudo(False)
    assert (await host.sudo("id")).json()["status"] == "failed"
    assert len(ssh_server.commands) == 1

    # 5. Revoke in the role: denied by policy before any broker runs.
    await host.set_allow_sudo(True)
    await host.set_role("ssh.*")
    assert (await host.sudo("id")).status_code == 403
    assert len(ssh_server.commands) == 1


async def test_sudo_needs_approval_by_default(
    settings: Settings,
    ssh_server: SshServer,  # noqa: F811
) -> None:
    """With the default by_risk policy, high-risk ssh.sudo waits for a human."""
    gateway = build_gateway(settings)
    await gateway.start(background=False)
    admin = gateway.admin
    resource = await admin.create_resource(
        CLI_PRINCIPAL,
        ResourceType.SSH_HOST,
        "ops-server",
        attributes={
            "host": "127.0.0.1",
            "port": ssh_server.port,
            "username": "agent-gateway",
            "host_key_fingerprint": ssh_server.host_key.get_fingerprint("sha256"),
            "allow_sudo": True,
        },
    )
    await admin.put_role(CLI_PRINCIPAL, Role(id="ops-operator", actions=(SUDO,)))
    agent = await admin.create_agent(CLI_PRINCIPAL, "ops-agent", roles=["ops-operator"])
    await admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(role="ops-operator"),
        actions=[SUDO],
        resources=ResourceSelector(ids=(resource.id,)),
        effect=PolicyEffect.ALLOW,
    )
    token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.AGENT, agent_id=agent.id)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(gateway, manage_lifecycle=False)),
        base_url="http://gateway",
    ) as api:
        response = await api.post(
            "/v1/executions",
            json={"action": SUDO, "resource_id": resource.id, "params": {"command": "id"}},
            headers={"Authorization": f"Bearer {token.plaintext.get_secret_value()}"},
        )
    await gateway.stop()
    assert response.status_code == 202
    assert response.json()["status"] == "pending_approval"
    assert ssh_server.commands == []
