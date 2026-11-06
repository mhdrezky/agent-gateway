"""Time-boxed ssh.sudo windows: one approval opens 15 minutes of unattended sudo."""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx
import pytest

from agent_gateway.apps.api_server.app import create_app
from agent_gateway.common.errors import ActionNotAllowedError
from agent_gateway.config import ApprovalSettings, Settings
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.audit.models import AuditEventType
from agent_gateway.modules.authorization.models import (
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.execution.models import Execution, ExecutionRequest, ExecutionStatus
from agent_gateway.modules.identity.models import Principal, TokenKind
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.runtime import Gateway, build_gateway
from tests.fakes.clock import FixedClock
from tests.integration.test_ssh_runner import SshServer, ssh_server  # noqa: F401 - fixture

SUDO = "ssh.sudo"


@dataclass
class Box:
    gateway: Gateway
    clock: FixedClock
    agent: Principal
    agent_token: str
    admin_token: str
    resource: Resource
    other: Resource
    server: SshServer

    async def sudo(self, command: str = "id", resource: Resource | None = None) -> Execution:
        return await self.gateway.engine.submit(
            self.agent,
            ExecutionRequest(
                action=SUDO,
                resource_id=(resource or self.resource).id,
                params={"command": command},
            ),
        )

    async def approve(self, execution: Execution) -> Execution:
        assert execution.approval_id is not None
        await self.gateway.admin.approve(CLI_PRINCIPAL, execution.approval_id)
        await self.gateway.engine.dispatch_approvals()
        await self.gateway.engine.drain()
        return await self.gateway.engine.get(CLI_PRINCIPAL, execution.id)


async def _box(settings: Settings, server: SshServer) -> Box:
    clock = FixedClock()
    gateway = build_gateway(settings, clock=clock)
    await gateway.start(background=False)
    admin = gateway.admin
    credential = await admin.create_credential(
        CLI_PRINCIPAL,
        "box-key",
        SecretPayload(
            CredentialType.SSH_PRIVATE_KEY, server.client_key.export_private_key().decode()
        ),
    )
    attributes: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": server.port,
        "username": "agent-gateway",
        "host_key_fingerprint": server.host_key.get_fingerprint("sha256"),
        "allow_sudo": True,
    }
    resource = await admin.create_resource(
        CLI_PRINCIPAL,
        ResourceType.SSH_HOST,
        "box-server",
        attributes=attributes,
        credential_id=credential.id,
    )
    other = await admin.create_resource(
        CLI_PRINCIPAL,
        ResourceType.SSH_HOST,
        "other-server",
        attributes=attributes,
        credential_id=credential.id,
    )
    await admin.put_role(CLI_PRINCIPAL, Role(id="box-operator", actions=("ssh.*", SUDO)))
    agent = await admin.create_agent(CLI_PRINCIPAL, "box-agent", roles=["box-operator"])
    await admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(role="box-operator"),
        actions=[SUDO],
        resources=ResourceSelector(ids=(resource.id, other.id)),
        effect=PolicyEffect.ALLOW,  # default by_risk: high risk -> approval
    )
    agent_token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.AGENT, agent_id=agent.id)
    admin_token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.ADMIN)
    principal = await gateway.authenticator.authenticate(agent_token.plaintext.get_secret_value())
    return Box(
        gateway,
        clock,
        principal,
        agent_token.plaintext.get_secret_value(),
        admin_token.plaintext.get_secret_value(),
        resource,
        other,
        server,
    )


@pytest.fixture
async def box(settings: Settings, ssh_server: SshServer) -> AsyncIterator[Box]:  # noqa: F811
    b = await _box(settings, ssh_server)
    yield b
    await b.gateway.stop()


async def test_one_approval_opens_a_fifteen_minute_window(box: Box) -> None:
    first = await box.sudo("apt-get update")
    assert first.status is ExecutionStatus.PENDING_APPROVAL
    assert box.server.commands == []

    done = await box.approve(first)
    assert done.status is ExecutionStatus.SUCCEEDED
    [window] = await box.gateway.admin.list_elevations(CLI_PRINCIPAL)
    assert window.expires_at - window.granted_at == timedelta(minutes=15)
    assert window.approval_id == first.approval_id

    second = await box.sudo("apt-get install -y caddy")
    assert second.status is ExecutionStatus.SUCCEEDED
    assert second.approval_id is None
    assert second.decision is not None
    assert "elevated by" in second.decision.reason
    assert len(box.server.commands) == 2

    box.clock.advance(timedelta(minutes=14, seconds=59))
    assert (await box.sudo("true")).status is ExecutionStatus.SUCCEEDED

    box.clock.advance(timedelta(seconds=2))  # 15:01 after approval
    after = await box.sudo("true")
    assert after.status is ExecutionStatus.PENDING_APPROVAL
    assert len(box.server.commands) == 3


async def test_closing_the_window_early(box: Box) -> None:
    await box.approve(await box.sudo())
    [window] = await box.gateway.admin.list_elevations(CLI_PRINCIPAL)
    await box.gateway.admin.revoke_elevation(CLI_PRINCIPAL, window.id)
    assert (await box.sudo()).status is ExecutionStatus.PENDING_APPROVAL
    events = [e.event for e in await box.gateway.audit.query()]
    assert AuditEventType.ELEVATION_GRANTED in events
    assert AuditEventType.ELEVATION_REVOKED in events


async def test_window_covers_only_its_resource(box: Box) -> None:
    await box.approve(await box.sudo())
    elsewhere = await box.sudo(resource=box.other)
    assert elsewhere.status is ExecutionStatus.PENDING_APPROVAL


async def test_window_never_overrides_other_layers(box: Box) -> None:
    await box.approve(await box.sudo())

    # Host switch off: the broker still refuses inside the window.
    box.resource = await box.gateway.admin.update_resource(
        CLI_PRINCIPAL, box.resource.id, attributes={**box.resource.attributes, "allow_sudo": False}
    )
    refused = await box.sudo()
    assert refused.status is ExecutionStatus.FAILED
    assert refused.error is not None
    assert "allow_sudo" in refused.error

    # Role no longer names ssh.sudo: denied before any window is considered.
    await box.gateway.admin.put_role(CLI_PRINCIPAL, Role(id="box-operator", actions=("ssh.*",)))
    box.agent = await box.gateway.authenticator.authenticate(box.agent_token)
    with pytest.raises(ActionNotAllowedError):
        await box.sudo()


async def test_manual_window_from_the_admin(box: Box) -> None:
    await box.gateway.admin.grant_elevation(
        CLI_PRINCIPAL,
        agent_id=box.agent.agent_id or "",
        resource_id=box.resource.id,
        action=SUDO,
        minutes=5,
    )
    assert (await box.sudo()).status is ExecutionStatus.SUCCEEDED
    box.clock.advance(timedelta(minutes=5))
    assert (await box.sudo()).status is ExecutionStatus.PENDING_APPROVAL


async def test_zero_minutes_means_approve_every_command(
    settings: Settings,
    ssh_server: SshServer,  # noqa: F811
) -> None:
    b = await _box(
        settings.model_copy(update={"approvals": ApprovalSettings(elevation_minutes=0)}),
        ssh_server,
    )
    try:
        await b.approve(await b.sudo())
        assert await b.gateway.admin.list_elevations(CLI_PRINCIPAL) == []
        assert (await b.sudo()).status is ExecutionStatus.PENDING_APPROVAL
    finally:
        await b.gateway.stop()


async def test_admin_ui_shows_and_ends_the_window(box: Box) -> None:
    await box.approve(await box.sudo())
    app = create_app(box.gateway, manage_lifecycle=False)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8080"
    ) as ui:
        await ui.post("/admin/login", data={"token": box.admin_token})
        page = (await ui.get("/admin/approvals")).text
        assert "Open sudo windows" in page
        assert "15 min left" in page
        [window] = await box.gateway.admin.list_elevations(CLI_PRINCIPAL)
        csrf = page.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        ended = await ui.post(f"/admin/elevations/{window.id}/revoke", data={"csrf": csrf})
        assert ended.status_code == 303
    assert await box.gateway.admin.list_elevations(CLI_PRINCIPAL) == []
