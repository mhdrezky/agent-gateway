"""A real gateway on a temp ``var/`` with fake brokers, driven through the REST API."""

import asyncio
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, ConfigDict

from agent_gateway.apps.api_server.app import create_app
from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.config import RateLimitSettings, Settings, UserSettings
from agent_gateway.modules.action_registry.models import (
    ActionDefinition,
    RegisteredAction,
    RiskLevel,
)
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.crypto.keyring import generate_master_key
from agent_gateway.modules.identity.models import TokenKind, UserMatch
from agent_gateway.modules.identity.users import JwksSource
from agent_gateway.modules.resources.models import ResourceType
from agent_gateway.runtime import Gateway, build_gateway
from tests.fakes.brokers import FakeBroker
from tests.fakes.oidc import FakeIdp, oidc_settings

SECRET = "s3cr3t-api-token-value"
USER_HEADER = "x-user-token"


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SleepParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seconds: float


class TestBroker:
    """Extra fake actions: one that leaks its credential, one that sleeps."""

    __test__ = False

    @property
    def name(self) -> str:
        return "test"

    def resource_attribute_models(self) -> Mapping[ResourceType, type[BaseModel]]:
        return {}

    def register(self, registry: ActionRegistry) -> None:
        registry.register(
            RegisteredAction(
                ActionDefinition(
                    id="test.leak",
                    broker="test",
                    resource_type=ResourceType.HTTP_ENDPOINT,
                    description="Echo the credential back (a broken broker).",
                    risk=RiskLevel.LOW,
                    input_model=NoParams,
                    read_only=True,
                ),
                self._leak,
            )
        )
        registry.register(
            RegisteredAction(
                ActionDefinition(
                    id="test.sleep",
                    broker="test",
                    resource_type=ResourceType.HTTP_ENDPOINT,
                    description="Sleep, to test timeouts.",
                    risk=RiskLevel.LOW,
                    input_model=SleepParams,
                    timeout_seconds=1,
                    read_only=True,
                ),
                self._sleep,
            )
        )

    async def _leak(self, ctx: ActionContext, params: Any) -> ActionResult:
        assert ctx.credential is not None
        return ActionResult(ok=True, data={"leaked": f"value={ctx.credential.reveal()}"})

    async def _sleep(self, ctx: ActionContext, params: Any) -> ActionResult:
        await asyncio.sleep(params.seconds)
        return ActionResult(ok=True)


@dataclass
class World:
    gateway: Gateway
    fake: FakeBroker
    api: httpx.AsyncClient
    agent_id: str
    agent_token: str
    other_token: str
    admin_token: str
    resource_id: str
    master_key: str

    def agent(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.agent_token}"}

    def other(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.other_token}"}

    def admin(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.admin_token}"}


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    key_file = tmp_path / "master.key"
    key_file.write_text(generate_master_key(), encoding="ascii")
    return Settings(
        var_dir=tmp_path / "var",
        master_key_file=key_file,
        rate_limit=RateLimitSettings(auth_failures_per_minute=5),
    )


async def build_world(
    settings: Settings, *, approval: ApprovalMode, jwks: JwksSource | None = None
) -> World:
    fake = FakeBroker()
    gateway = build_gateway(settings, brokers=[fake, TestBroker()], jwks=jwks)
    await gateway.start(background=False)
    admin = gateway.admin

    await admin.put_role(CLI_PRINCIPAL, Role(id="operator", actions=("fake.*", "test.*")))
    agent = await admin.create_agent(CLI_PRINCIPAL, "claude-ops", roles=["operator"])
    other = await admin.create_agent(CLI_PRINCIPAL, "other-agent", roles=["operator"])
    credential = await admin.create_credential(
        CLI_PRINCIPAL, "api token", SecretPayload(CredentialType.API_TOKEN, SECRET)
    )
    resource = await admin.create_resource(
        CLI_PRINCIPAL,
        ResourceType.HTTP_ENDPOINT,
        "echo-endpoint",
        tags=["env:test"],
        attributes={"host": "echo.internal"},
        credential_id=credential.id,
    )
    await admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(role="operator"),
        actions=["fake.*", "test.*"],
        resources=ResourceSelector(ids=(resource.id,)),
        effect=PolicyEffect.ALLOW,
        approval=approval,
    )
    agent_token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.AGENT, agent_id=agent.id)
    other_token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.AGENT, agent_id=other.id)
    admin_token = await admin.issue_token(CLI_PRINCIPAL, TokenKind.ADMIN)

    app = create_app(gateway, manage_lifecycle=False)
    api = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway")
    return World(
        gateway=gateway,
        fake=fake,
        api=api,
        agent_id=agent.id,
        agent_token=agent_token.plaintext.get_secret_value(),
        other_token=other_token.plaintext.get_secret_value(),
        admin_token=admin_token.plaintext.get_secret_value(),
        resource_id=resource.id,
        master_key=settings.master_key_file.read_text(encoding="ascii").strip(),
    )


@pytest.fixture
async def world(settings: Settings) -> AsyncIterator[World]:
    w = await build_world(settings, approval=ApprovalMode.NEVER)
    yield w
    await w.api.aclose()
    await w.gateway.stop()


@pytest.fixture
async def approval_world(settings: Settings) -> AsyncIterator[World]:
    w = await build_world(settings, approval=ApprovalMode.ALWAYS)
    yield w
    await w.api.aclose()
    await w.gateway.stop()


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
async def user_world(settings: Settings, idp: FakeIdp) -> AsyncIterator[World]:
    """``world`` plus OIDC users: group ``staff`` gets role ``staff`` (``fake.*`` on the
    endpoint), so a staff user may run ``fake.echo`` but not ``test.*``.
    """
    configured = settings.model_copy(update={"users": UserSettings(oidc=oidc_settings())})
    w = await build_world(configured, approval=ApprovalMode.NEVER, jwks=idp)
    admin = w.gateway.admin
    await admin.add_user(CLI_PRINCIPAL, UserMatch(group="staff"), ["staff"])
    await admin.put_role(CLI_PRINCIPAL, Role(id="staff", actions=("fake.*",)))
    await admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(user_role="staff"),
        actions=["fake.*"],
        resources=ResourceSelector(ids=(w.resource_id,)),
        effect=PolicyEffect.ALLOW,
        approval=ApprovalMode.NEVER,
    )
    yield w
    await w.api.aclose()
    await w.gateway.stop()
