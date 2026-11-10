"""A gateway set up the way agentgate's console reaches it (SPEC §23).

- agents ``claude-ops`` and ``other-agent`` hold role ``operator`` (agent side), which also
  holds the privileged ``priv.sudo``;
- users: group ``staff`` → role ``staff`` (``fake.*``, ``test.leak``), group
  ``platform-admin`` → role ``platform-admin`` (the access admins, ``admin.user_roles``);
- policy ``staff-echo`` lets ``staff`` use ``fake.*`` on ``echo-endpoint``;
- a ``sql_database`` resource ``sample`` allows table ``customer``; its catalog lists
  ``customer`` and ``product``;
- the IdP directory knows alice (staff), bob (staff + admin), and carol (admin).
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.brokers.sql.broker import SqlBroker
from agent_gateway.config import AdminSettings, DirectorySettings, Settings, UserSettings
from agent_gateway.modules.action_registry.models import (
    ActionDefinition,
    RegisteredAction,
    RiskLevel,
)
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.administration.catalog_port import CatalogActionState, CatalogSummary
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.identity.models import UserMatch
from agent_gateway.modules.resources.models import Resource, ResourceType
from tests.fakes.clock import FixedClock
from tests.fakes.keycloak import BASE_URL, CLIENT_ID, CLIENT_SECRET, REALM, FakeKeycloak, FakeUser
from tests.fakes.oidc import FakeIdp, oidc_settings
from tests.world import USER_HEADER, World, build_world

ADMIN_ROLE = "platform-admin"
ALICE = ("u-alice", ["staff"])
BOB = ("u-bob", ["staff", ADMIN_ROLE])
CAROL = ("u-carol", [ADMIN_ROLE])


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrivBroker:
    """One privileged action, like ``ssh.sudo``."""

    @property
    def name(self) -> str:
        return "priv"

    def resource_attribute_models(self) -> Mapping[ResourceType, type[BaseModel]]:
        return {}

    def register(self, registry: ActionRegistry) -> None:
        registry.register(
            RegisteredAction(
                ActionDefinition(
                    id="priv.sudo",
                    broker="priv",
                    resource_type=ResourceType.HTTP_ENDPOINT,
                    description="Run anything as root.",
                    risk=RiskLevel.HIGH,
                    input_model=NoParams,
                    privileged=True,
                ),
                self._run,
            )
        )

    async def _run(self, ctx: ActionContext, params: Any) -> ActionResult:
        return ActionResult(ok=True)


@dataclass
class FakeCatalog:
    tables_by_resource: dict[str, frozenset[str]] = field(default_factory=dict)

    async def summary(self, resource: Resource) -> CatalogSummary:
        if resource.name in self.tables_by_resource:
            return CatalogSummary(snapshot_id="snap-1", synced_at="2026-11-10T00:00:00.000Z")
        return CatalogSummary()

    async def tables(self, resource: Resource) -> frozenset[str] | None:
        return self.tables_by_resource.get(resource.name)

    async def action_state(self, action_id: str) -> CatalogActionState:
        return "active"

    async def action_resource(self, action_id: str) -> str | None:
        return None


@dataclass
class AccessWorld:
    w: World
    idp: FakeIdp
    idp_admin: FakeKeycloak
    clock: FixedClock
    sample_id: str

    def as_user(self, who: tuple[str, list[str]]) -> dict[str, str]:
        subject, groups = who
        return {**self.w.agent(), USER_HEADER: self.idp.token(subject, groups)}

    def as_user_via_other(self, who: tuple[str, list[str]]) -> dict[str, str]:
        subject, groups = who
        return {**self.w.other(), USER_HEADER: self.idp.token(subject, groups)}


def access_settings(settings: Settings, *, second_admin: bool = False) -> Settings:
    return settings.model_copy(
        update={
            "users": UserSettings(oidc=oidc_settings()),
            "admin": AdminSettings(
                user_roles=[ADMIN_ROLE],
                apply_requires_second_admin=second_admin,
                directory=DirectorySettings(
                    base_url=BASE_URL,
                    realm=REALM,
                    client_id=CLIENT_ID,
                    credential="idp-directory",
                ),
            ),
        }
    )


async def build_access_world(
    settings: Settings,
    *,
    user_approval: ApprovalMode = ApprovalMode.NEVER,
    second_admin: bool = False,
) -> AccessWorld:
    idp = FakeIdp()
    idp_admin = FakeKeycloak(
        users=[
            FakeUser("u-alice", "alice", "Alice", "A", "alice@example.com", ["staff"]),
            FakeUser("u-bob", "bob", "Bob", "B", None, ["staff", ADMIN_ROLE]),
            FakeUser("u-carol", "carol", "Carol", "C", None, [ADMIN_ROLE]),
        ],
        groups=["staff", ADMIN_ROLE],
    )
    clock = FixedClock(datetime.now(UTC))
    w = await build_world(
        access_settings(settings, second_admin=second_admin),
        approval=ApprovalMode.NEVER,
        jwks=idp,
        extra_brokers=[PrivBroker(), SqlBroker()],
        catalog=FakeCatalog({"sample": frozenset({"customer", "product"})}),
        directory_transport=idp_admin.transport(),
        clock=clock,
    )
    admin = w.gateway.admin
    await admin.put_role(
        CLI_PRINCIPAL, Role(id="operator", actions=("fake.*", "test.*", "priv.sudo"))
    )
    await admin.create_policy(
        CLI_PRINCIPAL,
        subject=PolicySubject(role="operator"),
        actions=["priv.sudo"],
        resources=ResourceSelector(ids=(w.resource_id,)),
        effect=PolicyEffect.ALLOW,
        approval=ApprovalMode.ALWAYS,
    )
    await admin.put_role(CLI_PRINCIPAL, Role(id="staff", actions=("fake.*", "test.leak")))
    await admin.put_role(CLI_PRINCIPAL, Role(id=ADMIN_ROLE, description="Access admins"))
    await admin.add_user(CLI_PRINCIPAL, UserMatch(group="staff"), ["staff"])
    await admin.add_user(CLI_PRINCIPAL, UserMatch(group=ADMIN_ROLE), [ADMIN_ROLE])
    await admin.create_policy(
        CLI_PRINCIPAL,
        name="staff-echo",
        subject=PolicySubject(user_role="staff"),
        actions=["fake.*"],
        resources=ResourceSelector(ids=(w.resource_id,)),
        effect=PolicyEffect.ALLOW,
        approval=user_approval,
    )
    await admin.create_credential(
        CLI_PRINCIPAL, "idp-directory", SecretPayload(CredentialType.API_TOKEN, CLIENT_SECRET)
    )
    sample = await admin.create_resource(
        CLI_PRINCIPAL,
        ResourceType.SQL_DATABASE,
        "sample",
        attributes={
            "host": "db.internal",
            "dbname": "sample",
            "username": "reader",
            "allowed_tables": ["customer"],
        },
    )
    return AccessWorld(w=w, idp=idp, idp_admin=idp_admin, clock=clock, sample_id=sample.id)
