"""Composition root: builds every module from settings and wires them together.

This is the only place that knows the concrete classes. The API server, the CLI, and the
tests all get a ``Gateway`` from ``build_gateway``.
"""

import asyncio
import contextlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from pydantic import BaseModel

from agent_gateway.brokers.base import Broker
from agent_gateway.brokers.docker.broker import DockerBroker
from agent_gateway.brokers.smtp.broker import SmtpBroker
from agent_gateway.brokers.sql.broker import SqlBroker
from agent_gateway.brokers.ssh.broker import SshBroker
from agent_gateway.common.clock import Clock, SystemClock
from agent_gateway.config import Settings
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.modules.administration.service import AdminService
from agent_gateway.modules.approvals.models import Approval
from agent_gateway.modules.approvals.service import ApprovalWorkflow
from agent_gateway.modules.audit.file_log import FileAuditLog
from agent_gateway.modules.authorization.engine import DefaultPolicyEngine
from agent_gateway.modules.authorization.models import Policy, Role
from agent_gateway.modules.credentials.models import CredentialMeta
from agent_gateway.modules.credentials.store import EncryptedCredentialStore
from agent_gateway.modules.crypto.envelope import AesGcmEnvelopeCipher
from agent_gateway.modules.crypto.keyring import MasterKeyRing
from agent_gateway.modules.crypto.ports import KeyRing
from agent_gateway.modules.elevation.models import Elevation
from agent_gateway.modules.elevation.service import ElevationService
from agent_gateway.modules.execution.engine import GatewayExecutionEngine
from agent_gateway.modules.execution.store import FileExecutionStore
from agent_gateway.modules.identity.authenticator import TokenAuthenticator
from agent_gateway.modules.identity.models import Agent, Token, User
from agent_gateway.modules.identity.service import IdentityManager
from agent_gateway.modules.identity.users import JwksSource, UserDirectory, build_user_directory
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.modules.resources.registry import StoredResourceRegistry
from agent_gateway.modules.storage.atomic import cleanup_stale_temp_files
from agent_gateway.modules.storage.blob_store import FileBlobStore
from agent_gateway.modules.storage.json_collection import JsonCollection
from agent_gateway.modules.storage.locking import FileLocker

DISPATCH_INTERVAL_SECONDS = 2.0

log = logging.getLogger("agent_gateway")


class _Checkable(Protocol):
    async def check(self) -> None: ...


@dataclass
class Gateway:
    settings: Settings
    clock: Clock
    collections: list[_Checkable]
    registry: InMemoryActionRegistry
    audit: FileAuditLog
    authenticator: TokenAuthenticator
    users: UserDirectory
    identity: IdentityManager
    engine: GatewayExecutionEngine
    admin: AdminService
    _dispatcher: asyncio.Task[None] | None = field(default=None, init=False)

    async def start(self, *, background: bool = True) -> None:
        """Validate storage, clean up crash leftovers, recover executions, start dispatcher."""
        for collection in self.collections:
            await collection.check()
        await asyncio.to_thread(cleanup_stale_temp_files, self.settings.var_dir)
        for action_id in self.registry.unknown_disabled():
            log.warning("actions.disabled names an unknown action: %s", action_id)
        await self.engine.recover()
        if background:
            self._dispatcher = asyncio.create_task(self._dispatch_loop())

    async def stop(self) -> None:
        if self._dispatcher is not None:
            self._dispatcher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._dispatcher
            self._dispatcher = None
        await self.engine.drain()

    async def _dispatch_loop(self) -> None:
        while True:
            try:
                await self.engine.dispatch_approvals()
            except Exception:
                log.exception("approval dispatch failed")
            await asyncio.sleep(DISPATCH_INTERVAL_SECONDS)


def default_brokers(settings: Settings) -> list[Broker]:
    brokers: list[Broker] = [SshBroker()]
    if settings.brokers.docker.enabled:
        brokers.append(DockerBroker(default_endpoint=settings.brokers.docker.socket))
    if settings.brokers.sql.enabled:
        brokers.append(SqlBroker())
    if settings.brokers.smtp.enabled:
        brokers.append(SmtpBroker())
    return brokers


def build_gateway(
    settings: Settings,
    *,
    brokers: Sequence[Broker] | None = None,
    keyring: KeyRing | None = None,
    clock: Clock | None = None,
    jwks: JwksSource | None = None,
) -> Gateway:
    clock = clock or SystemClock()
    keyring = keyring or MasterKeyRing.from_file(settings.master_key_file)
    var = settings.var_dir
    locker = FileLocker(var / ".locks")

    agents = JsonCollection(var / "agents.json", Agent, locker=locker, clock=clock)
    tokens = JsonCollection(var / "tokens.json", Token, locker=locker, clock=clock)
    roles = JsonCollection(var / "roles.json", Role, locker=locker, clock=clock)
    policies = JsonCollection(var / "policies.json", Policy, locker=locker, clock=clock)
    credential_meta = JsonCollection(
        var / "credentials.json", CredentialMeta, locker=locker, clock=clock
    )
    approvals_data = JsonCollection(var / "approvals.json", Approval, locker=locker, clock=clock)
    elevations_data = JsonCollection(var / "elevations.json", Elevation, locker=locker, clock=clock)

    resources_data = JsonCollection(var / "resources.json", Resource, locker=locker, clock=clock)
    users_data = JsonCollection(var / "users.json", User, locker=locker, clock=clock)

    registry = InMemoryActionRegistry(disabled=settings.actions.disabled)
    schemas: dict[ResourceType, type[BaseModel]] = {}
    for broker in brokers if brokers is not None else default_brokers(settings):
        broker.register(registry)
        schemas.update(broker.resource_attribute_models())

    audit = FileAuditLog(var / "audit", locker, clock)
    identity = IdentityManager(agents, tokens, keyring, clock=clock)
    authenticator = TokenAuthenticator(agents, tokens, keyring, clock=clock)
    users = build_user_directory(users_data, settings.users.oidc, source=jwks, clock=clock)
    resources = StoredResourceRegistry(resources_data, schemas)
    credentials = EncryptedCredentialStore(
        credential_meta,
        FileBlobStore(var / "credentials", locker=locker),
        AesGcmEnvelopeCipher.for_credentials(keyring),
        locker=locker,
        clock=clock,
    )
    approvals = ApprovalWorkflow(approvals_data, audit, clock, settings.approvals)
    elevations = ElevationService(elevations_data, audit, clock)
    engine = GatewayExecutionEngine(
        executions=FileExecutionStore(var / "executions", locker=locker),
        registry=registry,
        resources=resources,
        credentials=credentials,
        roles=roles,
        policies=policies,
        policy_engine=DefaultPolicyEngine(),
        approvals=approvals,
        audit=audit,
        clock=clock,
        settings=settings.execution,
        elevations=elevations,
        elevation_minutes=settings.approvals.elevation_minutes,
    )
    admin = AdminService(
        identity=identity,
        resources=resources,
        credentials=credentials,
        roles=roles,
        policies=policies,
        approvals=approvals,
        audit=audit,
        clock=clock,
        elevations=elevations,
        users=users_data,
    )
    return Gateway(
        settings=settings,
        clock=clock,
        collections=[
            agents,
            tokens,
            roles,
            policies,
            credential_meta,
            approvals_data,
            resources_data,
            elevations_data,
            users_data,
        ],
        registry=registry,
        audit=audit,
        authenticator=authenticator,
        users=users,
        identity=identity,
        engine=engine,
        admin=admin,
    )
