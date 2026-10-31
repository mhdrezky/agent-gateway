"""The fakes must honour the same contracts as the real implementations."""

from datetime import timedelta

import pytest

from agent_gateway.common.errors import (
    ActionNotFoundError,
    AuditUnavailableError,
    CredentialNotFoundError,
    InvalidParamsError,
)
from agent_gateway.modules.audit.models import Actor, ActorType, AuditEventType, AuditRecord
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.storage.ports import Collection
from tests.contracts.collection import CollectionContract, Item
from tests.fakes.audit import FakeAuditLog
from tests.fakes.brokers import FakeBroker
from tests.fakes.clock import FixedClock
from tests.fakes.credentials import FakeCredentialStore
from tests.fakes.registry import FakeActionRegistry
from tests.fakes.storage import InMemoryBlobStore, InMemoryCollection


class TestInMemoryCollection(CollectionContract):
    @pytest.fixture
    def collection(self) -> Collection[Item]:
        return InMemoryCollection[Item]()


async def test_blob_store_round_trip() -> None:
    store = InMemoryBlobStore()
    await store.write("x.bin", b"\x00\x01")
    assert await store.read("x.bin") == b"\x00\x01"
    assert await store.delete("x.bin") is True
    assert await store.read("x.bin") is None


async def test_credential_store_rotate_and_open() -> None:
    store = FakeCredentialStore()
    meta = await store.create("key", SecretPayload(CredentialType.API_TOKEN, "s3cret"))
    rotated = await store.rotate(meta.id, SecretPayload(CredentialType.API_TOKEN, "n3w"))
    assert rotated.version == 2
    opened = await store.open(meta.id)
    assert opened.reveal() == "n3w"
    with pytest.raises(CredentialNotFoundError):
        await store.open("cred_missing")


def _record(event: AuditEventType = AuditEventType.AGENT_CREATED) -> AuditRecord:
    return AuditRecord(event=event, actor=Actor(type=ActorType.SYSTEM, id="test"))


async def test_audit_chain_verifies_and_detects_tampering() -> None:
    log = FakeAuditLog(FixedClock())
    for _ in range(3):
        await log.append(_record())
    assert (await log.verify()).ok

    log.entries[1] = log.entries[1].model_copy(
        update={"actor": Actor(type=ActorType.ADMIN, id="x")}
    )
    result = await log.verify()
    assert not result.ok
    assert result.first_bad_seq == 2


async def test_audit_fail_closed() -> None:
    log = FakeAuditLog()
    log.fail_writes = True
    with pytest.raises(AuditUnavailableError):
        await log.append(_record())


async def test_audit_query_filters() -> None:
    clock = FixedClock()
    log = FakeAuditLog(clock)
    await log.append(_record(AuditEventType.AGENT_CREATED))
    clock.advance(timedelta(minutes=1))
    await log.append(_record(AuditEventType.TOKEN_CREATED))
    assert len(await log.query(event=AuditEventType.TOKEN_CREATED)) == 1
    assert len(await log.query(since=clock.now())) == 1


def test_fake_registry_validates_params() -> None:
    registry = FakeActionRegistry()
    FakeBroker().register(registry)
    with pytest.raises(ValueError, match="already registered"):
        FakeBroker().register(registry)
    with pytest.raises(ActionNotFoundError):
        registry.validate_params("fake.missing", {})
    with pytest.raises(InvalidParamsError):
        registry.validate_params("fake.echo", {"message": "hi", "extra": 1})
    assert registry.validate_params("fake.echo", {"message": "hi"}).model_dump() == {
        "message": "hi"
    }


def test_fakes_satisfy_contracts() -> None:
    """Checked by mypy: each fake is assignable to the protocol it stands in for."""
    from agent_gateway.brokers.base import Broker
    from agent_gateway.common.clock import Clock
    from agent_gateway.modules.action_registry.ports import ActionRegistry
    from agent_gateway.modules.audit.ports import AuditLog
    from agent_gateway.modules.credentials.ports import CredentialStore
    from agent_gateway.modules.storage.ports import BlobStore, Locker
    from tests.fakes.storage import InMemoryLocker

    contracts: list[object] = []
    store: CredentialStore = FakeCredentialStore()
    audit: AuditLog = FakeAuditLog()
    registry: ActionRegistry = FakeActionRegistry()
    broker: Broker = FakeBroker()
    clock: Clock = FixedClock()
    blobs: BlobStore = InMemoryBlobStore()
    locker: Locker = InMemoryLocker()
    contracts.extend([store, audit, registry, broker, clock, blobs, locker])
    assert len(contracts) == 7
