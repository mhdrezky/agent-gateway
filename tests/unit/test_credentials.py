"""Encrypted credential store (SPEC §7.3, §8.6)."""

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from agent_gateway.common.errors import ConflictError, CredentialNotFoundError, InvalidParamsError
from agent_gateway.common.ids import IdPrefix, has_prefix
from agent_gateway.modules.credentials.models import CredentialMeta, CredentialType, SecretPayload
from agent_gateway.modules.credentials.ports import CredentialStore
from agent_gateway.modules.credentials.store import EncryptedCredentialStore, blob_name
from agent_gateway.modules.crypto.envelope import AesGcmEnvelopeCipher
from agent_gateway.modules.crypto.keyring import MasterKeyRing
from agent_gateway.modules.crypto.ports import CryptoError, credential_aad
from agent_gateway.modules.storage.blob_store import FileBlobStore
from agent_gateway.modules.storage.json_collection import JsonCollection
from agent_gateway.modules.storage.locking import FileLocker
from tests.fakes.clock import FixedClock
from tests.fakes.storage import InMemoryBlobStore, InMemoryCollection, InMemoryLocker

SECRET = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA-very-secret\n-----END-----"


class FailingUpdateCollection(InMemoryCollection[CredentialMeta]):
    async def update(
        self, item_id: str, fn: Callable[[CredentialMeta], CredentialMeta]
    ) -> CredentialMeta:
        raise OSError("disk full")


class FailingPutCollection(InMemoryCollection[CredentialMeta]):
    async def put(self, item: CredentialMeta) -> None:
        raise OSError("disk full")


class Env:
    def __init__(self, metadata: InMemoryCollection[CredentialMeta] | None = None) -> None:
        self.clock = FixedClock()
        self.keyring = MasterKeyRing(bytes(range(32)))
        self.cipher = AesGcmEnvelopeCipher.for_credentials(self.keyring)
        self.metadata = metadata if metadata is not None else InMemoryCollection[CredentialMeta]()
        self.blobs = InMemoryBlobStore()
        self.store = EncryptedCredentialStore(
            self.metadata, self.blobs, self.cipher, locker=InMemoryLocker(), clock=self.clock
        )


@pytest.fixture
def env() -> Env:
    return Env()


def ssh_key(value: str = SECRET) -> SecretPayload:
    return SecretPayload(CredentialType.SSH_PRIVATE_KEY, value, {"passphrase": "hunter2"})


def test_satisfies_protocol(env: Env) -> None:
    store: CredentialStore = env.store
    assert store is not None


async def test_create_and_open(env: Env) -> None:
    meta = await env.store.create("homelab deploy key", ssh_key())
    assert has_prefix(meta.id, IdPrefix.CREDENTIAL)
    assert meta.type is CredentialType.SSH_PRIVATE_KEY
    assert (meta.version, meta.key_version) == (1, 1)
    assert meta.created_at == env.clock.now()
    assert meta.rotated_at is None
    assert await env.store.get_meta(meta.id) == meta

    payload = await env.store.open(meta.id)
    assert payload.type is CredentialType.SSH_PRIVATE_KEY
    assert payload.reveal() == SECRET
    assert payload.field("passphrase") == "hunter2"


async def test_envelope_is_encrypted_and_bound_to_id(env: Env) -> None:
    meta = await env.store.create("key", ssh_key())
    envelope = await env.blobs.read(blob_name(meta.id))
    assert envelope is not None
    assert envelope[:4] == b"AGWC"
    assert SECRET.encode() not in envelope
    assert b"hunter2" not in envelope
    assert b"AAAA-very-secret" not in envelope
    assert env.cipher.open(envelope, credential_aad(meta.id, 1))
    assert SECRET not in meta.model_dump_json()


async def test_swapped_envelope_is_rejected(env: Env) -> None:
    first = await env.store.create("first", ssh_key("one"))
    second = await env.store.create("second", ssh_key("two"))
    envelope = await env.blobs.read(blob_name(first.id))
    assert envelope is not None
    await env.blobs.write(blob_name(second.id), envelope)
    with pytest.raises(CryptoError):
        await env.store.open(second.id)


async def test_tampered_envelope_is_rejected(env: Env) -> None:
    meta = await env.store.create("key", ssh_key())
    envelope = bytearray(await env.blobs.read(blob_name(meta.id)) or b"")
    envelope[-1] ^= 0x80
    await env.blobs.write(blob_name(meta.id), bytes(envelope))
    with pytest.raises(CryptoError):
        await env.store.open(meta.id)


async def test_rotate_bumps_version(env: Env) -> None:
    meta = await env.store.create("key", ssh_key("old"))
    env.clock.advance(timedelta(days=1))
    rotated = await env.store.rotate(meta.id, ssh_key("new"))
    assert rotated.version == 2
    assert rotated.rotated_at == env.clock.now()
    assert rotated.created_at == meta.created_at
    assert rotated.name == meta.name
    assert await env.store.get_meta(meta.id) == rotated
    assert (await env.store.open(meta.id)).reveal() == "new"
    third = await env.store.rotate(meta.id, ssh_key("newer"))
    assert third.version == 3
    assert (await env.store.open(meta.id)).reveal() == "newer"


async def test_old_envelope_cannot_be_replayed_after_rotation(env: Env) -> None:
    meta = await env.store.create("key", ssh_key("old"))
    old_envelope = await env.blobs.read(blob_name(meta.id))
    assert old_envelope is not None
    await env.store.rotate(meta.id, ssh_key("new"))
    await env.blobs.write(blob_name(meta.id), old_envelope)
    with pytest.raises(CryptoError):
        await env.store.open(meta.id)


async def test_rotate_rejects_type_change(env: Env) -> None:
    meta = await env.store.create("key", ssh_key())
    with pytest.raises(InvalidParamsError, match="type"):
        await env.store.rotate(meta.id, SecretPayload(CredentialType.API_TOKEN, "tok"))
    assert (await env.store.open(meta.id)).reveal() == SECRET


async def test_rotate_missing(env: Env) -> None:
    with pytest.raises(CredentialNotFoundError):
        await env.store.rotate("cred_missing", ssh_key())


async def test_failed_rotation_restores_old_envelope() -> None:
    env = Env(FailingUpdateCollection())
    meta = CredentialMeta(
        id="cred_x", type=CredentialType.API_TOKEN, name="t", created_at=env.clock.now()
    )
    await InMemoryCollection.put(env.metadata, meta)
    envelope = env.cipher.seal(
        b'{"type":"api_token","value":"old","fields":{}}', credential_aad("cred_x", 1)
    )
    await env.blobs.write(blob_name("cred_x"), envelope)

    with pytest.raises(OSError, match="disk full"):
        await env.store.rotate("cred_x", SecretPayload(CredentialType.API_TOKEN, "new"))
    assert await env.blobs.read(blob_name("cred_x")) == envelope
    assert (await env.store.open("cred_x")).reveal() == "old"


async def test_rotate_detects_concurrent_version_change(env: Env) -> None:
    meta = await env.store.create("key", ssh_key("old"))
    original_get = env.metadata.get

    async def stale_get(item_id: str) -> CredentialMeta | None:
        current = await original_get(item_id)
        # Another writer bumps the version right after this read.
        await env.metadata.put(meta.model_copy(update={"version": 5}))
        return current

    env.metadata.get = stale_get  # type: ignore[method-assign]
    with pytest.raises(ConflictError):
        await env.store.rotate(meta.id, ssh_key("new"))


async def test_failed_create_leaves_no_envelope() -> None:
    env = Env(FailingPutCollection())
    with pytest.raises(OSError, match="disk full"):
        await env.store.create("key", ssh_key())
    assert env.blobs._blobs == {}


async def test_create_validates_name(env: Env) -> None:
    with pytest.raises(InvalidParamsError, match="name"):
        await env.store.create("", ssh_key())
    with pytest.raises(InvalidParamsError, match="name"):
        await env.store.create("x" * 101, ssh_key())
    assert env.blobs._blobs == {}


async def test_list_and_delete(env: Env) -> None:
    first = await env.store.create("a", ssh_key())
    second = await env.store.create("b", SecretPayload(CredentialType.API_TOKEN, "t"))
    assert await env.store.list_meta() == sorted([first, second], key=lambda m: m.id)
    assert await env.store.delete(first.id) is True
    assert await env.store.delete(first.id) is False
    assert await env.blobs.read(blob_name(first.id)) is None
    assert await env.store.get_meta(first.id) is None
    with pytest.raises(CredentialNotFoundError):
        await env.store.open(first.id)
    assert await env.store.list_meta() == [second]


async def test_open_missing(env: Env) -> None:
    with pytest.raises(CredentialNotFoundError):
        await env.store.open("cred_missing")


async def test_open_with_missing_envelope(env: Env) -> None:
    meta = await env.store.create("key", ssh_key())
    await env.blobs.delete(blob_name(meta.id))
    with pytest.raises(CredentialNotFoundError):
        await env.store.open(meta.id)


@pytest.mark.parametrize(
    "plaintext",
    [
        b"not json",
        b"\xff",
        b"[]",
        b'{"type":"api_token","value":"x","fields":{}}',
        b'{"type":"ssh_private_key","value":1,"fields":{}}',
        b'{"type":"ssh_private_key","value":"x"}',
        b'{"type":"ssh_private_key","value":"x","fields":{"a":1}}',
    ],
)
async def test_malformed_payload_is_rejected(env: Env, plaintext: bytes) -> None:
    meta = await env.store.create("key", ssh_key())
    await env.blobs.write(
        blob_name(meta.id), env.cipher.seal(plaintext, credential_aad(meta.id, 1))
    )
    with pytest.raises(CryptoError, match="malformed"):
        await env.store.open(meta.id)


async def test_other_master_key_cannot_open(env: Env) -> None:
    meta = await env.store.create("key", ssh_key())
    other = EncryptedCredentialStore(
        env.metadata,
        env.blobs,
        AesGcmEnvelopeCipher.for_credentials(MasterKeyRing(bytes(32))),
        locker=InMemoryLocker(),
    )
    with pytest.raises(CryptoError):
        await other.open(meta.id)


async def test_key_version_is_recorded(env: Env) -> None:
    keyring = MasterKeyRing(bytes(range(32)), key_version=2)
    store = EncryptedCredentialStore(
        env.metadata,
        env.blobs,
        AesGcmEnvelopeCipher.for_credentials(keyring),
        locker=InMemoryLocker(),
    )
    meta = await store.create("key", ssh_key())
    assert meta.key_version == 2


async def test_on_disk_layout(tmp_path: Path) -> None:
    locker = FileLocker(tmp_path / ".locks")
    metadata = JsonCollection(tmp_path / "credentials.json", CredentialMeta, locker=locker)
    blobs = FileBlobStore(tmp_path / "credentials", locker=locker)
    cipher = AesGcmEnvelopeCipher.for_credentials(MasterKeyRing(bytes(range(32))))
    store = EncryptedCredentialStore(metadata, blobs, cipher, locker=locker)

    meta = await store.create("homelab deploy key", ssh_key())
    blob = tmp_path / "credentials" / f"{meta.id}.bin"
    assert blob.read_bytes()[:4] == b"AGWC"
    for path in (blob, tmp_path / "credentials.json"):
        content = path.read_bytes()
        assert b"very-secret" not in content
        assert b"hunter2" not in content
    assert (await store.open(meta.id)).reveal() == SECRET
