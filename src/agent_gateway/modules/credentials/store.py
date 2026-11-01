"""Encrypted credential store (SPEC §6.1, §7.3, §8.6).

Metadata lives in a collection (``credentials.json``); each secret is an AES-GCM envelope
in a blob store as ``cred_<id>.bin``, bound by its AAD to the credential id and version.
"""

import json
from contextlib import AbstractAsyncContextManager
from typing import Any

from pydantic import ValidationError

from agent_gateway.common.clock import Clock, SystemClock
from agent_gateway.common.errors import (
    ConflictError,
    CredentialNotFoundError,
    InvalidParamsError,
)
from agent_gateway.common.ids import IdPrefix, new_id
from agent_gateway.modules.credentials.models import CredentialMeta, CredentialType, SecretPayload
from agent_gateway.modules.crypto.envelope import envelope_key_version
from agent_gateway.modules.crypto.ports import CryptoError, EnvelopeCipher, credential_aad
from agent_gateway.modules.storage.ports import BlobStore, Collection, Locker


def blob_name(credential_id: str) -> str:
    return f"{credential_id}.bin"


class EncryptedCredentialStore:
    """Plaintext goes in through ``create`` / ``rotate`` and comes back only from ``open``.

    Each credential's operations run under a cross-process lock, so a reader never pairs
    metadata of one version with the envelope of another.
    """

    def __init__(
        self,
        metadata: Collection[CredentialMeta],
        blobs: BlobStore,
        cipher: EnvelopeCipher,
        *,
        locker: Locker,
        clock: Clock | None = None,
    ) -> None:
        self._metadata = metadata
        self._blobs = blobs
        self._cipher = cipher
        self._locker = locker
        self._clock = clock or SystemClock()

    async def create(self, name: str, payload: SecretPayload) -> CredentialMeta:
        credential_id = new_id(IdPrefix.CREDENTIAL)
        envelope = self._seal(credential_id, 1, payload)
        meta = _meta(
            id=credential_id,
            type=payload.type,
            name=name,
            version=1,
            key_version=envelope_key_version(envelope),
            created_at=self._clock.now(),
        )
        async with self._lock(credential_id):
            # Envelope first: metadata must never point at a missing envelope.
            await self._blobs.write(blob_name(credential_id), envelope)
            try:
                await self._metadata.put(meta)
            except BaseException:
                await self._blobs.delete(blob_name(credential_id))
                raise
        return meta

    async def rotate(self, credential_id: str, payload: SecretPayload) -> CredentialMeta:
        async with self._lock(credential_id):
            meta = await self._require(credential_id)
            if payload.type is not meta.type:
                raise InvalidParamsError(
                    f"credential {credential_id} is of type {meta.type.value}, "
                    f"not {payload.type.value}"
                )
            version = meta.version + 1
            envelope = self._seal(credential_id, version, payload)
            rotated = _meta(
                **{
                    **meta.model_dump(),
                    "version": version,
                    "key_version": envelope_key_version(envelope),
                    "rotated_at": self._clock.now(),
                }
            )

            def bump(current: CredentialMeta) -> CredentialMeta:
                if current.version != meta.version:
                    raise ConflictError(f"credential {credential_id} changed during rotation")
                return rotated

            name = blob_name(credential_id)
            previous = await self._blobs.read(name)
            await self._blobs.write(name, envelope)
            try:
                return await self._metadata.update(credential_id, bump)
            except BaseException:
                # Put the old envelope back so it matches the unchanged metadata.
                if previous is not None:
                    await self._blobs.write(name, previous)
                raise

    async def get_meta(self, credential_id: str) -> CredentialMeta | None:
        return await self._metadata.get(credential_id)

    async def list_meta(self) -> list[CredentialMeta]:
        return sorted(await self._metadata.all(), key=lambda meta: meta.id)

    async def delete(self, credential_id: str) -> bool:
        async with self._lock(credential_id):
            # Metadata first: once it is gone, ``open`` reports not found.
            removed = await self._metadata.delete(credential_id)
            await self._blobs.delete(blob_name(credential_id))
            return removed

    async def open(self, credential_id: str) -> SecretPayload:
        async with self._lock(credential_id):
            meta = await self._require(credential_id)
            envelope = await self._blobs.read(blob_name(credential_id))
        if envelope is None:
            raise CredentialNotFoundError(f"credential {credential_id} has no stored secret")
        plaintext = self._cipher.open(envelope, credential_aad(credential_id, meta.version))
        return _decode_payload(plaintext, meta.type)

    def _lock(self, credential_id: str) -> AbstractAsyncContextManager[None]:
        return self._locker.lock(f"credential.{credential_id}")

    async def _require(self, credential_id: str) -> CredentialMeta:
        meta = await self._metadata.get(credential_id)
        if meta is None:
            raise CredentialNotFoundError(f"credential {credential_id} not found")
        return meta

    def _seal(self, credential_id: str, version: int, payload: SecretPayload) -> bytes:
        return self._cipher.seal(_encode_payload(payload), credential_aad(credential_id, version))


def _meta(**fields: Any) -> CredentialMeta:
    try:
        return CredentialMeta.model_validate(fields)
    except ValidationError as exc:
        names = sorted({".".join(map(str, err["loc"])) for err in exc.errors()})
        raise InvalidParamsError(f"invalid credential fields: {', '.join(names)}") from None


def _encode_payload(payload: SecretPayload) -> bytes:
    fields = {name: payload.field(name) for name in payload.field_names()}
    document = {"type": payload.type.value, "value": payload.reveal(), "fields": fields}
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _decode_payload(plaintext: bytes, expected_type: CredentialType) -> SecretPayload:
    # Authenticated by GCM, so a malformed payload means a bug or a key mix-up, not an attacker.
    try:
        document = json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CryptoError("credential payload is malformed") from None
    if (
        not isinstance(document, dict)
        or document.get("type") != expected_type.value
        or not isinstance(document.get("value"), str)
        or not isinstance(document.get("fields"), dict)
        or not all(isinstance(v, str) for v in document["fields"].values())
    ):
        raise CryptoError("credential payload is malformed")
    return SecretPayload(expected_type, document["value"], document["fields"])
