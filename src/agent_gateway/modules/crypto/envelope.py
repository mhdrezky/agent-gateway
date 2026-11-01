"""AES-256-GCM envelopes in the wire format of SPEC §7.3.

```
offset  size  content
0       4     magic "AGWC"
4       1     format version (0x01)
5       1     key version
6       12    random nonce
18      n     ciphertext + 16-byte GCM tag
```

The header is not part of the AAD (the AAD is fixed by SPEC §7.3), but every header
byte is still checked: magic, format version and key version must match exactly, and
the nonce feeds GCM, so changing any byte makes ``open`` fail.
"""

import os
from typing import NoReturn

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent_gateway.modules.crypto.keyring import MAX_KEY_VERSION, SUBKEY_BYTES
from agent_gateway.modules.crypto.ports import (
    ENVELOPE_FORMAT_VERSION,
    ENVELOPE_HEADER_BYTES,
    ENVELOPE_MAGIC,
    NONCE_BYTES,
    TAG_BYTES,
    CryptoError,
    KeyRing,
    SubkeyPurpose,
)

_FORMAT_OFFSET = len(ENVELOPE_MAGIC)
_KEY_VERSION_OFFSET = _FORMAT_OFFSET + 1
_NONCE_OFFSET = _KEY_VERSION_OFFSET + 1


def envelope_key_version(envelope: bytes) -> int:
    """The key version recorded in an envelope header, after checking magic and format."""
    _check_header(envelope)
    return envelope[_KEY_VERSION_OFFSET]


class AesGcmEnvelopeCipher:
    """Seals and opens envelopes with one 32-byte key tagged with ``key_version``."""

    __slots__ = ("_aead", "_key_version")

    def __init__(self, key: bytes, *, key_version: int) -> None:
        if len(key) != SUBKEY_BYTES:
            raise CryptoError(f"envelope key must be exactly {SUBKEY_BYTES} bytes")
        if not 1 <= key_version <= MAX_KEY_VERSION:
            raise CryptoError(f"key version must be between 1 and {MAX_KEY_VERSION}")
        self._aead = AESGCM(key)
        self._key_version = key_version

    @classmethod
    def for_credentials(cls, keyring: KeyRing) -> "AesGcmEnvelopeCipher":
        """The cipher for credential envelopes, keyed with ``k_cred``."""
        return cls(keyring.subkey(SubkeyPurpose.CREDENTIALS), key_version=keyring.key_version)

    @property
    def key_version(self) -> int:
        return self._key_version

    def seal(self, plaintext: bytes, aad: bytes) -> bytes:
        # A fresh random 96-bit nonce per call; never reused with the same key.
        nonce = os.urandom(NONCE_BYTES)
        header = ENVELOPE_MAGIC + bytes((ENVELOPE_FORMAT_VERSION, self._key_version)) + nonce
        return header + self._aead.encrypt(nonce, plaintext, aad)

    def open(self, envelope: bytes, aad: bytes) -> bytes:
        _check_header(envelope)
        if envelope[_KEY_VERSION_OFFSET] != self._key_version:
            raise CryptoError("envelope was sealed with a different key version")
        nonce = envelope[_NONCE_OFFSET:ENVELOPE_HEADER_BYTES]
        try:
            return self._aead.decrypt(nonce, envelope[ENVELOPE_HEADER_BYTES:], aad)
        except InvalidTag:
            raise CryptoError("envelope authentication failed") from None

    def __repr__(self) -> str:
        return f"AesGcmEnvelopeCipher(key_version={self._key_version}, key=***)"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("AesGcmEnvelopeCipher cannot be pickled")


def _check_header(envelope: bytes) -> None:
    if len(envelope) < ENVELOPE_HEADER_BYTES + TAG_BYTES:
        raise CryptoError("envelope is too short")
    if envelope[:_FORMAT_OFFSET] != ENVELOPE_MAGIC:
        raise CryptoError("envelope has wrong magic")
    if envelope[_FORMAT_OFFSET] != ENVELOPE_FORMAT_VERSION:
        raise CryptoError("unsupported envelope format version")
