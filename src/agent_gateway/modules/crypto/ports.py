"""Encryption contracts and wire-format constants (SPEC §7)."""

from enum import StrEnum
from typing import Protocol

MASTER_KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
ENVELOPE_MAGIC = b"AGWC"
ENVELOPE_FORMAT_VERSION = 1
# magic (4) + format version (1) + key version (1) + nonce (12)
ENVELOPE_HEADER_BYTES = len(ENVELOPE_MAGIC) + 2 + NONCE_BYTES


class SubkeyPurpose(StrEnum):
    """HKDF ``info`` strings. Each purpose yields an independent 32-byte subkey."""

    CREDENTIALS = "agw/credentials/v1"
    TOKEN_HMAC = "agw/token-hmac/v1"
    AUDIT_ANCHOR = "agw/audit-anchor/v1"


class CryptoError(Exception):
    """Decryption or key handling failed. Messages never include key material."""


class MasterKeyError(CryptoError):
    """The master key is missing, unreadable, or has the wrong length."""


class KeyRing(Protocol):
    """Holds the master key in memory and derives subkeys. Never exposes the master key."""

    @property
    def key_version(self) -> int: ...

    def subkey(self, purpose: SubkeyPurpose) -> bytes: ...


class EnvelopeCipher(Protocol):
    """AES-256-GCM envelope in the format of SPEC §7.3."""

    def seal(self, plaintext: bytes, aad: bytes) -> bytes: ...

    def open(self, envelope: bytes, aad: bytes) -> bytes:
        """Raise ``CryptoError`` on a wrong key, wrong AAD, or any tampering."""
        ...


def credential_aad(credential_id: str, version: int) -> bytes:
    """AAD binding an envelope to one credential id and version (SPEC §7.3)."""
    return f"agw-cred|{credential_id}|{version}".encode()
