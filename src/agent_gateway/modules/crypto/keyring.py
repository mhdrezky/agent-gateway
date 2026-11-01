"""Master key loading and HKDF-SHA256 subkey derivation (SPEC §7.1, §7.2)."""

import base64
import binascii
import secrets
from pathlib import Path
from typing import NoReturn

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from agent_gateway.modules.crypto.ports import MASTER_KEY_BYTES, MasterKeyError, SubkeyPurpose

SUBKEY_BYTES = 32
MAX_KEY_VERSION = 255  # stored in one byte of the envelope header
# A base64 32-byte key is 44 characters; anything far larger is not a key file.
MAX_KEY_FILE_BYTES = 1024


def generate_master_key() -> str:
    """A new random master key, base64-encoded, for writing to the key file (``agw init``)."""
    return base64.b64encode(secrets.token_bytes(MASTER_KEY_BYTES)).decode("ascii")


class MasterKeyRing:
    """Holds the master key in memory only and derives one subkey per purpose.

    The master key itself is never returned; ``repr`` never shows key material.
    """

    __slots__ = ("_key_version", "_master_key", "_subkeys")

    def __init__(self, master_key: bytes, *, key_version: int = 1) -> None:
        if len(master_key) != MASTER_KEY_BYTES:
            raise MasterKeyError(f"master key must be exactly {MASTER_KEY_BYTES} bytes")
        if not 1 <= key_version <= MAX_KEY_VERSION:
            raise MasterKeyError(f"key version must be between 1 and {MAX_KEY_VERSION}")
        self._master_key = bytes(master_key)
        self._key_version = key_version
        self._subkeys: dict[SubkeyPurpose, bytes] = {}

    @classmethod
    def from_file(cls, path: Path, *, key_version: int = 1) -> "MasterKeyRing":
        """Load a base64-encoded 32-byte key. Raise ``MasterKeyError`` on any problem."""
        try:
            with path.open("rb") as fh:
                raw = fh.read(MAX_KEY_FILE_BYTES + 1)
        except OSError:
            raise MasterKeyError(f"cannot read master key file {path}") from None
        if len(raw) > MAX_KEY_FILE_BYTES:
            raise MasterKeyError(f"master key file {path} is too large")
        try:
            key = base64.b64decode(raw.strip(), validate=True)
        except (binascii.Error, ValueError):
            raise MasterKeyError(f"master key file {path} is not valid base64") from None
        if len(key) != MASTER_KEY_BYTES:
            raise MasterKeyError(
                f"master key file {path} must decode to exactly {MASTER_KEY_BYTES} bytes"
            )
        return cls(key, key_version=key_version)

    @property
    def key_version(self) -> int:
        return self._key_version

    def subkey(self, purpose: SubkeyPurpose) -> bytes:
        cached = self._subkeys.get(purpose)
        if cached is None:
            cached = derive_subkey(self._master_key, purpose)
            self._subkeys[purpose] = cached
        return cached

    def __repr__(self) -> str:
        return f"MasterKeyRing(key_version={self._key_version}, master_key=***)"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("MasterKeyRing cannot be pickled")


def derive_subkey(master_key: bytes, purpose: SubkeyPurpose) -> bytes:
    """HKDF-SHA256 with an empty salt and ``info`` = the purpose string."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SUBKEY_BYTES,
        salt=None,
        info=purpose.value.encode("ascii"),
    )
    return hkdf.derive(master_key)
