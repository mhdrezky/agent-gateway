"""Credential store contract. Plaintext goes in, but only ``open`` ever gives it back."""

from typing import Protocol

from agent_gateway.modules.credentials.models import CredentialMeta, SecretPayload


class CredentialStore(Protocol):
    async def create(self, name: str, payload: SecretPayload) -> CredentialMeta: ...

    async def rotate(self, credential_id: str, payload: SecretPayload) -> CredentialMeta:
        """Replace the secret and bump ``version``."""
        ...

    async def get_meta(self, credential_id: str) -> CredentialMeta | None: ...

    async def list_meta(self) -> list[CredentialMeta]: ...

    async def delete(self, credential_id: str) -> bool: ...

    async def open(self, credential_id: str) -> SecretPayload:
        """Decrypt for a broker call. Only the execution engine may call this.

        Raise ``CredentialNotFoundError`` if missing, ``CryptoError`` if tampered.
        """
        ...
