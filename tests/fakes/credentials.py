"""Credential store that keeps plaintext in memory. For tests only."""

from agent_gateway.common.clock import Clock, SystemClock
from agent_gateway.common.errors import CredentialNotFoundError
from agent_gateway.common.ids import IdPrefix, new_id
from agent_gateway.modules.credentials.models import CredentialMeta, SecretPayload


class FakeCredentialStore:
    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()
        self._meta: dict[str, CredentialMeta] = {}
        self._secrets: dict[str, tuple[str, dict[str, str]]] = {}
        self.opened: list[str] = []

    async def create(self, name: str, payload: SecretPayload) -> CredentialMeta:
        meta = CredentialMeta(
            id=new_id(IdPrefix.CREDENTIAL),
            type=payload.type,
            name=name,
            created_at=self._clock.now(),
        )
        self._meta[meta.id] = meta
        self._store(meta.id, payload)
        return meta

    async def rotate(self, credential_id: str, payload: SecretPayload) -> CredentialMeta:
        meta = self._require(credential_id)
        rotated = meta.model_copy(
            update={"version": meta.version + 1, "rotated_at": self._clock.now()}
        )
        self._meta[credential_id] = rotated
        self._store(credential_id, payload)
        return rotated

    async def get_meta(self, credential_id: str) -> CredentialMeta | None:
        return self._meta.get(credential_id)

    async def list_meta(self) -> list[CredentialMeta]:
        return list(self._meta.values())

    async def delete(self, credential_id: str) -> bool:
        self._secrets.pop(credential_id, None)
        return self._meta.pop(credential_id, None) is not None

    async def open(self, credential_id: str) -> SecretPayload:
        meta = self._require(credential_id)
        value, fields = self._secrets[credential_id]
        self.opened.append(credential_id)
        return SecretPayload(meta.type, value, fields)

    def _require(self, credential_id: str) -> CredentialMeta:
        meta = self._meta.get(credential_id)
        if meta is None:
            raise CredentialNotFoundError(f"credential {credential_id} not found")
        return meta

    def _store(self, credential_id: str, payload: SecretPayload) -> None:
        fields = {name: payload.field(name) for name in payload.field_names()}
        self._secrets[credential_id] = (payload.reveal(), fields)
