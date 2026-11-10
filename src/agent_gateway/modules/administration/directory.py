"""Read-only IdP directory for the admin API (SPEC §23, contract §5).

The gateway signs in to the IdP with its own service account (client credentials) and only
reads users and groups. The client secret is a credential in the gateway's store; it is
opened for one token request and wiped. Every failure is ``503 directory_unavailable`` with
a fixed message; details go to the server log only.
"""

import asyncio
import logging
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from agent_gateway.common.clock import Clock
from agent_gateway.common.errors import DirectoryUnavailableError
from agent_gateway.config import DirectorySettings
from agent_gateway.modules.administration.access_models import DirectoryGroup, DirectoryUser
from agent_gateway.modules.credentials.ports import CredentialStore

UNAVAILABLE = "the identity directory is unavailable"
# Members are counted from one page; a bigger group reports this many.
MEMBER_COUNT_CAP = 1000
TOKEN_MARGIN = timedelta(seconds=30)

log = logging.getLogger("agent_gateway.directory")


class Directory(Protocol):
    async def users(self, query: str, limit: int) -> list[DirectoryUser]: ...

    async def groups(self, query: str) -> list[DirectoryGroup]: ...

    async def user(self, subject: str) -> DirectoryUser | None:
        """One user by subject, with groups; ``None`` when the IdP does not know it."""
        ...


class UnconfiguredDirectory:
    """``admin.directory`` is not set: every call is ``503 directory_unavailable``."""

    async def users(self, query: str, limit: int) -> list[DirectoryUser]:
        raise DirectoryUnavailableError(UNAVAILABLE)

    async def groups(self, query: str) -> list[DirectoryGroup]:
        raise DirectoryUnavailableError(UNAVAILABLE)

    async def user(self, subject: str) -> DirectoryUser | None:
        raise DirectoryUnavailableError(UNAVAILABLE)


class KeycloakDirectory:
    """Keycloak admin REST API, read only (the service account needs ``view-users``)."""

    def __init__(
        self,
        settings: DirectorySettings,
        credentials: CredentialStore,
        clock: Clock,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._credentials = credentials
        self._clock = clock
        self._transport = transport
        self._token: str | None = None
        self._token_until: datetime | None = None
        self._lock = asyncio.Lock()

    # ---- Directory ----------------------------------------------------------------------

    async def users(self, query: str, limit: int) -> list[DirectoryUser]:
        params: dict[str, Any] = {"max": limit, "briefRepresentation": "true"}
        if query:
            params["search"] = query
        async with self._client() as client:
            found = await self._get_list(client, "/users", params)
            return [await self._user(client, item) for item in found]

    async def groups(self, query: str) -> list[DirectoryGroup]:
        params: dict[str, Any] = {"briefRepresentation": "false"}
        if query:
            params["search"] = query
        async with self._client() as client:
            tree = await self._get_list(client, "/groups", params)
            flat = list(_flatten(tree))
            needle = query.lower()
            result: list[DirectoryGroup] = []
            for group in flat:
                name, path, group_id = group.get("name"), group.get("path"), group.get("id")
                if not isinstance(name, str) or not isinstance(path, str):
                    continue
                if needle and needle not in name.lower() and needle not in path.lower():
                    continue
                members = await self._get_list(
                    client,
                    f"/groups/{quote(str(group_id), safe='')}/members",
                    {"briefRepresentation": "true", "max": MEMBER_COUNT_CAP},
                )
                result.append(
                    DirectoryGroup(
                        name=self._claim_value(name, path), path=path, member_count=len(members)
                    )
                )
            return sorted(result, key=lambda g: g.path)

    async def user(self, subject: str) -> DirectoryUser | None:
        async with self._client() as client:
            item = await self._get(client, f"/users/{quote(subject, safe='')}", {}, allow_404=True)
            if item is None:
                return None
            if not isinstance(item, dict):
                raise DirectoryUnavailableError(UNAVAILABLE)
            return await self._user(client, item)

    # ---- helpers ------------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self._settings.timeout_seconds, transport=self._transport)

    def _claim_value(self, name: str, path: str) -> str:
        return path if self._settings.groups_full_path else name

    async def _user(self, client: httpx.AsyncClient, item: dict[str, Any]) -> DirectoryUser:
        subject, username = item.get("id"), item.get("username")
        if not isinstance(subject, str) or not isinstance(username, str):
            raise DirectoryUnavailableError(UNAVAILABLE)
        groups = await self._get_list(
            client, f"/users/{quote(subject, safe='')}/groups", {"briefRepresentation": "true"}
        )
        names = sorted(
            self._claim_value(g["name"], g["path"])
            for g in groups
            if isinstance(g.get("name"), str) and isinstance(g.get("path"), str)
        )
        first, last = item.get("firstName") or "", item.get("lastName") or ""
        email = item.get("email")
        return DirectoryUser(
            subject=subject,
            username=username,
            display_name=f"{first} {last}".strip() if isinstance(first, str) else "",
            email=email if isinstance(email, str) else None,
            groups=names,
            enabled=item.get("enabled") is not False,
        )

    async def _get_list(
        self, client: httpx.AsyncClient, path: str, params: dict[str, Any]
    ) -> list[dict[str, Any]]:
        body = await self._get(client, path, params)
        if not isinstance(body, list) or not all(isinstance(i, dict) for i in body):
            log.warning("directory: unexpected body for %s", path)
            raise DirectoryUnavailableError(UNAVAILABLE)
        return body

    async def _get(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any],
        *,
        allow_404: bool = False,
    ) -> Any:
        url = f"{self._settings.base_url}/admin/realms/{quote(self._settings.realm, safe='')}{path}"
        for attempt in (1, 2):
            token = await self._access_token(client)
            try:
                response = await client.get(
                    url, params=params, headers={"Authorization": f"Bearer {token}"}
                )
            except httpx.HTTPError as exc:
                log.warning("directory: request failed: %s", type(exc).__name__)
                raise DirectoryUnavailableError(UNAVAILABLE) from None
            if response.status_code == 401 and attempt == 1:
                self._token = None  # expired or revoked early: sign in once more
                continue
            if response.status_code == 404 and allow_404:
                return None
            if response.is_error:
                log.warning("directory: %s answered %s", path, response.status_code)
                raise DirectoryUnavailableError(UNAVAILABLE)
            try:
                return response.json()
            except ValueError:
                raise DirectoryUnavailableError(UNAVAILABLE) from None
        raise DirectoryUnavailableError(UNAVAILABLE)

    async def _access_token(self, client: httpx.AsyncClient) -> str:
        async with self._lock:
            now = self._clock.now()
            if (
                self._token is not None
                and self._token_until is not None
                and now < self._token_until
            ):
                return self._token
            secret = await self._client_secret()
            url = (
                f"{self._settings.base_url}/realms/{quote(self._settings.realm, safe='')}"
                "/protocol/openid-connect/token"
            )
            try:
                response = await client.post(
                    url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._settings.client_id,
                        "client_secret": secret,
                    },
                )
            except httpx.HTTPError as exc:
                log.warning("directory: token request failed: %s", type(exc).__name__)
                raise DirectoryUnavailableError(UNAVAILABLE) from None
            finally:
                secret = ""
            if response.is_error:
                log.warning("directory: token request answered %s", response.status_code)
                raise DirectoryUnavailableError(UNAVAILABLE)
            try:
                body = response.json()
            except ValueError:
                raise DirectoryUnavailableError(UNAVAILABLE) from None
            token, expires_in = body.get("access_token"), body.get("expires_in", 60)
            if not isinstance(token, str) or not isinstance(expires_in, int):
                raise DirectoryUnavailableError(UNAVAILABLE)
            self._token = token
            self._token_until = now + timedelta(seconds=expires_in) - TOKEN_MARGIN
            return token

    async def _client_secret(self) -> str:
        name = self._settings.credential
        meta = next((m for m in await self._credentials.list_meta() if m.name == name), None)
        if meta is None:
            log.warning("directory: credential %r does not exist", name)
            raise DirectoryUnavailableError(UNAVAILABLE)
        opened = await self._credentials.open(meta.id)
        try:
            return opened.reveal()
        finally:
            opened.wipe()


def _flatten(groups: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for group in groups:
        yield group
        children = group.get("subGroups")
        if isinstance(children, list):
            yield from _flatten([c for c in children if isinstance(c, dict)])
