"""A fake IdP admin REST API (users and groups) served through ``httpx.MockTransport``."""

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote

import httpx

BASE_URL = "http://idp.internal"
REALM = "dev"
CLIENT_ID = "gateway-directory"
CLIENT_SECRET = "directory-secret-value"


@dataclass
class FakeUser:
    id: str
    username: str
    first: str = ""
    last: str = ""
    email: str | None = None
    groups: list[str] = field(default_factory=list)  # group names
    enabled: bool = True


@dataclass
class FakeKeycloak:
    users: list[FakeUser] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    down: bool = False
    token_requests: int = 0
    calls: list[str] = field(default_factory=list)
    issued: str = "admin-access-token-1"

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("idp down", request=request)
        path = unquote(request.url.path)
        self.calls.append(path)
        if path == f"/realms/{REALM}/protocol/openid-connect/token":
            form = parse_qs(request.content.decode())
            self.token_requests += 1
            if form.get("client_secret") != [CLIENT_SECRET] or form.get("client_id") != [CLIENT_ID]:
                return httpx.Response(401, json={"error": "unauthorized_client"})
            return httpx.Response(200, json={"access_token": self.issued, "expires_in": 300})
        if request.headers.get("authorization") != f"Bearer {self.issued}":
            return httpx.Response(401)
        prefix = f"/admin/realms/{REALM}"
        if not path.startswith(prefix):
            return httpx.Response(404)
        rest = path[len(prefix) :].strip("/").split("/")
        params = request.url.params
        if rest == ["users"]:
            search = params.get("search", "").lower()
            limit = int(params.get("max", "100"))
            found = [u for u in self.users if not search or _hit(u, search)][:limit]
            return httpx.Response(200, json=[_brief(u) for u in found])
        if len(rest) == 2 and rest[0] == "users":
            user = next((u for u in self.users if u.id == rest[1]), None)
            return httpx.Response(404) if user is None else httpx.Response(200, json=_brief(user))
        if len(rest) == 3 and rest[0] == "users" and rest[2] == "groups":
            user = next((u for u in self.users if u.id == rest[1]), None)
            if user is None:
                return httpx.Response(404)
            return httpx.Response(200, json=[_group(name) for name in user.groups])
        if rest == ["groups"]:
            search = params.get("search", "").lower()
            return httpx.Response(
                200, json=[_group(n) for n in self.groups if not search or search in n.lower()]
            )
        if len(rest) == 3 and rest[0] == "groups" and rest[2] == "members":
            name = rest[1].removeprefix("grp-")
            members = [_brief(u) for u in self.users if name in u.groups]
            return httpx.Response(200, content=json.dumps(members).encode())
        return httpx.Response(404)


def _hit(user: FakeUser, search: str) -> bool:
    text = " ".join([user.username, user.first, user.last, user.email or ""]).lower()
    return search in text


def _brief(user: FakeUser) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": user.id,
        "username": user.username,
        "firstName": user.first,
        "lastName": user.last,
        "enabled": user.enabled,
    }
    if user.email is not None:
        body["email"] = user.email
    return body


def _group(name: str) -> dict[str, Any]:
    return {"id": f"grp-{name}", "name": name, "path": f"/{name}", "subGroups": []}
