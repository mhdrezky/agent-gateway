"""Registers an onboarded SSH host through the admin REST API.

The onboarding tool never touches ``var/`` or the master key; it goes through the same
audited admin endpoints as any other admin client.
"""

from dataclasses import dataclass, field
from typing import Any

import httpx

from agent_gateway.apps.onboarding.naming import Names

SSH_ACTIONS = "ssh.*"
SMOKE_ACTION = "ssh.system.info"


class GatewayError(Exception):
    """The gateway refused a request; ``code`` is the gateway's error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        # Set by ``AdminClient.register``: what was created before the failure.
        self.registration: Registration | None = None


@dataclass(frozen=True, slots=True)
class HostPlan:
    names: Names
    host: str
    port: int
    user: str
    host_key_fingerprint: str
    host_key_algorithm: str
    private_key: str
    tags: tuple[str, ...]
    allowed_services: tuple[str, ...]


@dataclass(slots=True)
class Registration:
    credential_id: str | None = None
    resource_id: str | None = None
    role_id: str | None = None
    agent_id: str | None = None
    policy_id: str | None = None
    token_id: str | None = None
    agent_token: str | None = field(default=None, repr=False)

    def created(self) -> list[str]:
        return [
            f"{label}: {value}"
            for label, value in (
                ("credential", self.credential_id),
                ("resource", self.resource_id),
                ("role", self.role_id),
                ("agent", self.agent_id),
                ("policy", self.policy_id),
                ("token", self.token_id),
            )
            if value
        ]


class AdminClient:
    def __init__(
        self,
        base_url: str,
        admin_token: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url
        self._transport = transport
        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=60,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def check_admin(self) -> None:
        body = await self._call("GET", "/v1/whoami")
        if body.get("kind") != "admin":
            raise GatewayError("admin_required", "this token is not an admin token")

    async def taken_names(self) -> set[str]:
        """Every name in use for agents, roles, resources, and credentials."""
        agents = await self._call("GET", "/v1/admin/agents")
        roles = await self._call("GET", "/v1/admin/roles")
        resources = await self._call("GET", "/v1/admin/resources")
        credentials = await self._call("GET", "/v1/admin/credentials")
        return (
            {a["name"] for a in agents}
            | {r["id"] for r in roles}
            | {r["name"] for r in resources}
            | {c["name"] for c in credentials}
        )

    async def register(self, plan: HostPlan) -> Registration:
        """Create credential, resource, role, agent, policy, and agent token, in that order.

        On failure ``GatewayError.registration`` holds what was already created, so the
        caller can report it.
        """
        done = Registration()
        try:
            credential = await self._call(
                "POST",
                "/v1/admin/credentials",
                json={
                    "name": plan.names.credential,
                    "type": "ssh_private_key",
                    "value": plan.private_key,
                },
            )
            done.credential_id = credential["id"]
            resource = await self._call(
                "POST",
                "/v1/admin/resources",
                json={
                    "type": "ssh_host",
                    "name": plan.names.resource,
                    "tags": list(plan.tags),
                    "credential_id": done.credential_id,
                    "attributes": {
                        "host": plan.host,
                        "port": plan.port,
                        "username": plan.user,
                        "host_key_fingerprint": plan.host_key_fingerprint,
                        "host_key_algorithm": plan.host_key_algorithm,
                        "allowed_services": list(plan.allowed_services),
                    },
                },
            )
            done.resource_id = resource["id"]
            role = await self._call(
                "PUT",
                f"/v1/admin/roles/{plan.names.role}",
                json={
                    "description": f"SSH actions on {plan.names.resource}",
                    "actions": [SSH_ACTIONS],
                },
            )
            done.role_id = role["id"]
            agent = await self._call(
                "POST",
                "/v1/admin/agents",
                json={
                    "name": plan.names.agent,
                    "description": f"Agent for {plan.names.resource}",
                    "roles": [plan.names.role],
                },
            )
            done.agent_id = agent["id"]
            policy = await self._call(
                "POST",
                "/v1/admin/policies",
                json={
                    "subject": {"role": plan.names.role},
                    "actions": [SSH_ACTIONS],
                    "resources": {"ids": [done.resource_id]},
                    "effect": "allow",
                    "approval": "by_risk",
                },
            )
            done.policy_id = policy["id"]
            token = await self._call("POST", f"/v1/admin/agents/{done.agent_id}/tokens", json={})
            done.token_id = token["token"]["id"]
            done.agent_token = token["plaintext"]
        except GatewayError as exc:
            exc.registration = done
            raise
        return done

    async def smoke_test(self, agent_token: str, resource_id: str) -> dict[str, Any]:
        """Run ``ssh.system.info`` as the new agent, through the normal execution pipeline."""
        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=120,
            transport=self._transport,
        ) as agent:
            response = await agent.post(
                "/v1/executions",
                json={"action": SMOKE_ACTION, "resource_id": resource_id, "params": {}},
            )
            result: dict[str, Any] = _body(response)
            return result

    async def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise GatewayError("gateway_unreachable", str(exc)) from exc
        return _body(response)


def _body(response: httpx.Response) -> Any:
    try:
        body = response.json()
    except ValueError:
        raise GatewayError("bad_response", f"HTTP {response.status_code}") from None
    if response.status_code >= 400:
        error = body.get("error", {}) if isinstance(body, dict) else {}
        raise GatewayError(
            str(error.get("code", response.status_code)), str(error.get("message", body))
        )
    return body
