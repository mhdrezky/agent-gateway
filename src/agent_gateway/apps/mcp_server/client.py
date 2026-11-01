"""HTTP client for the gateway's agent endpoints, authenticated with one agent token."""

from typing import Any

import httpx

DEFAULT_URL = "http://127.0.0.1:8080"
TIMEOUT_SECONDS = 120.0


class GatewayClient:
    def __init__(
        self,
        token: str,
        *,
        base_url: str = DEFAULT_URL,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=TIMEOUT_SECONDS,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def list_actions(self) -> Any:
        return await self._call("GET", "/v1/actions")

    async def list_resources(self, type: str | None = None) -> Any:
        return await self._call("GET", "/v1/resources", params={"type": type} if type else None)

    async def execute(
        self,
        action: str,
        resource_id: str,
        params: dict[str, Any],
        idempotency_key: str | None,
    ) -> Any:
        body: dict[str, Any] = {"action": action, "resource_id": resource_id, "params": params}
        if idempotency_key:
            body["idempotency_key"] = idempotency_key
        return await self._call("POST", "/v1/executions", json=body)

    async def get_execution(self, execution_id: str) -> Any:
        return await self._call("GET", f"/v1/executions/{execution_id}")

    async def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        """Return the JSON body. Gateway errors are returned as data, so the agent sees why."""
        try:
            response = await self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            return {"error": {"code": "gateway_unreachable", "message": str(exc)}}
        try:
            return response.json()
        except ValueError:
            return {"error": {"code": "bad_response", "message": f"HTTP {response.status_code}"}}
