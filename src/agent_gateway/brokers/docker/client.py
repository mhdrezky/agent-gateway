"""Minimal Docker Engine API client over httpx."""

import struct
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx

from agent_gateway.brokers.docker.models import DockerHostAttributes
from agent_gateway.brokers.output import BrokerError
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload

UNIX_BASE_URL = "http://docker"
FRAME_HEADER = struct.Struct(">BxxxL")
STDOUT_STREAM, STDERR_STREAM = 1, 2

# Build a transport for an endpoint; tests inject httpx.MockTransport here.
TransportFactory = Callable[[str], httpx.AsyncBaseTransport]


class ContainerNotFoundError(BrokerError):
    pass


def base_url(endpoint: str) -> str:
    if endpoint.startswith("unix://"):
        return UNIX_BASE_URL
    if endpoint.startswith("tcp://"):
        return "http://" + endpoint.removeprefix("tcp://")
    return endpoint


def default_transport(endpoint: str) -> httpx.AsyncBaseTransport:
    if endpoint.startswith("unix://"):
        return httpx.AsyncHTTPTransport(uds=endpoint.removeprefix("unix://"))
    return httpx.AsyncHTTPTransport()


def _auth_headers(credential: SecretPayload | None) -> dict[str, str]:
    if credential is None:
        return {}
    if credential.type is CredentialType.API_TOKEN:
        return {"Authorization": f"Bearer {credential.reveal()}"}
    raise BrokerError(f"credential type {credential.type.value!r} is not supported for docker")


def demux_logs(raw: bytes) -> tuple[bytes, bytes]:
    """Split the multiplexed log stream Docker sends for containers without a TTY."""
    stdout, stderr = bytearray(), bytearray()
    offset = 0
    while offset + FRAME_HEADER.size <= len(raw):
        stream, size = FRAME_HEADER.unpack_from(raw, offset)
        offset += FRAME_HEADER.size
        chunk = raw[offset : offset + size]
        offset += size
        (stderr if stream == STDERR_STREAM else stdout).extend(chunk)
    return bytes(stdout), bytes(stderr)


class DockerClient:
    def __init__(self, http: httpx.AsyncClient, api_version: str | None) -> None:
        self._http = http
        self._prefix = f"/{api_version}" if api_version else ""

    @classmethod
    @asynccontextmanager
    async def open(
        cls,
        attrs: DockerHostAttributes,
        default_endpoint: str,
        credential: SecretPayload | None,
        transport_factory: TransportFactory,
        timeout_seconds: float,
    ) -> AsyncIterator["DockerClient"]:
        endpoint = attrs.endpoint or default_endpoint
        async with httpx.AsyncClient(
            transport=transport_factory(endpoint),
            base_url=base_url(endpoint),
            headers=_auth_headers(credential),
            timeout=timeout_seconds,
            follow_redirects=False,
        ) as http:
            yield cls(http, attrs.api_version)

    @staticmethod
    def _check(response: httpx.Response, *ok: int) -> None:
        if response.status_code in ok:
            return
        if response.status_code == httpx.codes.NOT_FOUND:
            raise ContainerNotFoundError("container not found")
        raise BrokerError(f"docker engine returned HTTP {response.status_code}")

    async def list_containers(self) -> list[dict[str, Any]]:
        response = await self._http.get(f"{self._prefix}/containers/json", params={"all": "1"})
        self._check(response, httpx.codes.OK)
        body = response.json()
        if not isinstance(body, list):
            raise BrokerError("unexpected docker engine response")
        return body

    async def inspect(self, container: str) -> dict[str, Any]:
        response = await self._http.get(f"{self._prefix}/containers/{container}/json")
        self._check(response, httpx.codes.OK)
        body = response.json()
        if not isinstance(body, dict):
            raise BrokerError("unexpected docker engine response")
        return body

    async def logs(self, container_id: str, tail: int, max_bytes: int) -> tuple[bytes, bool]:
        """Raw log bytes, cut at ``max_bytes``; the flag tells whether it was cut."""
        params = {"stdout": "1", "stderr": "1", "tail": str(tail), "timestamps": "1"}
        url = f"{self._prefix}/containers/{container_id}/logs"
        async with self._http.stream("GET", url, params=params) as response:
            if response.status_code != httpx.codes.OK:
                await response.aread()
                self._check(response, httpx.codes.OK)
            buffer = bytearray()
            async for chunk in response.aiter_bytes():
                buffer.extend(chunk)
                if len(buffer) > max_bytes:
                    return bytes(buffer[:max_bytes]), True
            return bytes(buffer), False

    async def restart(self, container_id: str, grace_seconds: int) -> None:
        response = await self._http.post(
            f"{self._prefix}/containers/{container_id}/restart", params={"t": str(grace_seconds)}
        )
        self._check(response, httpx.codes.NO_CONTENT)

    async def stop(self, container_id: str, grace_seconds: int) -> bool:
        """Return False if the container was already stopped."""
        response = await self._http.post(
            f"{self._prefix}/containers/{container_id}/stop", params={"t": str(grace_seconds)}
        )
        self._check(response, httpx.codes.NO_CONTENT, httpx.codes.NOT_MODIFIED)
        return response.status_code == httpx.codes.NO_CONTENT
