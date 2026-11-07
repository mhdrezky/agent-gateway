"""Docker broker: the four container actions of SPEC §11.3.

Only containers labelled ``agw.managed=true`` or named in the resource's
``allowed_containers`` are visible or touchable. Every action resolves the
container first and then acts on its id, so a name cannot be swapped in between.
"""

from collections.abc import Iterable, Mapping
from contextlib import AbstractAsyncContextManager
from typing import Any

from pydantic import BaseModel, ValidationError

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.brokers.docker.client import (
    ContainerNotFoundError,
    DockerClient,
    TransportFactory,
    default_transport,
    demux_logs,
)
from agent_gateway.brokers.docker.models import (
    MANAGED_LABEL,
    MANAGED_VALUE,
    STOP_TIMEOUT_SECONDS,
    ContainerParams,
    DockerHostAttributes,
    LogsParams,
    NoParams,
)
from agent_gateway.brokers.output import BrokerError, OutputSanitizer, run_safely
from agent_gateway.modules.action_registry.decorators import action, collect_actions
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.resources.models import ResourceType

DEFAULT_SOCKET = "unix:///var/run/docker.sock"
SHORT_ID_LENGTH = 12
# Raw log bytes read per byte of output budget; leaves room for redaction to shrink text.
RAW_LOG_FACTOR = 4
NOT_PERMITTED = "container not found or not managed by the gateway"


def host_attributes(ctx: ActionContext) -> DockerHostAttributes:
    if ctx.resource.type is not ResourceType.DOCKER_HOST:
        raise BrokerError("resource is not a docker_host")
    try:
        return DockerHostAttributes.model_validate(ctx.resource.attributes)
    except ValidationError as exc:
        raise BrokerError("docker_host resource attributes are invalid") from exc


def is_permitted(
    labels: Mapping[str, str] | None, names: Iterable[str], attrs: DockerHostAttributes
) -> bool:
    if (labels or {}).get(MANAGED_LABEL) == MANAGED_VALUE:
        return True
    return any(name.lstrip("/") in attrs.allowed_containers for name in names)


class DockerBroker:
    def __init__(
        self,
        default_endpoint: str = DEFAULT_SOCKET,
        transport_factory: TransportFactory = default_transport,
    ) -> None:
        self._default_endpoint = default_endpoint
        self._transport_factory = transport_factory

    @property
    def name(self) -> str:
        return "docker"

    def resource_attribute_models(self) -> Mapping[ResourceType, type[BaseModel]]:
        return {ResourceType.DOCKER_HOST: DockerHostAttributes}

    def register(self, registry: ActionRegistry) -> None:
        for registered in collect_actions(self):
            registry.register(registered)

    def _client(
        self, ctx: ActionContext, attrs: DockerHostAttributes
    ) -> AbstractAsyncContextManager[DockerClient]:
        return DockerClient.open(
            attrs,
            self._default_endpoint,
            ctx.credential,
            self._transport_factory,
            ctx.timeout_seconds,
        )

    @staticmethod
    async def _resolve(
        client: DockerClient, container: str, attrs: DockerHostAttributes
    ) -> dict[str, Any]:
        """Inspect a container and refuse it unless the gateway may touch it."""
        try:
            info = await client.inspect(container)
        except ContainerNotFoundError as exc:
            # Same answer as for unmanaged containers, so agents cannot probe for names.
            raise BrokerError(NOT_PERMITTED) from exc
        labels = (info.get("Config") or {}).get("Labels")
        if not is_permitted(labels, [str(info.get("Name", ""))], attrs):
            raise BrokerError(NOT_PERMITTED)
        return info

    @action(
        id="docker.container.list",
        resource_type=ResourceType.DOCKER_HOST,
        risk=RiskLevel.LOW,
        description=(
            "List containers managed by the gateway (label agw.managed=true or allowlisted)."
        ),
        input_model=NoParams,
        read_only=True,
    )
    async def container_list(self, ctx: ActionContext, params: NoParams) -> ActionResult:
        async def body() -> ActionResult:
            attrs = host_attributes(ctx)
            async with self._client(ctx, attrs) as client:
                containers = await client.list_containers()
            sanitizer = OutputSanitizer(ctx)
            visible = [
                {
                    "id": str(c.get("Id", ""))[:SHORT_ID_LENGTH],
                    "names": [sanitizer.clean(str(n).lstrip("/")) for n in c.get("Names") or []],
                    "image": sanitizer.clean(str(c.get("Image", ""))),
                    "state": sanitizer.clean(str(c.get("State", ""))),
                    "status": sanitizer.clean(str(c.get("Status", ""))),
                }
                for c in containers
                if is_permitted(c.get("Labels"), c.get("Names") or [], attrs)
            ]
            return ActionResult(
                ok=True, data={"containers": visible}, truncated=sanitizer.truncated
            )

        return await run_safely(ctx, "docker.container.list", body)

    @action(
        id="docker.container.logs",
        resource_type=ResourceType.DOCKER_HOST,
        risk=RiskLevel.LOW,
        description="Show the last log lines (at most 500) of a managed container.",
        input_model=LogsParams,
        read_only=True,
    )
    async def container_logs(self, ctx: ActionContext, params: LogsParams) -> ActionResult:
        async def body() -> ActionResult:
            attrs = host_attributes(ctx)
            async with self._client(ctx, attrs) as client:
                info = await self._resolve(client, params.container, attrs)
                raw, cut = await client.logs(
                    str(info["Id"]), params.tail, ctx.output_limit_bytes * RAW_LOG_FACTOR
                )
            tty = bool((info.get("Config") or {}).get("Tty"))
            stdout, stderr = (raw, b"") if tty else demux_logs(raw)
            sanitizer = OutputSanitizer(ctx)
            data = {
                "container": params.container,
                "stdout": sanitizer.clean(stdout.decode("utf-8", errors="replace")),
                "stderr": sanitizer.clean(stderr.decode("utf-8", errors="replace")),
            }
            return ActionResult(ok=True, data=data, truncated=cut or sanitizer.truncated)

        return await run_safely(ctx, "docker.container.logs", body)

    @action(
        id="docker.container.restart",
        resource_type=ResourceType.DOCKER_HOST,
        risk=RiskLevel.MEDIUM,
        description="Restart a managed container.",
        input_model=ContainerParams,
    )
    async def container_restart(self, ctx: ActionContext, params: ContainerParams) -> ActionResult:
        async def body() -> ActionResult:
            attrs = host_attributes(ctx)
            async with self._client(ctx, attrs) as client:
                info = await self._resolve(client, params.container, attrs)
                await client.restart(str(info["Id"]), STOP_TIMEOUT_SECONDS)
            return ActionResult(ok=True, data={"container": params.container, "restarted": True})

        return await run_safely(ctx, "docker.container.restart", body)

    @action(
        id="docker.container.stop",
        resource_type=ResourceType.DOCKER_HOST,
        risk=RiskLevel.HIGH,
        description="Stop a managed container.",
        input_model=ContainerParams,
    )
    async def container_stop(self, ctx: ActionContext, params: ContainerParams) -> ActionResult:
        async def body() -> ActionResult:
            attrs = host_attributes(ctx)
            async with self._client(ctx, attrs) as client:
                info = await self._resolve(client, params.container, attrs)
                stopped = await client.stop(str(info["Id"]), STOP_TIMEOUT_SECONDS)
            return ActionResult(
                ok=True, data={"container": params.container, "already_stopped": not stopped}
            )

        return await run_safely(ctx, "docker.container.stop", body)
