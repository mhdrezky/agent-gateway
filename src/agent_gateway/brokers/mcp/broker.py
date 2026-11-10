"""MCP broker: tools of an external MCP server as actions (SPEC §11.6, admin contract §7).

There are no code-defined actions here. ``agw sync`` lists the server's tools into the
resource's catalog, and each live tool becomes action ``mcp.<resource>.<tool>``, bound to
that one resource. Calls still go through the engine (policy, approval, audit); the
engine's catalog guard denies tools that wait for review.
"""

import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ValidationError

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.brokers.mcp.client import HttpClientFactory, McpClient, ToolCallOutput
from agent_gateway.brokers.mcp.models import McpServerAttributes, McpToolParams, params_model
from agent_gateway.brokers.output import BrokerError, OutputSanitizer, run_safely
from agent_gateway.modules.action_registry.models import (
    ActionDefinition,
    ActionHandler,
    RegisteredAction,
)
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.catalog.models import CatalogSnapshot, CatalogTool, SourceCatalog
from agent_gateway.modules.catalog.ports import SourceUnavailableError
from agent_gateway.modules.catalog.rules import tool_risk
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.resources.models import Resource, ResourceType

MAX_DESCRIPTION = 1024
MAX_ERROR_TEXT = 300


def server_attributes(resource: Resource) -> McpServerAttributes:
    if resource.type is not ResourceType.MCP_SERVER:
        raise BrokerError("resource is not an mcp_server")
    try:
        return McpServerAttributes.model_validate(resource.attributes)
    except ValidationError as exc:
        raise BrokerError("mcp_server resource attributes are invalid") from exc


def bearer_token(credential: SecretPayload | None) -> str | None:
    if credential is None:
        return None
    if credential.type is not CredentialType.API_TOKEN:
        raise BrokerError("mcp_server credential must be an api_token")
    return credential.reveal()


def _json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def tool_result(ctx: ActionContext, output: ToolCallOutput) -> ActionResult:
    """Text content redacted and cut to the output limit; structured content kept only if
    it still fits whole."""
    sanitizer = OutputSanitizer(ctx)
    texts = [sanitizer.clean(text) for text in output.texts]
    data: dict[str, Any] = {"content": texts}
    if output.other:
        data["other_content"] = output.other
    truncated = sanitizer.truncated
    if output.structured is not None:
        # The engine redacts credential values from the whole result afterwards.
        if _json_size(output.structured) <= max(ctx.output_limit_bytes - _json_size(data), 0):
            data["structured"] = output.structured
        else:
            truncated = True
    if output.is_error:
        first = texts[0][:MAX_ERROR_TEXT] if texts else ""
        error = f"the tool reported an error: {first}" if first else "the tool reported an error"
        return ActionResult(ok=False, data=data, truncated=truncated, error=error)
    return ActionResult(ok=True, data=data, truncated=truncated)


class McpBroker:
    """Broker, catalog source, and action provider for ``mcp_server`` resources."""

    def __init__(self, http_client: HttpClientFactory | None = None) -> None:
        self._client = McpClient(http_client)

    @property
    def name(self) -> str:
        return "mcp"

    @property
    def resource_type(self) -> ResourceType:
        return ResourceType.MCP_SERVER

    def resource_attribute_models(self) -> Mapping[ResourceType, type[BaseModel]]:
        return {ResourceType.MCP_SERVER: McpServerAttributes}

    def register(self, registry: ActionRegistry) -> None:
        """No code-defined actions: they come from each resource's catalog."""

    # ---- CatalogSource ------------------------------------------------------------------

    async def read(self, resource: Resource, credential: SecretPayload | None) -> SourceCatalog:
        try:
            attrs = server_attributes(resource)
            tools = await self._client.list_tools(attrs, bearer_token(credential))
        except BrokerError as exc:
            raise SourceUnavailableError(str(exc)) from None
        return SourceCatalog(tools=tuple(tools))

    # ---- CatalogActions ---------------------------------------------------------------

    def actions_for(self, snapshot: CatalogSnapshot) -> list[RegisteredAction]:
        return [self._action(snapshot, tool) for tool in snapshot.live_tools()]

    def _action(self, snapshot: CatalogSnapshot, tool: CatalogTool) -> RegisteredAction:
        description = (tool.description or f"Tool '{tool.name}' of {snapshot.resource_name}.")[
            :MAX_DESCRIPTION
        ]
        definition = ActionDefinition(
            id=tool.action,
            broker="mcp",
            resource_type=ResourceType.MCP_SERVER,
            description=description,
            risk=tool_risk(read_only=tool.read_only, destructive=tool.destructive),
            input_model=params_model(tool.action, tool.input_schema),
            read_only=tool.read_only,
            bound_resource=snapshot.id,
        )
        return RegisteredAction(definition, self._handler(tool.name, tool.action))

    def _handler(self, tool: str, action_id: str) -> ActionHandler:
        async def call(ctx: ActionContext, params: McpToolParams) -> ActionResult:
            async def body() -> ActionResult:
                attrs = server_attributes(ctx.resource)
                output = await self._client.call_tool(
                    attrs, bearer_token(ctx.credential), tool, dict(params.arguments)
                )
                return tool_result(ctx, output)

            return await run_safely(ctx, action_id, body)

        return call
