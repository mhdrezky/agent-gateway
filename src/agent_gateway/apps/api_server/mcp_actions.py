"""MCP over Streamable HTTP at ``/mcp/actions``: one tool per action (SPEC §16, §22).

For applications that hand the tools straight to a model (agentgate, contract
``agentgate-gateway/1``). Transport, authentication, and the DNS rebinding guard are those
of ``/mcp``; only the tool shape differs. The tool list is computed per request from the
caller's roles and policies, and every call goes through the same execution engine (P6).
"""

import json
from collections.abc import Mapping
from typing import Any

import mcp_types as types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from pydantic import ValidationError

from agent_gateway.apps.api_server.deps import principal_from_headers
from agent_gateway.apps.api_server.mcp_http import AGENT_ONLY
from agent_gateway.apps.api_server.schemas import ToolOutcome
from agent_gateway.common.errors import ActionNotAllowedError, GatewayError, InvalidParamsError
from agent_gateway.modules.action_registry.models import RegisteredAction
from agent_gateway.modules.execution.models import Execution, ExecutionRequest, ExecutionStatus
from agent_gateway.modules.identity.models import Principal, TokenKind
from agent_gateway.runtime import Gateway

MCP_ACTIONS_PATH = "/mcp/actions"
RESOURCE_ARG = "resource_id"
INSTRUCTIONS = (
    "Each tool runs one infrastructure action through Agent Gateway. "
    "A result with status 'pending' waits for a person to confirm it; do not call it again."
)


def tool_name(action_id: str) -> str:
    """``sql.query`` → ``sql_query``: model APIs reject dots in function names."""
    return action_id.replace(".", "_")


def _tool(action: RegisteredAction, resource_ids: list[str]) -> types.Tool | None:
    schema = action.definition.params_schema()
    properties: dict[str, Any] = dict(schema.get("properties", {}))
    if RESOURCE_ARG in properties:
        return None
    properties = {
        RESOURCE_ARG: {"type": "string", "enum": resource_ids, "description": "Target resource"},
        **properties,
    }
    input_schema = {
        **schema,
        "type": "object",
        "properties": properties,
        "required": [RESOURCE_ARG, *schema.get("required", [])],
    }
    input_schema.pop("title", None)
    return types.Tool(
        name=tool_name(action.definition.id),
        description=action.definition.description,
        input_schema=input_schema,
    )


async def _tools(gateway: Gateway, principal: Principal) -> dict[str, tuple[str, types.Tool]]:
    """Tool name → (action id, tool) for every action the caller can target somewhere."""
    resources = await gateway.engine.visible_resources(principal)
    tools: dict[str, tuple[str, types.Tool]] = {}
    ambiguous: set[str] = set()
    for action in sorted(
        await gateway.engine.visible_actions(principal), key=lambda a: a.definition.id
    ):
        ids = sorted(r.id for r in resources if r.type is action.definition.resource_type)
        tool = _tool(action, ids) if ids else None
        if tool is None:
            continue
        if tool.name in tools:
            ambiguous.add(tool.name)
        tools[tool.name] = (action.definition.id, tool)
    for name in ambiguous:
        del tools[name]
    return tools


def _outcome(execution: Execution) -> ToolOutcome:
    match execution.status:
        case ExecutionStatus.SUCCEEDED:
            data = execution.result.data if execution.result else {}
            return ToolOutcome(status="ok", execution_id=execution.id, result=data)
        case ExecutionStatus.PENDING_APPROVAL:
            return ToolOutcome(
                status="pending",
                execution_id=execution.id,
                summary=f"{execution.action} on {execution.resource_id} waits for approval",
            )
        case ExecutionStatus.DENIED:
            return ToolOutcome(status="denied", execution_id=execution.id, error="not allowed")
        case _:
            error = execution.error or (execution.result.error if execution.result else None)
            return ToolOutcome(
                status="error", execution_id=execution.id, error=error or execution.status.value
            )


def _error_outcome(exc: GatewayError) -> ToolOutcome:
    if isinstance(exc, ActionNotAllowedError):
        return ToolOutcome(status="denied", execution_id=exc.execution_id, error=exc.message)
    return ToolOutcome(status="error", execution_id=exc.execution_id, error=exc.message)


def _result(outcome: ToolOutcome) -> types.CallToolResult:
    body = outcome.model_dump(mode="json", exclude_none=True)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(body))],
        structured_content=body,
        is_error=outcome.status in ("denied", "error"),
    )


def build_actions_server(gateway: Gateway) -> Server[Any]:
    async def agent(ctx: ServerRequestContext[Any, Any]) -> Principal:
        headers: Mapping[str, str] = getattr(ctx.request, "headers", None) or {}
        principal = await principal_from_headers(gateway, headers)
        if principal.kind is not TokenKind.AGENT:
            raise ActionNotAllowedError(AGENT_ONLY)
        return principal

    async def list_tools(
        ctx: ServerRequestContext[Any, Any], _: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        tools = await _tools(gateway, await agent(ctx))
        return types.ListToolsResult(tools=[tool for _, tool in tools.values()])

    async def call_tool(
        ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        try:
            principal = await agent(ctx)
            found = (await _tools(gateway, principal)).get(params.name)
            if found is None:
                raise InvalidParamsError(f"unknown tool {params.name!r}")
            arguments = dict(params.arguments or {})
            resource_id = arguments.pop(RESOURCE_ARG, None)
            if not isinstance(resource_id, str):
                raise InvalidParamsError(f"{RESOURCE_ARG} is required")
            try:
                request = ExecutionRequest(
                    action=found[0], resource_id=resource_id, params=arguments
                )
            except ValidationError as exc:
                raise InvalidParamsError(
                    f"invalid request: {exc.error_count()} problem(s)"
                ) from None
            execution = await gateway.engine.submit(principal, request)
        except GatewayError as exc:
            return _result(_error_outcome(exc))
        return _result(_outcome(execution))

    return Server(
        "agent-gateway-actions",
        instructions=INSTRUCTIONS,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
