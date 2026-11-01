"""MCP server exposing the gateway to MCP clients (SPEC §16).

It is a thin client of the REST API: it holds only the agent's gateway token, never the
master key or any credential, and every call goes through the same execution engine (P6).
"""

import os
import sys
from typing import Any

from mcp.server.mcpserver import MCPServer

from agent_gateway.apps.mcp_server.client import DEFAULT_URL, GatewayClient

INSTRUCTIONS = (
    "Agent Gateway runs registered infrastructure actions on your behalf. "
    "Call list_actions and list_resources first, then execute_action. "
    "Some actions need human approval: the result then has status 'pending_approval'; "
    "poll get_execution with its id instead of submitting again."
)


def _wrap(key: str, body: Any) -> Any:
    """Return lists as one object: MCP would otherwise split them into separate items."""
    return {key: body} if isinstance(body, list) else body


def build_server(client: GatewayClient) -> MCPServer:
    server = MCPServer("agent-gateway", instructions=INSTRUCTIONS)

    @server.tool()
    async def list_actions() -> Any:
        """List the actions you may run, with the JSON schema of their params."""
        return _wrap("actions", await client.list_actions())

    @server.tool()
    async def list_resources(type: str | None = None) -> Any:
        """List the resources you may target, optionally filtered by resource type."""
        return _wrap("resources", await client.list_resources(type))

    @server.tool()
    async def execute_action(
        action: str,
        resource_id: str,
        params: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        """Run a registered action on a resource.

        The result may have status 'pending_approval'. In that case a human must approve it
        first: call get_execution with the returned id to check the outcome. Do not submit
        the same request again; pass an idempotency_key if you might retry.
        """
        return await client.execute(action, resource_id, params or {}, idempotency_key)

    @server.tool()
    async def get_execution(execution_id: str) -> Any:
        """Get the status and result of an execution you submitted."""
        return await client.get_execution(execution_id)

    return server


def main() -> None:
    token = os.environ.get("AGW_TOKEN")
    if not token:
        sys.exit("AGW_TOKEN is not set")
    client = GatewayClient(token, base_url=os.environ.get("AGW_URL", DEFAULT_URL))
    build_server(client).run(transport="stdio")


if __name__ == "__main__":
    main()
