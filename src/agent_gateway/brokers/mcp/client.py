"""Talk to an external MCP server with the official SDK client (Streamable HTTP).

One short session per operation: list the tools for a sync, or call one tool. Nothing is
kept open between calls. Every failure becomes a ``BrokerError`` with a safe message; the
detail stays in the server log.
"""

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx2
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, TextContent

from agent_gateway.brokers.mcp.models import McpServerAttributes
from agent_gateway.brokers.output import BrokerError
from agent_gateway.modules.catalog.models import ToolSpec

UNREACHABLE = "could not reach the MCP server"
MAX_PAGES = 50

log = logging.getLogger(__name__)

# Builds the HTTP client for one session; tests swap in an in-process transport.
type HttpClientFactory = Callable[[dict[str, str], float], httpx2.AsyncClient]


def default_http_client(headers: dict[str, str], timeout: float) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(headers=headers, timeout=timeout)


@dataclass(frozen=True, slots=True)
class ToolCallOutput:
    is_error: bool
    texts: list[str] = field(default_factory=list[str])
    # Content items that are not text (images, audio, resources), by type.
    other: list[str] = field(default_factory=list[str])
    structured: dict[str, Any] | None = None


class McpClient:
    def __init__(self, http_client: HttpClientFactory | None = None) -> None:
        self._http_client = http_client or default_http_client

    @asynccontextmanager
    async def _session(
        self, attrs: McpServerAttributes, token: str | None
    ) -> AsyncIterator[ClientSession]:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        http = self._http_client(headers, float(attrs.timeout_seconds))
        async with (
            http,
            streamable_http_client(attrs.url, http_client=http) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            yield session

    async def list_tools(self, attrs: McpServerAttributes, token: str | None) -> list[ToolSpec]:
        try:
            async with self._session(attrs, token) as session:
                tools: list[ToolSpec] = []
                cursor: str | None = None
                for _ in range(MAX_PAGES):
                    page = await session.list_tools(
                        params=None if cursor is None else _page(cursor)
                    )
                    tools.extend(
                        ToolSpec(
                            name=tool.name,
                            description=tool.description or "",
                            input_schema=dict(tool.input_schema),
                            annotations=tool.annotations.model_dump(
                                by_alias=True, exclude_none=True, mode="json"
                            )
                            if tool.annotations is not None
                            else None,
                        )
                        for tool in page.tools
                    )
                    cursor = page.next_cursor
                    if cursor is None:
                        break
                return tools
        except Exception as exc:
            log.warning("mcp tools/list at %s failed: %r", attrs.url, exc)
            raise BrokerError(UNREACHABLE) from None

    async def call_tool(
        self, attrs: McpServerAttributes, token: str | None, tool: str, arguments: dict[str, Any]
    ) -> ToolCallOutput:
        try:
            async with self._session(attrs, token) as session:
                result = await session.call_tool(tool, arguments)
        except Exception as exc:
            log.warning("mcp tools/call %s at %s failed: %r", tool, attrs.url, exc)
            raise BrokerError(UNREACHABLE) from None
        if not isinstance(result, CallToolResult):
            raise BrokerError("the MCP server asked for input the gateway cannot give")
        texts: list[str] = []
        other: list[str] = []
        for item in result.content:
            if isinstance(item, TextContent):
                texts.append(item.text)
            else:
                other.append(str(getattr(item, "type", "unknown")))
        structured = result.structured_content
        return ToolCallOutput(
            is_error=bool(result.is_error),
            texts=texts,
            other=other,
            structured=dict(structured) if isinstance(structured, dict) else None,
        )


def _page(cursor: str) -> Any:
    from mcp.types import PaginatedRequestParams

    return PaginatedRequestParams(cursor=cursor)
