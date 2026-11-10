"""A tiny MCP server to sync and call through the ``mcp_server`` broker (SPEC §11.6).

Tools in variant ``v1``:

| Tool | Annotations | Becomes |
| ---- | ----------- | ------- |
| ``lookup_order`` | ``readOnlyHint: true`` | read, risk low |
| ``list_queues`` | ``readOnlyHint: true`` | read, risk low |
| ``create_ticket`` | ``readOnlyHint: false, destructiveHint: false`` | write, risk medium |
| ``ping_raw`` | none | write, risk high (no annotation = write) |

Variant ``v2`` changes them, for the review rules: ``lookup_order`` gets a new required
argument (schema changed), ``list_queues`` becomes a write (read → write), ``ping_raw`` is
gone, and ``close_ticket`` is new. ``create_ticket`` stays the same.

In tests it runs in-process (``FixtureServer.transport()`` with ``running()``). To run it
for the dev stack or by hand::

    uv run python -m tests.fixtures.mcp_fixture --port 8765 [--variant v2] [--token T]

The endpoint is ``http://127.0.0.1:8765/mcp``. ``POST /variant`` with body ``v1`` or ``v2``
switches the tools of a running server.
"""

import argparse
import copy
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx2
from mcp import types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

PATH = "/mcp"
Variant = Literal["v1", "v2"]

_ORDER = {
    "type": "object",
    "properties": {"order_id": {"type": "string", "minLength": 1}},
    "required": ["order_id"],
    "additionalProperties": False,
}
_ORDER_V2 = {
    "type": "object",
    "properties": {
        "order_id": {"type": "string", "minLength": 1},
        "include_lines": {"type": "boolean"},
    },
    "required": ["order_id", "include_lines"],
    "additionalProperties": False,
}
_TICKET = {
    "type": "object",
    "properties": {"title": {"type": "string", "maxLength": 80}, "body": {"type": "string"}},
    "required": ["title"],
    "additionalProperties": False,
}
_EMPTY: dict[str, Any] = {"type": "object", "properties": {}}
READ = types.ToolAnnotations(read_only_hint=True)
WRITE_SAFE = types.ToolAnnotations(read_only_hint=False, destructive_hint=False)


def tools_for(variant: Variant) -> list[types.Tool]:
    lookup = _ORDER if variant == "v1" else _ORDER_V2
    queues = READ if variant == "v1" else WRITE_SAFE
    tools = [
        types.Tool(
            name="lookup_order",
            description="Look up one order by id.",
            input_schema=lookup,
            annotations=READ,
        ),
        types.Tool(
            name="list_queues",
            description="List the ticket queues.",
            input_schema=_EMPTY,
            annotations=queues,
        ),
        types.Tool(
            name="create_ticket",
            description="Open a support ticket.",
            input_schema=_TICKET,
            annotations=WRITE_SAFE,
        ),
    ]
    if variant == "v1":
        tools.append(types.Tool(name="ping_raw", description="Answer pong.", input_schema=_EMPTY))
    else:
        tools.append(
            types.Tool(
                name="close_ticket",
                description="Close a ticket.",
                input_schema=_TICKET,
                annotations=WRITE_SAFE,
            )
        )
    return [copy.deepcopy(t) for t in tools]


@dataclass
class FixtureServer:
    """The fixture's state; ``tools`` replaces the variant's tools when set."""

    variant: Variant = "v1"
    token: str | None = None
    tools: list[types.Tool] | None = None
    calls: list[tuple[str, dict[str, Any]]] = field(
        default_factory=list[tuple[str, dict[str, Any]]]
    )
    secret_in_output: str | None = None

    def __post_init__(self) -> None:
        self.server = self._build()
        self.app = self._asgi(self.server)

    def listed(self) -> list[types.Tool]:
        return self.tools if self.tools is not None else tools_for(self.variant)

    def _build(self) -> Server[Any]:
        async def list_tools(
            _: ServerRequestContext[Any, Any], __: types.PaginatedRequestParams | None
        ) -> types.ListToolsResult:
            return types.ListToolsResult(tools=self.listed())

        async def call_tool(
            _: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
        ) -> types.CallToolResult:
            args = dict(params.arguments or {})
            self.calls.append((params.name, args))
            return self._answer(params.name, args)

        return Server("mcp-fixture", on_list_tools=list_tools, on_call_tool=call_tool)

    def _answer(self, name: str, args: dict[str, Any]) -> types.CallToolResult:
        def text(value: str, *, error: bool = False) -> types.CallToolResult:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=value)], is_error=error
            )

        if name == "lookup_order":
            order_id = str(args.get("order_id"))
            if order_id == "missing":
                return text(f"order {order_id} not found", error=True)
            note = f" (key {self.secret_in_output})" if self.secret_in_output else ""
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"order {order_id} is open{note}")],
                structured_content={"order_id": order_id, "status": "open"},
            )
        if name == "list_queues":
            return text("support, billing")
        if name in ("create_ticket", "close_ticket"):
            return text(f"{name}: {args.get('title')}")
        if name == "ping_raw":
            return text("pong")
        return text(f"unknown tool {name}", error=True)

    def _asgi(self, server: Server[Any]) -> ASGIApp:
        mcp_app = server.streamable_http_app(
            streamable_http_path=PATH,
            stateless_http=True,
            json_response=True,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        [route] = [r for r in mcp_app.routes if getattr(r, "path", None) == PATH]
        endpoint: ASGIApp = route.endpoint  # type: ignore[attr-defined]

        async def variant(request: Request) -> PlainTextResponse:
            body = (await request.body()).decode().strip()
            if body not in ("v1", "v2"):
                return PlainTextResponse("variant must be v1 or v2", status_code=422)
            self.variant = body  # type: ignore[assignment]
            return PlainTextResponse(self.variant)

        app = Starlette(
            routes=[Route("/variant", variant, methods=["POST"]), Mount(PATH, app=endpoint)]
        )
        return _BearerCheck(app, self)

    @asynccontextmanager
    async def running(self) -> AsyncIterator["FixtureServer"]:
        """Run the session manager of ``self.app`` (for a real server, e.g. uvicorn)."""
        async with self.server.session_manager.run():
            yield self

    def http_client(self, headers: dict[str, str], timeout: float) -> httpx2.AsyncClient:
        """An ``HttpClientFactory`` that reaches this server in-process.

        Each client gets a fresh server whose session manager runs from the client's own
        ``__aenter__`` to ``__aexit__``: the SDK needs both in one task, which a pytest
        fixture cannot promise, while the broker opens and closes a client in one task.
        """
        server = self._build()
        return _InProcessClient(server, self._asgi(server), headers, timeout)


class _InProcessClient(httpx2.AsyncClient):
    def __init__(
        self, server: Server[Any], app: ASGIApp, headers: dict[str, str], timeout: float
    ) -> None:
        super().__init__(transport=httpx2.ASGITransport(app=app), headers=headers, timeout=timeout)
        self._server = server
        self._stack = AsyncExitStack()

    async def __aenter__(self) -> "_InProcessClient":
        await self._stack.enter_async_context(self._server.session_manager.run())
        await super().__aenter__()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        try:
            await super().__aexit__(*exc)
        finally:
            await self._stack.aclose()


class _BearerCheck:
    def __init__(self, app: ASGIApp, fixture: FixtureServer) -> None:
        self._app = app
        self._fixture = fixture

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        token = self._fixture.token
        if scope["type"] == "http" and token is not None:
            headers = dict(scope.get("headers") or [])
            if headers.get(b"authorization") != f"Bearer {token}".encode():
                response = JSONResponse({"error": "unauthorized"}, status_code=401)
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--variant", choices=["v1", "v2"], default="v1")
    parser.add_argument("--token", default=None, help="Require Authorization: Bearer <token>.")
    args = parser.parse_args()
    fixture = FixtureServer(variant=args.variant, token=args.token)

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with fixture.running():
            yield

    app = Starlette(routes=[Mount("/", app=fixture.app)], lifespan=lifespan)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
