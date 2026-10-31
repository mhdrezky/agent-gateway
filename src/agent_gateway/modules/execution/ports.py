"""Execution engine contract (SPEC §12). REST and MCP both end up here."""

from typing import Protocol

from agent_gateway.modules.execution.models import Execution, ExecutionRequest
from agent_gateway.modules.identity.models import Principal


class ExecutionEngine(Protocol):
    async def submit(self, principal: Principal, request: ExecutionRequest) -> Execution:
        """Run the full pipeline. Returns a finished, pending-approval, or denied execution."""
        ...

    async def get(self, principal: Principal, execution_id: str) -> Execution:
        """Agents only see their own executions; raise ``ExecutionNotFoundError`` otherwise."""
        ...

    async def list_for(
        self, principal: Principal, *, cursor: str | None = None, limit: int = 50
    ) -> tuple[list[Execution], str | None]:
        """Return a page and the next cursor."""
        ...
