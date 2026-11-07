"""Execution engine contract (SPEC §12). REST and MCP both end up here."""

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from agent_gateway.modules.approvals.models import Approval
from agent_gateway.modules.execution.models import Execution, ExecutionRequest
from agent_gateway.modules.identity.models import Principal


class ExecutionStore(Protocol):
    """One record per execution (SPEC §6.1: ``executions/<yyyy-mm>/exe_<id>.json``)."""

    async def get(self, execution_id: str) -> Execution | None: ...

    async def put(self, execution: Execution) -> None: ...

    async def update(self, execution_id: str, fn: Callable[[Execution], Execution]) -> Execution:
        """Raise ``ExecutionNotFoundError`` if missing."""
        ...

    async def recent(self, *, since: datetime) -> list[Execution]:
        """Executions created at or after ``since``, newest first."""
        ...

    async def page(
        self,
        *,
        agent_id: str | None,
        before: str | None,
        limit: int,
        user_subject: str | None = None,
    ) -> list[Execution]:
        """Newest first, optionally only one agent's (and one user's), strictly older than id
        ``before``."""
        ...


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

    async def my_approvals(self, principal: Principal) -> list[tuple[Approval, Execution]]:
        """``requester`` approvals of the caller's user for its agent (SPEC §13b).

        Raise ``AuthenticationError`` without a user.
        """
        ...

    async def decide_as_requester(
        self, principal: Principal, approval_id: str, *, confirm: bool
    ) -> tuple[Approval, Execution]:
        """Confirm (re-authorize, run, and wait) or reject one of those approvals."""
        ...
