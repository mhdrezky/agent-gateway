"""Policy engine contract (SPEC §10.2)."""

from typing import Protocol

from agent_gateway.modules.authorization.models import AuthorizationRequest, Decision


class PolicyEngine(Protocol):
    def decide(self, request: AuthorizationRequest) -> Decision:
        """Pure function: same request, same decision. Default deny; deny always wins."""
        ...
