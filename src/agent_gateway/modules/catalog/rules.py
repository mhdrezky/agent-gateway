"""Pure rules of the admin contract §7 and §7.1 (`agentgate-gateway-admin/1`).

The same rules live in the contract package of agentgate (`mcp_action_id`,
`tool_is_read_only`); both sides must compute them the same way, so change them only
together with the contract.
"""

import re
from typing import Any

from agent_gateway.common.canonical import sha256_digest
from agent_gateway.modules.action_registry.models import RiskLevel

# The model-facing tool name is the action id with "." -> "_" (agentgate-gateway/1 §4.1).
TOOL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_NOT_ID_CHAR = re.compile(r"[^a-z0-9_]")


class ActionIdError(ValueError):
    """A tool name that cannot become an action id."""


class ActionIdTooLongError(ActionIdError):
    """The model-facing name of the action id would exceed 64 characters."""


def _id_part(text: str) -> str:
    part = _NOT_ID_CHAR.sub("_", text.lower())
    if not part:
        raise ActionIdError("an action id part cannot be empty")
    return part if "a" <= part[0] <= "z" else f"t_{part}"


def mcp_action_id(resource: str, tool: str) -> str:
    """`mcp.<resource>.<tool>` (§7.1, amendment A1): each part lowercased, every character
    outside `[a-z0-9_]` replaced by `_`, and a part that does not then start with `a-z`
    prefixed with `t_` (`2fa-reset` → `t_2fa_reset`, `_private` → `t__private`)."""
    action = f"mcp.{_id_part(resource)}.{_id_part(tool)}"
    if not TOOL_NAME_RE.match(action.replace(".", "_")):
        raise ActionIdTooLongError(f"action id '{action}' is too long for a tool name")
    return action


def tool_is_read_only(annotations: dict[str, Any] | None) -> bool:
    """Read only when the server says so; anything else is a write (§7)."""
    return annotations is not None and annotations.get("readOnlyHint") is True


def tool_is_destructive(annotations: dict[str, Any] | None) -> bool:
    """A write is destructive unless the server says it is not (MCP's own default)."""
    if tool_is_read_only(annotations):
        return False
    return annotations is None or annotations.get("destructiveHint") is not False


def tool_risk(*, read_only: bool, destructive: bool) -> RiskLevel:
    """read → low; a write the server calls non-destructive → medium; other writes → high."""
    if read_only:
        return RiskLevel.LOW
    return RiskLevel.HIGH if destructive else RiskLevel.MEDIUM


def schema_digest(schema: dict[str, Any]) -> str:
    """Digest of an input schema in canonical JSON, so key order never counts as a change."""
    return sha256_digest(schema)
