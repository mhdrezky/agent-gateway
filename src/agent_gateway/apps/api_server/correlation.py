"""Correlation ids (SPEC §12).

REST sends one in ``X-Correlation-Id``. An MCP ``tools/call`` sends it in
``_meta["agentgate/correlation_id"]``, falling back to the same header. The value is
stored on the execution and copied into that execution's audit events.
"""

from collections.abc import Mapping
from typing import Any

from agent_gateway.common.errors import InvalidParamsError

CORRELATION_HEADER = "x-correlation-id"
META_CORRELATION = "agentgate/correlation_id"
MAX_LENGTH = 200


def header_value(headers: Mapping[str, str] | None, name: str) -> str | None:
    if not headers:
        return None
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def parse_correlation(value: object) -> str | None:
    """Validate one id. ``None`` means the caller sent nothing."""
    if value is None:
        return None
    if not isinstance(value, str) or not value or value != value.strip():
        raise InvalidParamsError("correlation id must be a non-empty string")
    if len(value) > MAX_LENGTH or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise InvalidParamsError(
            f"correlation id must be 1..{MAX_LENGTH} characters without control characters"
        )
    return value


def resolve_correlation(header: str | None, meta: Mapping[str, Any] | None) -> str | None:
    """One id for the call. The header and ``_meta`` may not disagree."""
    from_header = parse_correlation(header)
    from_meta = (
        parse_correlation(meta[META_CORRELATION])
        if meta is not None and META_CORRELATION in meta
        else None
    )
    if from_header is not None and from_meta is not None and from_header != from_meta:
        raise InvalidParamsError("X-Correlation-Id and _meta correlation id disagree")
    return from_meta if from_meta is not None else from_header
