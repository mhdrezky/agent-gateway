"""Last-line redaction of credential values from anything returned to an agent (P2).

Brokers redact their own output; the engine applies this again so a broker bug cannot
leak a secret.
"""

from collections.abc import Iterable
from typing import Any

from agent_gateway.modules.credentials.models import REDACTED

# Very short values would redact ordinary text; real credentials are far longer.
MIN_SECRET_LENGTH = 4


def redact(value: Any, secrets: Iterable[str]) -> Any:
    needles = sorted({s for s in secrets if len(s) >= MIN_SECRET_LENGTH}, key=len, reverse=True)
    if not needles:
        return value
    return _walk(value, needles)


def _walk(value: Any, needles: list[str]) -> Any:
    if isinstance(value, str):
        for needle in needles:
            value = value.replace(needle, REDACTED)
        return value
    if isinstance(value, dict):
        return {_walk(k, needles): _walk(v, needles) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_walk(v, needles) for v in value]
    return value
