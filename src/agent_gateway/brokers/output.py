"""Helpers every broker uses to make output safe for the agent (SPEC §11.2)."""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.modules.credentials.models import REDACTED

# Lines of a multi-line secret (e.g. a PEM key) shorter than this are not redacted
# on their own, so short common lines such as "" or "-----" do not wipe output.
MIN_SECRET_LINE_LENGTH = 12


class BrokerError(Exception):
    """An expected failure whose message is safe to return to the agent."""


def secret_fragments(secrets: Iterable[str]) -> list[str]:
    """Each secret plus its long lines, longest first so overlaps redact fully."""
    fragments: set[str] = set()
    for secret in secrets:
        if not secret:
            continue
        fragments.add(secret)
        stripped = secret.strip()
        if stripped:
            fragments.add(stripped)
        for line in secret.splitlines():
            line = line.strip()
            if len(line) >= MIN_SECRET_LINE_LENGTH:
                fragments.add(line)
    return sorted(fragments, key=len, reverse=True)


def redact(text: str, fragments: Iterable[str]) -> str:
    for fragment in fragments:
        text = text.replace(fragment, REDACTED)
    return text


def truncate_utf8(text: str, limit: int) -> tuple[str, bool]:
    """Cut ``text`` to at most ``limit`` UTF-8 bytes without splitting a character."""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    return encoded[: max(limit, 0)].decode("utf-8", errors="ignore"), True


class OutputSanitizer:
    """Redacts credential values, then truncates, sharing one byte budget per action.

    Redaction runs before truncation so a cut can never expose part of a secret.
    """

    def __init__(self, ctx: ActionContext) -> None:
        secrets = ctx.credential.secret_values() if ctx.credential is not None else []
        self._fragments = secret_fragments(secrets)
        self._remaining = ctx.output_limit_bytes
        self.truncated = False

    def clean(self, text: str) -> str:
        cleaned, cut = truncate_utf8(redact(text, self._fragments), self._remaining)
        self._remaining -= len(cleaned.encode("utf-8"))
        self.truncated = self.truncated or cut
        return cleaned


async def run_safely(
    ctx: ActionContext, action_id: str, body: Callable[[], Awaitable[ActionResult]]
) -> ActionResult:
    """Run a handler body under the action timeout; turn every failure into a safe result."""
    try:
        async with asyncio.timeout(ctx.timeout_seconds):
            return await body()
    except BrokerError as exc:
        return ActionResult(ok=False, error=str(exc))
    except TimeoutError:
        return ActionResult(ok=False, error=f"{action_id} timed out")
    except Exception:
        _log_failure(ctx.logger, action_id, ctx.execution_id)
        return ActionResult(ok=False, error=f"{action_id} failed")


def _log_failure(logger: logging.Logger, action_id: str, execution_id: str) -> None:
    # The stack trace stays in the server log; the agent only sees a generic message.
    logger.exception("broker action %s failed (execution %s)", action_id, execution_id)
