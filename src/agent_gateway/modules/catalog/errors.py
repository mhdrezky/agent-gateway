"""Errors of catalog and sync (admin contract §7, §15)."""

from collections.abc import Sequence

from agent_gateway.common.errors import (
    ConflictError,
    GatewayError,
    InvalidParamsError,
    NotFoundError,
)
from agent_gateway.modules.catalog.models import SyncProblem


class SyncFailedError(GatewayError):
    """The resource could not be read; the last snapshot stays. The message is safe."""

    code = "sync_failed"
    status_code = 502


class NotPendingReviewError(ConflictError):
    code = "not_pending_review"


class ActionCollisionError(ConflictError):
    """Two tools of one server normalise to the same action id; neither is added."""

    code = "action_collision"


class ActionTooLongError(ConflictError):
    """A tool's action id would make a model-facing name longer than 64 characters."""

    code = "action_too_long"


class CatalogNotSupportedError(InvalidParamsError):
    """The resource's type has no catalog, or its broker is not enabled."""

    code = "catalog_not_supported"


class CatalogNotFoundError(NotFoundError):
    """The resource was never synced."""

    code = "catalog_not_found"


class InvalidActionIdError(ConflictError):
    """A tool name that no action id can hold (e.g. it starts with "_"); not in the contract."""

    code = "invalid_action_id"


_PROBLEM_ERRORS: dict[str, type[ConflictError]] = {
    "action_collision": ActionCollisionError,
    "action_too_long": ActionTooLongError,
    "invalid_action_id": InvalidActionIdError,
}


def problems_error(problems: Sequence[SyncProblem]) -> ConflictError | None:
    """The 409 a sync answers when it left tools out (admin contract §7.1): the code of the
    first problem, every problem in the message. The snapshot is stored without those tools."""
    if not problems:
        return None
    return _PROBLEM_ERRORS[problems[0].code]("; ".join(p.message for p in problems))
