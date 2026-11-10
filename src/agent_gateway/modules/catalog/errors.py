"""Errors of catalog and sync (admin contract §7, §15)."""

from agent_gateway.common.errors import (
    ConflictError,
    GatewayError,
    InvalidParamsError,
    NotFoundError,
)


class SyncFailedError(GatewayError):
    """The resource could not be read; the last snapshot stays. The message is safe."""

    code = "sync_failed"
    status_code = 502


class NotPendingReviewError(ConflictError):
    code = "not_pending_review"


class CatalogNotSupportedError(InvalidParamsError):
    """The resource's type has no catalog, or its broker is not enabled."""

    code = "catalog_not_supported"


class CatalogNotFoundError(NotFoundError):
    """The resource was never synced."""

    code = "catalog_not_found"
