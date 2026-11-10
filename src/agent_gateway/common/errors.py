"""Gateway errors. Each maps to one HTTP status and error code (SPEC §15.3)."""

from typing import ClassVar


class GatewayError(Exception):
    code: ClassVar[str] = "internal_error"
    status_code: ClassVar[int] = 500

    def __init__(self, message: str, *, execution_id: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.execution_id = execution_id


class AuthenticationError(GatewayError):
    code = "unauthenticated"
    status_code = 401


class ActionNotAllowedError(GatewayError):
    code = "action_not_allowed"
    status_code = 403


class AdminRequiredError(GatewayError):
    code = "admin_required"
    status_code = 403


class NotFoundError(GatewayError):
    code = "not_found"
    status_code = 404


class ActionNotFoundError(NotFoundError):
    code = "action_not_found"


class ResourceNotFoundError(NotFoundError):
    code = "resource_not_found"


class ExecutionNotFoundError(NotFoundError):
    code = "execution_not_found"


class AgentNotFoundError(NotFoundError):
    code = "agent_not_found"


class CredentialNotFoundError(NotFoundError):
    code = "credential_not_found"


class ApprovalNotFoundError(NotFoundError):
    code = "approval_not_found"


class ModelNotFoundError(NotFoundError):
    code = "model_not_found"


class ConflictError(GatewayError):
    code = "conflict"
    status_code = 409


class ApprovalNotPendingError(ConflictError):
    code = "approval_not_pending"


class NamesMissingError(ConflictError):
    """``POST /v1/bind`` named things this agent does not have; ``missing`` lists them."""

    code = "names_missing"

    def __init__(self, message: str, *, missing: dict[str, list[str]]) -> None:
        super().__init__(message)
        self.missing = missing


class InvalidParamsError(GatewayError):
    code = "invalid_params"
    status_code = 422


class RateLimitedError(GatewayError):
    code = "rate_limited"
    status_code = 429


class AuditUnavailableError(GatewayError):
    code = "audit_unavailable"
    status_code = 503


# ---- agentgate-gateway-admin/1 (SPEC §23) ------------------------------------------------


class NotAdminError(GatewayError):
    """A signed-in user who holds none of the roles in ``admin.user_roles``."""

    code = "not_admin"
    status_code = 403


class InfraOnlyError(GatewayError):
    """Something only the gateway's own admin (static admin token) may see or do."""

    code = "infra_only"
    status_code = 403


class UserNotFoundError(NotFoundError):
    code = "user_not_found"


class SelfApprovalError(ConflictError):
    code = "self_approval"


class PlanStaleError(ConflictError):
    code = "plan_stale"


class PlanHasProblemsError(ConflictError):
    code = "plan_has_problems"


class PlanExpiredError(ConflictError):
    code = "plan_expired"


class SecondAdminRequiredError(ConflictError):
    code = "second_admin_required"


class DirectoryUnavailableError(GatewayError):
    code = "directory_unavailable"
    status_code = 503
