"""Wire types of the gateway admin contract ``agentgate-gateway-admin/1`` (SPEC §23).

They mirror the contract's own wire module field for field; timestamps are RFC 3339 strings
with a ``Z`` suffix. The one deliberate widening is ``ConfigSubject``: a config may name an
agent-side subject, so the plan can report ``agent_side_policy`` instead of a bare 422.
"""

from typing import Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
    model_validator,
)

from agent_gateway.modules.catalog.models import CatalogState
from agent_gateway.modules.identity.models import UserMatch

ADMIN_CONTRACT_VERSION = "agentgate-gateway-admin/1"
ACCESS_SCHEMA: Literal["agentgate-access/1"] = "agentgate-access/1"
POLICY_NAME_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---- §4 reads ----------------------------------------------------------------------------


class RoleView(BaseModel):
    id: str
    description: str = ""
    actions: list[str]
    held_by_agents: list[str] = Field(default_factory=list)
    editable: bool


class UserRecord(BaseModel):
    id: str
    match: UserMatch
    roles: list[str]


class ResourceView(BaseModel):
    """A resource as the console sees it: never a secret, never a credential id."""

    id: str
    name: str
    type: str
    tags: list[str] = Field(default_factory=list)
    has_credential: bool
    allowed_tables: list[str] | None = None
    catalog: CatalogState = Field(default_factory=CatalogState)


ActionState = Literal["active", "needs_review"]


class AdminActionInfo(BaseModel):
    """``ActionInfo`` of the admin contract (not the agent's ``/v1/actions`` item)."""

    id: str
    resource_type: str
    resource: str | None = None
    description: str = ""
    risk: str
    read_only: bool
    source: Literal["builtin", "mcp"]
    state: ActionState = "active"


# ---- §5 directory, §6 access -------------------------------------------------------------


class DirectoryUser(BaseModel):
    subject: str
    username: str
    display_name: str = ""
    email: str | None = None
    groups: list[str] = Field(default_factory=list)
    enabled: bool = True


class DirectoryGroup(BaseModel):
    name: str
    path: str
    member_count: int = Field(ge=0)


class RoleVia(BaseModel):
    kind: Literal["group", "subject"]
    value: str
    user_record: str


class RoleSource(BaseModel):
    role: str
    via: list[RoleVia] = Field(min_length=1)


AccessDecision = Literal["allow", "requester", "admin"]


class AccessGrant(BaseModel):
    action: str
    resource: str
    decision: AccessDecision
    policy: str | None = None
    reason: str


class AccessDenied(BaseModel):
    action: str
    reason: str


class AccessView(BaseModel):
    subject: str
    groups: list[str]
    roles: list[RoleSource]
    grants: list[AccessGrant]
    denied: list[AccessDenied] = Field(default_factory=list)


# ---- §8 access config, plan, apply -------------------------------------------------------


class ConfigSubject(_Strict):
    """Exactly one of ``user_role`` or ``user``; ``agent_id``/``role`` are accepted only so
    the plan can name them as ``agent_side_policy``."""

    user_role: str | None = None
    user: str | None = None
    agent_id: str | None = None
    role: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        given = [v for v in (self.user_role, self.user, self.agent_id, self.role) if v is not None]
        if len(given) != 1:
            raise ValueError("subject needs exactly one of 'user_role' or 'user'")
        return self

    @property
    def is_user_side(self) -> bool:
        return self.user_role is not None or self.user is not None

    @model_serializer(mode="wrap")
    def _only_given(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        # The contract's subject has no agent keys and forbids extras: never send them.
        data: dict[str, Any] = handler(self)
        return {key: value for key, value in data.items() if value is not None}


class ResourceNames(_Strict):
    names: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.names and not self.tags:
            raise ValueError("a policy must name resources or tags")
        return self


ApprovalModeName = Literal["never", "always", "by_risk", "requester"]


class UserPolicy(_Strict):
    name: str = Field(pattern=POLICY_NAME_PATTERN)
    subject: ConfigSubject
    actions: list[str] = Field(min_length=1)
    resources: ResourceNames
    effect: Literal["allow", "deny"]
    approval: ApprovalModeName = "by_risk"
    expires_at: str | None = None


class ConfigRole(_Strict):
    id: str
    description: str = ""
    actions: list[str] = Field(default_factory=list)


class ConfigUser(_Strict):
    """A user-store item in a config; no ``id`` means new (§8.1)."""

    id: str | None = None
    match: UserMatch
    roles: list[str]


class AccessConfig(_Strict):
    schema_: Literal["agentgate-access/1"] = Field(default=ACCESS_SCHEMA, alias="schema")
    roles: list[ConfigRole] = Field(default_factory=list)
    users: list[ConfigUser] = Field(default_factory=list)
    policies: list[UserPolicy] = Field(default_factory=list)
    resource_tables: dict[str, list[str]] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", populate_by_name=True, serialize_by_alias=True)

    @model_validator(mode="after")
    def _unique_names(self) -> Self:
        for what, names in (
            ("role", [r.id for r in self.roles]),
            ("policy", [p.name for p in self.policies]),
            ("user", [_match_key(u.match) for u in self.users]),
            ("user id", [u.id for u in self.users if u.id is not None]),
        ):
            seen: set[str] = set()
            for name in names:
                if name in seen:
                    raise ValueError(f"{what} '{name}' appears twice")
                seen.add(name)
        return self


class PlanIn(_Strict):
    config: AccessConfig


ChangeKind = Literal["role", "user", "policy", "resource_tables"]
ProblemCode = Literal[
    "missing_resource",
    "missing_action",
    "missing_role",
    "role_held_by_agent",
    "table_not_in_catalog",
    "agent_side_policy",
    "privileged_action",
    "last_admin",
    "self_lockout",
]


class Change(BaseModel):
    kind: ChangeKind
    name: str
    op: Literal["create", "update", "delete"]
    before: Any = None
    after: Any = None


class Problem(BaseModel):
    code: ProblemCode
    message: str


PlanStatus = Literal["open", "applied", "expired", "discarded"]


class PlanOut(BaseModel):
    plan_id: str
    base_digest: str
    created_by: str
    expires_at: str
    status: PlanStatus = "open"
    changes: list[Change]
    problems: list[Problem] = Field(default_factory=list)


class InstanceView(BaseModel):
    """``GET /v1/admin/instance`` (amendment A1): the instance's admin settings."""

    apply_requires_second_admin: bool
    admin_user_roles: list[str]


class ApplyIn(_Strict):
    plan_id: str = Field(min_length=1, max_length=64)


class ApplyOut(BaseModel):
    applied_at: str
    applied_by: str
    changes: list[Change]


# ---- §10 approvals, §11 history, §12 audit -----------------------------------------------


class RequestedBy(BaseModel):
    agent: str
    subject: str | None = None


class AdminApprovalView(BaseModel):
    id: str
    execution_id: str
    action: str
    resource: str
    summary: str
    params: dict[str, Any]
    requested_by: RequestedBy
    status: Literal["pending", "approved", "rejected", "expired"]
    created_at: str
    expires_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    reason: str | None = None


class AdminRejectIn(_Strict):
    reason: str = Field(min_length=1, max_length=500)


class ExecutionView(BaseModel):
    id: str
    action: str
    resource: str
    agent: str
    subject: str | None = None
    status: str
    decision_reason: str | None = None
    correlation_id: str | None = None
    created_at: str
    finished_at: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    error: str | None = None


class ExecutionDetail(ExecutionView):
    params: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] | None = None


class AuditActor(BaseModel):
    kind: Literal["user", "agent", "admin_token", "system"]
    subject: str | None = None
    via_agent: str | None = None


class AuditEntryView(BaseModel):
    seq: int = Field(ge=0)
    at: str
    event: str
    actor: AuditActor
    target: str | None = None
    outcome: str
    details: dict[str, Any] = Field(default_factory=dict)


class AdminExecutionPage(BaseModel):
    items: list[ExecutionView]
    next_cursor: str | None = None


class AuditPage(BaseModel):
    items: list[AuditEntryView]
    next_cursor: str | None = None


def _match_key(match: UserMatch) -> str:
    """``subject:<sub>`` or ``group:<group>``: how a user-store item is named in a plan."""
    if match.subject is not None:
        return f"subject:{match.subject}"
    return f"group:{match.group}"


match_key = _match_key
