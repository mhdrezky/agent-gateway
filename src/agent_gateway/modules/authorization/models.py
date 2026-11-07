"""Roles, policies, and decisions (SPEC §8.3, §8.4, §10)."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from agent_gateway.common.models import Record, StrictModel
from agent_gateway.modules.action_registry.models import ActionDefinition
from agent_gateway.modules.approvals.models import Approver
from agent_gateway.modules.identity.models import Principal
from agent_gateway.modules.resources.models import Resource

# An action id, or a prefix ending in ".*" (wildcard only in the last segment).
ACTION_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(\.\*|(\.[a-z][a-z0-9_]*))$"

ActionPattern = Annotated[str, StringConstraints(pattern=ACTION_PATTERN)]


class Role(Record):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    description: str = ""
    actions: tuple[ActionPattern, ...] = ()


class PolicySubject(StrictModel):
    """Who a policy applies to. ``user`` and ``user_role`` only match calls made on behalf
    of a user (``X-User-Token``, SPEC §10.3); ``agent_id`` and ``role`` match the agent.
    """

    agent_id: str | None = None
    role: str | None = None
    # The user's ``sub`` claim.
    user: str | None = Field(default=None, min_length=1, max_length=255)
    user_role: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        given = [v for v in (self.agent_id, self.role, self.user, self.user_role) if v is not None]
        if len(given) != 1:
            raise ValueError("subject needs exactly one of agent_id, role, user, or user_role")
        return self

    @property
    def is_user_side(self) -> bool:
        return self.user is not None or self.user_role is not None


class ResourceSelector(StrictModel):
    """Matches if the resource id is in ``ids`` OR the resource has all ``tags``."""

    ids: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


class PolicyEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ApprovalMode(StrEnum):
    NEVER = "never"
    ALWAYS = "always"
    BY_RISK = "by_risk"
    # The requesting user confirms (SPEC §13b); never satisfied without a user.
    REQUESTER = "requester"


class Policy(Record):
    """An authorization rule. ``name`` is the idempotency key ``agw apply`` stores (SPEC §20.6)."""

    name: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$"
    )
    subject: PolicySubject
    actions: tuple[ActionPattern, ...] = Field(min_length=1)
    resources: ResourceSelector
    effect: PolicyEffect
    approval: ApprovalMode = ApprovalMode.BY_RISK
    expires_at: AwareDatetime | None = None


class Decision(StrictModel):
    effect: PolicyEffect
    approval_required: bool
    policy_id: str | None = None
    reason: str
    # Who decides when ``approval_required``; ``None`` (phase 2 records) means the admin.
    approver: Approver | None = None

    @classmethod
    def deny(cls, reason: str, policy_id: str | None = None) -> "Decision":
        return cls(
            effect=PolicyEffect.DENY, approval_required=False, policy_id=policy_id, reason=reason
        )

    @property
    def allowed(self) -> bool:
        return self.effect is PolicyEffect.ALLOW


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthorizationRequest:
    """Everything the policy engine needs. The engine performs no I/O."""

    principal: Principal
    action: ActionDefinition
    resource: Resource
    roles: Sequence[Role]
    policies: Sequence[Policy]
    now: datetime
