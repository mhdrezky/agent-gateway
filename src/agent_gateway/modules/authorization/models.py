"""Roles, policies, and decisions (SPEC §8.3, §8.4, §10)."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from agent_gateway.common.models import Record, StrictModel
from agent_gateway.modules.action_registry.models import ActionDefinition
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
    agent_id: str | None = None
    role: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        if (self.agent_id is None) == (self.role is None):
            raise ValueError("subject needs exactly one of agent_id or role")
        return self


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


class Policy(Record):
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
