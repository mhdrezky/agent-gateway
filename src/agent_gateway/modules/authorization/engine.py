"""Pure policy engine (SPEC §10.2)."""

from collections.abc import Iterable

from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    AuthorizationRequest,
    Decision,
    Policy,
    PolicyEffect,
    ResourceSelector,
)
from agent_gateway.modules.identity.models import Principal
from agent_gateway.modules.resources.models import Resource

PROD_TAG = "env:prod"

REASON_NOT_IN_ROLES = "action not in agent roles"
REASON_RESOURCE_TYPE = "resource type does not match action"
REASON_DENY_POLICY = "denied by policy"
REASON_NO_POLICY = "no matching allow policy"
REASON_ALLOWED = "allowed by policy"
REASON_ALLOWED_APPROVAL = "allowed by policy, approval required"


def pattern_matches(pattern: str, action_id: str) -> bool:
    """Match an action id against a pattern.

    ``*`` is only valid as the last segment and matches one or more trailing
    segments, so ``docker.*`` covers ``docker.container.list``.
    """
    if pattern.endswith(".*"):
        return action_id.startswith(pattern[:-1])
    return pattern == action_id


def any_pattern_matches(patterns: Iterable[str], action_id: str) -> bool:
    return any(pattern_matches(p, action_id) for p in patterns)


def selector_matches(selector: ResourceSelector, resource: Resource) -> bool:
    """Match by id, or by tags when the selector names at least one tag.

    An empty selector matches nothing: a policy must name what it applies to.
    """
    if resource.id in selector.ids:
        return True
    return bool(selector.tags) and resource.has_tags(selector.tags)


def _subject_matches(policy: Policy, principal: Principal) -> bool:
    subject = policy.subject
    if subject.agent_id is not None:
        return principal.agent_id is not None and subject.agent_id == principal.agent_id
    return subject.role in principal.roles


def _approval_required(mode: ApprovalMode, risk: RiskLevel, resource: Resource) -> bool:
    if risk is RiskLevel.CRITICAL or mode is ApprovalMode.ALWAYS:
        return True
    if mode is ApprovalMode.NEVER:
        return False
    return risk is RiskLevel.HIGH or (risk is RiskLevel.MEDIUM and PROD_TAG in resource.tags)


class DefaultPolicyEngine:
    """RBAC gate followed by resource policies. Default deny; deny always wins."""

    def decide(self, request: AuthorizationRequest) -> Decision:
        principal, action, resource = request.principal, request.action, request.resource

        granted = (role for role in request.roles if role.id in principal.roles)
        if not any(any_pattern_matches(role.actions, action.id) for role in granted):
            return Decision.deny(REASON_NOT_IN_ROLES)

        if resource.type != action.resource_type:
            return Decision.deny(REASON_RESOURCE_TYPE)

        matching = [
            policy
            for policy in request.policies
            if (policy.expires_at is None or policy.expires_at > request.now)
            and _subject_matches(policy, principal)
            and any_pattern_matches(policy.actions, action.id)
            and selector_matches(policy.resources, resource)
        ]

        for policy in matching:
            if policy.effect is PolicyEffect.DENY:
                return Decision.deny(REASON_DENY_POLICY, policy_id=policy.id)

        allows = [p for p in matching if p.effect is PolicyEffect.ALLOW]
        if not allows:
            return Decision.deny(REASON_NO_POLICY)

        # The strictest policy wins: report the first one that demands approval.
        for policy in allows:
            if _approval_required(policy.approval, action.risk, resource):
                return Decision(
                    effect=PolicyEffect.ALLOW,
                    approval_required=True,
                    policy_id=policy.id,
                    reason=REASON_ALLOWED_APPROVAL,
                )
        return Decision(
            effect=PolicyEffect.ALLOW,
            approval_required=False,
            policy_id=allows[0].id,
            reason=REASON_ALLOWED,
        )
