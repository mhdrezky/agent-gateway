"""Pure policy engine (SPEC §10.2)."""

from collections.abc import Callable, Iterable

from agent_gateway.modules.action_registry.models import ActionDefinition, RiskLevel
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    AuthorizationRequest,
    Decision,
    Policy,
    PolicyEffect,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.identity.models import Principal
from agent_gateway.modules.resources.models import Resource

PROD_TAG = "env:prod"

REASON_NOT_IN_ROLES = "action not in agent roles"
REASON_NOT_IN_USER_ROLES = "action not in user roles"
REASON_NO_USER_POLICY = "no matching allow policy for user"
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


def grants(patterns: Iterable[str], action: ActionDefinition) -> bool:
    """Whether ``patterns`` cover ``action``. Privileged actions need their exact id."""
    if action.privileged:
        return action.id in patterns
    return any_pattern_matches(patterns, action.id)


def roles_grant(roles: Iterable[Role], held: Iterable[str], action: ActionDefinition) -> bool:
    """Whether any of the ``held`` role ids, looked up in ``roles``, covers ``action``."""
    ids = set(held)
    return any(grants(role.actions, action) for role in roles if role.id in ids)


def selector_matches(selector: ResourceSelector, resource: Resource) -> bool:
    """Match by id, or by tags when the selector names at least one tag.

    An empty selector matches nothing: a policy must name what it applies to.
    """
    if resource.id in selector.ids:
        return True
    return bool(selector.tags) and resource.has_tags(selector.tags)


def agent_subject_matches(policy: Policy, principal: Principal) -> bool:
    """Whether ``policy`` names the agent side of ``principal`` (its id or one of its roles)."""
    subject = policy.subject
    if subject.agent_id is not None:
        return principal.agent_id is not None and subject.agent_id == principal.agent_id
    return subject.role is not None and subject.role in principal.roles


def user_subject_matches(policy: Policy, principal: Principal) -> bool:
    """Whether ``policy`` names the user ``principal`` acts for. Never true without a user."""
    user, subject = principal.user, policy.subject
    if user is None:
        return False
    if subject.user is not None:
        return subject.user == user.subject
    return subject.user_role is not None and subject.user_role in user.roles


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

        if not roles_grant(request.roles, principal.roles, action):
            return Decision.deny(REASON_NOT_IN_ROLES)
        user = principal.user
        if user is not None and not roles_grant(request.roles, user.roles, action):
            return Decision.deny(REASON_NOT_IN_USER_ROLES)

        if resource.type != action.resource_type:
            return Decision.deny(REASON_RESOURCE_TYPE)

        def matching(side: Callable[[Policy, Principal], bool]) -> list[Policy]:
            return [
                policy
                for policy in request.policies
                if (policy.expires_at is None or policy.expires_at > request.now)
                and side(policy, principal)
                and grants(policy.actions, action)
                and selector_matches(policy.resources, resource)
            ]

        agent_side = matching(agent_subject_matches)
        user_side = matching(user_subject_matches) if user is not None else []

        for policy in [*agent_side, *user_side]:
            if policy.effect is PolicyEffect.DENY:
                return Decision.deny(REASON_DENY_POLICY, policy_id=policy.id)

        allows = [p for p in agent_side if p.effect is PolicyEffect.ALLOW]
        if not allows:
            return Decision.deny(REASON_NO_POLICY)
        if user is not None:
            user_allows = [p for p in user_side if p.effect is PolicyEffect.ALLOW]
            if not user_allows:
                return Decision.deny(REASON_NO_USER_POLICY)
            allows += user_allows

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
