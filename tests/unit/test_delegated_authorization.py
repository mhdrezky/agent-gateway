"""An agent acting for a user: scope = user ∩ agent (SPEC §10.3)."""

from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from agent_gateway.modules.action_registry.models import ActionDefinition, RiskLevel
from agent_gateway.modules.authorization.engine import (
    REASON_ALLOWED,
    REASON_ALLOWED_APPROVAL,
    REASON_DENY_POLICY,
    REASON_NO_POLICY,
    REASON_NO_USER_POLICY,
    REASON_NOT_IN_ROLES,
    REASON_NOT_IN_USER_ROLES,
    DefaultPolicyEngine,
)
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    AuthorizationRequest,
    Decision,
    Policy,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.identity.models import Principal, TokenKind, UserIdentity
from agent_gateway.modules.resources.models import Resource, ResourceType

NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)
AGENT = "agt_01JB8AAAAAAAAAAAAAAAAAAAAA"
RES = "res_db"
ROLES = [
    Role(id="app", actions=("sql.*", "mail.send")),
    Role(id="staff", actions=("sql.query",)),
    Role(id="author", actions=("sql.query", "mail.send")),
]


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


def action(action_id: str = "sql.query", risk: RiskLevel = RiskLevel.LOW) -> ActionDefinition:
    return ActionDefinition(
        id=action_id,
        broker="sql" if action_id.startswith("sql") else "mail",
        resource_type=ResourceType.HTTP_ENDPOINT,
        description="test",
        risk=risk,
        input_model=NoParams,
    )


RESOURCE = Resource(id=RES, type=ResourceType.HTTP_ENDPOINT, name="db")


def allow(pid: str, subject: PolicySubject, approval: ApprovalMode = ApprovalMode.NEVER) -> Policy:
    return Policy(
        id=pid,
        subject=subject,
        actions=("sql.*", "mail.send"),
        resources=ResourceSelector(ids=(RES,)),
        effect=PolicyEffect.ALLOW,
        approval=approval,
    )


def deny(pid: str, subject: PolicySubject) -> Policy:
    return allow(pid, subject).model_copy(update={"effect": PolicyEffect.DENY})


AGENT_ALLOW = allow("pol_agent", PolicySubject(role="app"))
STAFF_ALLOW = allow("pol_staff", PolicySubject(user_role="staff"))


def principal(user_roles: tuple[str, ...] | None = ("staff",), sub: str = "u-1") -> Principal:
    user = None if user_roles is None else UserIdentity(subject=sub, roles=user_roles)
    return Principal(
        kind=TokenKind.AGENT, token_id="tok_x", agent_id=AGENT, roles=("app",), user=user
    )


def decide(who: Principal, policies: list[Policy], act: ActionDefinition | None = None) -> Decision:
    return DefaultPolicyEngine().decide(
        AuthorizationRequest(
            principal=who,
            action=act or action(),
            resource=RESOURCE,
            roles=ROLES,
            policies=policies,
            now=NOW,
        )
    )


def test_both_sides_allow() -> None:
    decision = decide(principal(), [AGENT_ALLOW, STAFF_ALLOW])
    assert decision.allowed
    assert decision.reason == REASON_ALLOWED


def test_agent_only_calls_ignore_user_policies() -> None:
    """D14: without a user, the decision is the phase 2 one."""
    agent_only = principal(user_roles=None)
    assert decide(agent_only, [AGENT_ALLOW]).allowed
    assert decide(agent_only, [AGENT_ALLOW, deny("pol_u", PolicySubject(user_role="app"))]).allowed
    assert decide(agent_only, [STAFF_ALLOW]).reason == REASON_NO_POLICY


def test_user_roles_must_cover_the_action() -> None:
    mail = action("mail.send")
    decision = decide(principal(), [AGENT_ALLOW, STAFF_ALLOW], mail)
    assert decision.reason == REASON_NOT_IN_USER_ROLES
    assert decide(
        principal(("author",)), [AGENT_ALLOW, allow("p", PolicySubject(user_role="author"))], mail
    ).allowed


def test_a_user_without_roles_gets_nothing() -> None:
    assert decide(principal(()), [AGENT_ALLOW, STAFF_ALLOW]).reason == REASON_NOT_IN_USER_ROLES


def test_agent_roles_still_bound_the_user() -> None:
    narrow = Principal(
        kind=TokenKind.AGENT,
        token_id="tok_x",
        agent_id=AGENT,
        roles=("staff",),
        user=UserIdentity(subject="u-1", roles=("author",)),
    )
    decision = decide(narrow, [AGENT_ALLOW, STAFF_ALLOW], action("mail.send"))
    assert decision.reason == REASON_NOT_IN_ROLES


def test_the_user_side_needs_its_own_allow() -> None:
    assert decide(principal(), [AGENT_ALLOW]).reason == REASON_NO_USER_POLICY


def test_the_agent_side_needs_its_own_allow() -> None:
    assert decide(principal(), [STAFF_ALLOW]).reason == REASON_NO_POLICY


def test_a_policy_for_the_agent_role_does_not_grant_the_user() -> None:
    """``role`` names agent roles; a user holding a role of that name gains nothing from it."""
    as_role = allow("pol_role_staff", PolicySubject(role="staff"))
    assert decide(principal(), [AGENT_ALLOW, as_role]).reason == REASON_NO_USER_POLICY


def test_a_user_subject_policy_matches_only_that_user() -> None:
    mine = allow("pol_me", PolicySubject(user="u-1"))
    assert decide(principal(sub="u-1"), [AGENT_ALLOW, mine]).allowed
    assert decide(principal(sub="u-2"), [AGENT_ALLOW, mine]).reason == REASON_NO_USER_POLICY


@pytest.mark.parametrize(
    "subject",
    [PolicySubject(user="u-1"), PolicySubject(user_role="staff"), PolicySubject(role="app")],
    ids=["user", "user_role", "agent_role"],
)
def test_a_deny_on_either_side_wins(subject: PolicySubject) -> None:
    decision = decide(principal(), [AGENT_ALLOW, STAFF_ALLOW, deny("pol_deny", subject)])
    assert decision.reason == REASON_DENY_POLICY
    assert decision.policy_id == "pol_deny"


def test_the_strictest_approval_of_both_sides_wins() -> None:
    strict_user = allow("pol_staff", PolicySubject(user_role="staff"), ApprovalMode.ALWAYS)
    decision = decide(principal(), [AGENT_ALLOW, strict_user])
    assert decision.approval_required
    assert decision.reason == REASON_ALLOWED_APPROVAL
    assert decision.policy_id == "pol_staff"


def test_subject_needs_exactly_one_field() -> None:
    with pytest.raises(ValidationError):
        PolicySubject()
    with pytest.raises(ValidationError):
        PolicySubject(role="app", user_role="staff")
    assert PolicySubject(user_role="staff").is_user_side
    assert not PolicySubject(role="staff").is_user_side


def test_phase_two_policies_still_load() -> None:
    stored = {
        "id": "pol_01JB8",
        "subject": {"agent_id": None, "role": "operator"},
        "actions": ["ssh.*"],
        "resources": {"ids": [], "tags": ["env:prod"]},
        "effect": "allow",
        "approval": "by_risk",
        "expires_at": None,
    }
    policy = Policy.model_validate(stored)
    assert policy.subject.role == "operator"
    assert policy.subject.user is None
    assert policy.name is None
