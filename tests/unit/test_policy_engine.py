"""Decision table for the policy engine (SPEC §10.2, §19)."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel, ConfigDict

from agent_gateway.modules.action_registry.models import ActionDefinition, RiskLevel
from agent_gateway.modules.authorization.engine import (
    REASON_ALLOWED,
    REASON_ALLOWED_APPROVAL,
    REASON_DENY_POLICY,
    REASON_NO_POLICY,
    REASON_NOT_IN_ROLES,
    REASON_RESOURCE_TYPE,
    DefaultPolicyEngine,
    pattern_matches,
)
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    AuthorizationRequest,
    Policy,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.authorization.ports import PolicyEngine
from agent_gateway.modules.identity.models import Principal, TokenKind
from agent_gateway.modules.resources.models import Resource, ResourceType

NOW = datetime(2026, 10, 31, 12, tzinfo=UTC)
AGENT = "agt_01JB8AAAAAAAAAAAAAAAAAAAAA"
OTHER_AGENT = "agt_01JB8BBBBBBBBBBBBBBBBBBBBB"
RES = "res_homelab1"


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _action(
    risk: RiskLevel = RiskLevel.LOW,
    action_id: str = "ssh.service.restart",
    resource_type: ResourceType = ResourceType.SSH_HOST,
) -> ActionDefinition:
    return ActionDefinition(
        id=action_id,
        broker=action_id.split(".")[0],
        resource_type=resource_type,
        description="test",
        risk=risk,
        input_model=NoParams,
    )


def _policy(
    pid: str = "pol_allow",
    *,
    effect: PolicyEffect = PolicyEffect.ALLOW,
    approval: ApprovalMode = ApprovalMode.NEVER,
    actions: tuple[str, ...] = ("ssh.service.restart",),
    ids: tuple[str, ...] = (RES,),
    tags: tuple[str, ...] = (),
    agent_id: str | None = AGENT,
    role: str | None = None,
    expires_at: datetime | None = None,
) -> Policy:
    subject = PolicySubject(agent_id=None, role=role) if role else PolicySubject(agent_id=agent_id)
    return Policy(
        id=pid,
        subject=subject,
        actions=actions,
        resources=ResourceSelector(ids=ids, tags=tags),
        effect=effect,
        approval=approval,
        expires_at=expires_at,
    )


OPERATOR = Role(id="operator", actions=("ssh.service.*", "docker.container.list"))
VIEWER = Role(id="viewer", actions=("ssh.service.status",))


@dataclass
class Case:
    name: str
    policies: list[Policy]
    risk: RiskLevel = RiskLevel.LOW
    action_id: str = "ssh.service.restart"
    action_type: ResourceType = ResourceType.SSH_HOST
    resource_type: ResourceType = ResourceType.SSH_HOST
    tags: tuple[str, ...] = ()
    agent_roles: tuple[str, ...] = ("operator",)
    roles: list[Role] = field(default_factory=lambda: [OPERATOR, VIEWER])
    agent_id: str | None = AGENT
    kind: TokenKind = TokenKind.AGENT
    # expected
    allowed: bool = False
    approval: bool = False
    policy_id: str | None = None
    reason: str = ""


CASES = [
    # 1. role gate
    Case("no role covers action", [_policy()], agent_roles=("viewer",), reason=REASON_NOT_IN_ROLES),
    Case("agent has no roles", [_policy()], agent_roles=(), reason=REASON_NOT_IN_ROLES),
    Case(
        "role id unknown to request",
        [_policy()],
        agent_roles=("operator",),
        roles=[VIEWER],
        reason=REASON_NOT_IN_ROLES,
    ),
    Case(
        "admin principal has no roles",
        [_policy(agent_id=None, role="operator")],
        agent_roles=(),
        agent_id=None,
        kind=TokenKind.ADMIN,
        reason=REASON_NOT_IN_ROLES,
    ),
    Case(
        "wildcard role covers action",
        [_policy()],
        allowed=True,
        policy_id="pol_allow",
        reason=REASON_ALLOWED,
    ),
    Case(
        "wildcard does not cover sibling prefix",
        [_policy(actions=("ssh.services.restart",))],
        action_id="ssh.services.restart",
        reason=REASON_NOT_IN_ROLES,
    ),
    Case(
        "policy wildcard covers deeper segments",
        [_policy(actions=("ssh.*",))],
        allowed=True,
        policy_id="pol_allow",
        reason=REASON_ALLOWED,
    ),
    # 6. resource type
    Case(
        "resource type mismatch",
        [_policy()],
        resource_type=ResourceType.DOCKER_HOST,
        reason=REASON_RESOURCE_TYPE,
    ),
    # 2-4. policy matching, deny wins, default deny
    Case("no policies at all", [], reason=REASON_NO_POLICY),
    Case("policy for another agent", [_policy(agent_id=OTHER_AGENT)], reason=REASON_NO_POLICY),
    Case(
        "policy for agent's role",
        [_policy(agent_id=None, role="operator")],
        allowed=True,
        policy_id="pol_allow",
        reason=REASON_ALLOWED,
    ),
    Case(
        "policy for a role the agent lacks",
        [_policy(agent_id=None, role="viewer")],
        reason=REASON_NO_POLICY,
    ),
    Case(
        "policy for other action",
        [_policy(actions=("ssh.service.status",))],
        reason=REASON_NO_POLICY,
    ),
    Case("policy for other resource id", [_policy(ids=("res_other",))], reason=REASON_NO_POLICY),
    Case(
        "policy matches by all tags",
        [_policy(ids=(), tags=("env:prod", "site:home"))],
        tags=("env:prod", "site:home", "x:y"),
        allowed=True,
        policy_id="pol_allow",
        reason=REASON_ALLOWED,
    ),
    Case(
        "policy needs a tag the resource lacks",
        [_policy(ids=(), tags=("env:prod", "site:home"))],
        tags=("env:prod",),
        reason=REASON_NO_POLICY,
    ),
    Case(
        "id OR tags: id matches even if tags do not",
        [_policy(ids=(RES,), tags=("env:staging",))],
        tags=("env:prod",),
        allowed=True,
        policy_id="pol_allow",
        reason=REASON_ALLOWED,
    ),
    Case("empty selector matches nothing", [_policy(ids=(), tags=())], reason=REASON_NO_POLICY),
    Case(
        "deny wins over allow",
        [_policy(), _policy("pol_deny", effect=PolicyEffect.DENY)],
        policy_id="pol_deny",
        reason=REASON_DENY_POLICY,
    ),
    Case(
        "deny by role wins over allow by agent",
        [_policy(), _policy("pol_deny", effect=PolicyEffect.DENY, agent_id=None, role="operator")],
        policy_id="pol_deny",
        reason=REASON_DENY_POLICY,
    ),
    Case(
        "deny by tag wins over allow by id",
        [_policy(), _policy("pol_deny", effect=PolicyEffect.DENY, ids=(), tags=("env:prod",))],
        tags=("env:prod",),
        policy_id="pol_deny",
        reason=REASON_DENY_POLICY,
    ),
    Case(
        "non-matching deny is ignored",
        [_policy(), _policy("pol_deny", effect=PolicyEffect.DENY, ids=("res_other",))],
        allowed=True,
        policy_id="pol_allow",
        reason=REASON_ALLOWED,
    ),
    Case(
        "expired allow is ignored",
        [_policy(expires_at=NOW - timedelta(seconds=1))],
        reason=REASON_NO_POLICY,
    ),
    Case(
        "allow expiring exactly now is ignored",
        [_policy(expires_at=NOW)],
        reason=REASON_NO_POLICY,
    ),
    Case(
        "unexpired allow applies",
        [_policy(expires_at=NOW + timedelta(minutes=1))],
        allowed=True,
        policy_id="pol_allow",
        reason=REASON_ALLOWED,
    ),
    Case(
        "expired deny is ignored",
        [_policy(), _policy("pol_deny", effect=PolicyEffect.DENY, expires_at=NOW)],
        allowed=True,
        policy_id="pol_allow",
        reason=REASON_ALLOWED,
    ),
    # 5. approval modes
    *[
        Case(
            f"never/{risk.value}",
            [_policy(approval=ApprovalMode.NEVER)],
            risk=risk,
            tags=("env:prod",),
            allowed=True,
            approval=risk is RiskLevel.CRITICAL,
            policy_id="pol_allow",
            reason=REASON_ALLOWED_APPROVAL if risk is RiskLevel.CRITICAL else REASON_ALLOWED,
        )
        for risk in RiskLevel
    ],
    *[
        Case(
            f"always/{risk.value}",
            [_policy(approval=ApprovalMode.ALWAYS)],
            risk=risk,
            allowed=True,
            approval=True,
            policy_id="pol_allow",
            reason=REASON_ALLOWED_APPROVAL,
        )
        for risk in RiskLevel
    ],
    *[
        Case(
            f"by_risk/{risk.value}/{'prod' if prod else 'staging'}",
            [_policy(approval=ApprovalMode.BY_RISK)],
            risk=risk,
            tags=("env:prod",) if prod else ("env:staging",),
            allowed=True,
            approval=required,
            policy_id="pol_allow",
            reason=REASON_ALLOWED_APPROVAL if required else REASON_ALLOWED,
        )
        for risk, prod, required in [
            (RiskLevel.LOW, False, False),
            (RiskLevel.LOW, True, False),
            (RiskLevel.MEDIUM, False, False),
            (RiskLevel.MEDIUM, True, True),
            (RiskLevel.HIGH, False, True),
            (RiskLevel.HIGH, True, True),
            (RiskLevel.CRITICAL, False, True),
            (RiskLevel.CRITICAL, True, True),
        ]
    ],
    Case(
        "strictest allow decides approval",
        [
            _policy("pol_a", approval=ApprovalMode.NEVER),
            _policy("pol_b", approval=ApprovalMode.ALWAYS),
        ],
        allowed=True,
        approval=True,
        policy_id="pol_b",
        reason=REASON_ALLOWED_APPROVAL,
    ),
    Case(
        "first allow reported when none needs approval",
        [_policy("pol_a"), _policy("pol_b")],
        allowed=True,
        policy_id="pol_a",
        reason=REASON_ALLOWED,
    ),
]


def _request(case: Case) -> AuthorizationRequest:
    principal = Principal(
        kind=case.kind,
        token_id="tok_x",
        agent_id=case.agent_id,
        roles=case.agent_roles,
    )
    resource = Resource(id=RES, type=case.resource_type, name="homelab-1", tags=case.tags)
    return AuthorizationRequest(
        principal=principal,
        action=_action(case.risk, case.action_id, case.action_type),
        resource=resource,
        roles=case.roles,
        policies=case.policies,
        now=NOW,
    )


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_decision_table(case: Case) -> None:
    engine: PolicyEngine = DefaultPolicyEngine()
    decision = engine.decide(_request(case))
    assert decision.allowed is case.allowed
    assert decision.approval_required is case.approval
    assert decision.policy_id == case.policy_id
    assert decision.reason == case.reason


def test_decision_is_deterministic() -> None:
    engine = DefaultPolicyEngine()
    request = _request(CASES[0])
    assert engine.decide(request) == engine.decide(request)


@pytest.mark.parametrize(
    ("pattern", "action_id", "expected"),
    [
        ("ssh.service.restart", "ssh.service.restart", True),
        ("ssh.service.restart", "ssh.service.status", False),
        ("ssh.service.*", "ssh.service.restart", True),
        ("ssh.*", "ssh.service.restart", True),
        ("ssh.service.*", "ssh.servicex.restart", False),
        ("ssh.service.*", "ssh.service", False),
        ("docker.*", "ssh.service.restart", False),
    ],
)
def test_pattern_matches(pattern: str, action_id: str, expected: bool) -> None:
    assert pattern_matches(pattern, action_id) is expected
