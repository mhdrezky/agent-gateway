"""Who decides an approval: admin, then requester, then nobody (SPEC §13b)."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.approvals.models import Approval, Approver
from agent_gateway.modules.authorization.engine import (
    REASON_ALLOWED_REQUESTER,
    REASON_REQUESTER_NEEDS_USER,
)
from agent_gateway.modules.authorization.models import ApprovalMode, Decision, PolicySubject
from tests.unit.test_delegated_authorization import (
    AGENT_ALLOW,
    action,
    allow,
    decide,
    principal,
)

STAFF_REQUESTER = allow("pol_req", PolicySubject(user_role="author"), ApprovalMode.REQUESTER)
MAIL = action("mail.send", RiskLevel.MEDIUM)
AUTHOR = principal(user_roles=("author",))


def test_the_requester_decides() -> None:
    decision = decide(AUTHOR, [AGENT_ALLOW, STAFF_REQUESTER], MAIL)
    assert decision.allowed
    assert decision.approval_required
    assert decision.approver is Approver.REQUESTER
    assert decision.policy_id == "pol_req"
    assert decision.reason == REASON_ALLOWED_REQUESTER


def test_a_requester_policy_without_a_user_denies() -> None:
    agent_requester = allow("pol_a", PolicySubject(role="app"), ApprovalMode.REQUESTER)
    decision = decide(principal(user_roles=None), [agent_requester], MAIL)
    assert not decision.allowed
    assert decision.reason == REASON_REQUESTER_NEEDS_USER
    assert decision.policy_id == "pol_a"


def test_admin_approval_wins_over_requester() -> None:
    agent_always = allow("pol_a", PolicySubject(role="app"), ApprovalMode.ALWAYS)
    decision = decide(AUTHOR, [agent_always, STAFF_REQUESTER], MAIL)
    assert decision.approval_required
    assert decision.approver is Approver.ADMIN
    assert decision.policy_id == "pol_a"


def test_a_triggered_by_risk_wins_over_requester() -> None:
    agent_by_risk = allow("pol_a", PolicySubject(role="app"), ApprovalMode.BY_RISK)
    high = action("mail.send", RiskLevel.HIGH)
    assert decide(AUTHOR, [agent_by_risk, STAFF_REQUESTER], high).approver is Approver.ADMIN
    # by_risk that does not trigger leaves the requester in charge.
    assert decide(AUTHOR, [agent_by_risk, STAFF_REQUESTER], MAIL).approver is (Approver.REQUESTER)


def test_critical_actions_stay_with_the_admin() -> None:
    critical = action("mail.send", RiskLevel.CRITICAL)
    assert decide(AUTHOR, [AGENT_ALLOW, STAFF_REQUESTER], critical).approver is Approver.ADMIN


def test_privileged_actions_stay_with_the_admin() -> None:
    sudo = replace(action("mail.send", RiskLevel.HIGH), privileged=True)
    requester_both = [
        allow("pol_a", PolicySubject(role="app"), ApprovalMode.REQUESTER),
        STAFF_REQUESTER,
    ]
    assert decide(AUTHOR, requester_both, sudo).approver is Approver.ADMIN


@pytest.mark.parametrize("mode", [ApprovalMode.ALWAYS, ApprovalMode.BY_RISK])
def test_admin_decisions_name_the_admin(mode: ApprovalMode) -> None:
    agent = allow("pol_a", PolicySubject(role="app"), mode)
    decision = decide(principal(user_roles=None), [agent], action(risk=RiskLevel.HIGH))
    assert decision.approver is Approver.ADMIN


def test_phase_two_records_still_load() -> None:
    decision = Decision.model_validate(
        {"effect": "allow", "approval_required": True, "policy_id": "pol_x", "reason": "r"}
    )
    assert decision.approver is None
    now = datetime(2026, 11, 7, tzinfo=UTC)
    approval = Approval.model_validate(
        {
            "id": "apr_01JB8AAAAAAAAAAAAAAAAAAAAA",
            "execution_id": "exe_01JB8AAAAAAAAAAAAAAAAAAAAA",
            "params_digest": "sha256:" + "0" * 64,
            "requested_at": now,
            "expires_at": now,
        }
    )
    assert approval.mode is Approver.ADMIN
    assert approval.requester is None
    assert approval.correlation_id is None
