from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from agent_gateway.common.canonical import sha256_digest
from agent_gateway.modules.action_registry.models import ActionDefinition, RiskLevel
from agent_gateway.modules.audit.models import (
    GENESIS_HASH,
    Actor,
    ActorType,
    AuditEntry,
    AuditEventType,
)
from agent_gateway.modules.authorization.models import (
    Decision,
    Policy,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.crypto.ports import credential_aad
from agent_gateway.modules.execution.models import Execution, ExecutionStatus
from agent_gateway.modules.identity.models import Token, TokenKind
from agent_gateway.modules.resources.models import Resource, ResourceType

NOW = datetime(2026, 10, 31, tzinfo=UTC)
HASH = "a" * 64


class StrictParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str


class LooseParams(BaseModel):
    service: str


def _action(**overrides: object) -> ActionDefinition:
    fields: dict[str, object] = {
        "id": "ssh.service.restart",
        "broker": "ssh",
        "resource_type": ResourceType.SSH_HOST,
        "description": "Restart a service.",
        "risk": RiskLevel.MEDIUM,
        "input_model": StrictParams,
    }
    fields.update(overrides)
    return ActionDefinition(**fields)  # type: ignore[arg-type]


def test_action_definition_valid() -> None:
    action = _action()
    assert action.params_schema()["properties"] == {
        "service": {"title": "Service", "type": "string"}
    }


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"id": "Restart"}, "invalid action id"),
        ({"id": "docker.container.stop"}, "must start with broker name"),
        ({"timeout_seconds": 0}, "timeout_seconds"),
        ({"input_model": LooseParams}, "extra='forbid'"),
    ],
)
def test_action_definition_rejects(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _action(**overrides)


def test_token_kind_binding() -> None:
    Token(
        id="tok_1",
        kind=TokenKind.AGENT,
        agent_id="agt_1",
        hash=HASH,
        prefix="agw_tok_1",
        created_at=NOW,
    )
    Token(id="tok_2", kind=TokenKind.ADMIN, hash=HASH, prefix="agw_tok_2", created_at=NOW)
    with pytest.raises(ValidationError, match="must reference an agent"):
        Token(id="tok_3", kind=TokenKind.AGENT, hash=HASH, prefix="p", created_at=NOW)
    with pytest.raises(ValidationError, match="must not reference an agent"):
        Token(
            id="tok_4",
            kind=TokenKind.ADMIN,
            agent_id="agt_1",
            hash=HASH,
            prefix="p",
            created_at=NOW,
        )


def test_token_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError):
        Token(
            id="tok_1",
            kind=TokenKind.ADMIN,
            hash=HASH,
            prefix="p",
            created_at=datetime(2026, 1, 1),  # noqa: DTZ001
        )


@pytest.mark.parametrize("pattern", ["ssh.service.restart", "docker.container.*", "docker.*"])
def test_role_accepts_action_patterns(pattern: str) -> None:
    Role(id="operator", actions=(pattern,))


@pytest.mark.parametrize("pattern", ["*", "ssh", "ssh.*.restart", "SSH.x"])
def test_role_rejects_bad_patterns(pattern: str) -> None:
    with pytest.raises(ValidationError):
        Role(id="operator", actions=(pattern,))


def test_policy_subject_needs_exactly_one() -> None:
    PolicySubject(role="operator")
    with pytest.raises(ValidationError):
        PolicySubject()
    with pytest.raises(ValidationError):
        PolicySubject(role="operator", agent_id="agt_1")


def test_policy_and_decision() -> None:
    policy = Policy(
        id="pol_1",
        subject=PolicySubject(agent_id="agt_1"),
        actions=("ssh.service.restart",),
        resources=ResourceSelector(tags=("env:staging",)),
        effect=PolicyEffect.ALLOW,
    )
    assert policy.approval == "by_risk"
    decision = Decision.deny("no matching policy")
    assert not decision.allowed
    assert not decision.approval_required


def test_resource_tags() -> None:
    resource = Resource(
        id="res_1", type=ResourceType.SSH_HOST, name="h", tags=("env:prod", "site:home")
    )
    assert resource.has_tags(["env:prod"])
    assert not resource.has_tags(["env:prod", "env:staging"])


def test_secret_payload_never_leaks_in_repr() -> None:
    payload = SecretPayload(CredentialType.BASIC_AUTH, "pa55", {"username": "deploy"})
    assert "pa55" not in repr(payload)
    assert "pa55" not in str(payload)
    assert payload.secret_values() == ["pa55", "deploy"]
    payload.wipe()
    assert payload.reveal() == ""


def test_secret_payload_cannot_be_pickled() -> None:
    import pickle

    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(SecretPayload(CredentialType.API_TOKEN, "x"))


def test_credential_aad_binds_id_and_version() -> None:
    assert credential_aad("cred_1", 1) == b"agw-cred|cred_1|1"
    assert credential_aad("cred_1", 1) != credential_aad("cred_1", 2)


def test_audit_entry_hash_covers_every_field() -> None:
    entry = AuditEntry(
        event=AuditEventType.AGENT_CREATED,
        actor=Actor(type=ActorType.SYSTEM, id="cli"),
        seq=1,
        ts=NOW,
        prev_hash=GENESIS_HASH,
        hash=GENESIS_HASH,
    )
    base = entry.compute_hash()
    assert base == entry.model_copy(update={"hash": HASH}).compute_hash()
    assert base != entry.model_copy(update={"seq": 2}).compute_hash()
    assert base != entry.model_copy(update={"details": {"x": 1}}).compute_hash()


def test_audit_entry_round_trip_keeps_hash() -> None:
    entry = AuditEntry(
        event=AuditEventType.AGENT_CREATED,
        actor=Actor(type=ActorType.SYSTEM, id="cli"),
        seq=1,
        ts=datetime(2026, 10, 31, 10, 0, 0, 123000, tzinfo=UTC),
        prev_hash=GENESIS_HASH,
        hash=GENESIS_HASH,
    )
    restored = AuditEntry.model_validate_json(entry.model_dump_json())
    assert restored.compute_hash() == entry.compute_hash()


def test_execution_terminal_status() -> None:
    execution = Execution(
        id="exe_1",
        agent_id="agt_1",
        action="ssh.service.restart",
        resource_id="res_1",
        params={"service": "nginx"},
        params_digest=sha256_digest({"service": "nginx"}),
        status=ExecutionStatus.PENDING_APPROVAL,
        created_at=NOW,
    )
    assert not execution.is_terminal
    assert execution.model_copy(update={"status": ExecutionStatus.DENIED}).is_terminal
