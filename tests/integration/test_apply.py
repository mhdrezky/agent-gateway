"""``agw apply`` against a temp data directory (SPEC §20.6)."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from agent_gateway.cli import app

runner = CliRunner()
SECRET = "apply-secret-9f3c2a"
OTHER_SECRET = "apply-secret-rotated-77"

SEED = """\
roles:
  - id: staff
    description: Practice staff
    actions: ["model.chat"]
agents:
  - name: agentgate-practice
    description: Dev assistant
    roles: [staff]
users:
  - group: staff
    roles: [staff]
credentials:
  - name: dev-model
    type: api_token
    secret_env: DEMO_MODEL_KEY
resources:
  - name: dev-model
    type: model
    tags: ["env:dev"]
    credential: dev-model
    attributes:
      base_url: http://127.0.0.1:8000/v1
      model_id: demo
policies:
  - name: staff-model
    subject: {user_role: staff}
    actions: ["model.chat"]
    resources: {names: [dev-model]}
    effect: allow
    approval: never
  - name: practice-agent
    subject: {agent: agentgate-practice}
    actions: ["model.chat"]
    resources: {tags: ["env:dev"]}
    effect: allow
    approval: never
"""


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    key = tmp_path / "secrets" / "master.key"
    config = tmp_path / "gateway.yaml"
    config.write_text(
        f"var_dir: {(tmp_path / 'var').as_posix()}\nmaster_key_file: {key.as_posix()}\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["keygen", "--out", str(key)])
    assert result.exit_code == 0, result.output
    return {"AGW_CONFIG_FILE": str(config), "AGW_ENV_FILE": str(tmp_path / ".env")}


def _var(env: dict[str, str]) -> Path:
    for line in Path(env["AGW_CONFIG_FILE"]).read_text(encoding="utf-8").splitlines():
        if line.startswith("var_dir:"):
            return Path(line.split(":", 1)[1].strip())
    raise AssertionError("config has no var_dir")


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "seed.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _apply(env: dict[str, str], seed: Path, secret: str = SECRET) -> Result:
    return runner.invoke(app, ["apply", str(seed)], env={**env, "DEMO_MODEL_KEY": secret})


def _results(output: str) -> dict[tuple[str, str], str]:
    report = json.loads(output)
    return {(item["kind"], item["name"]): item["result"] for item in report["changes"]}


def _stored_text(env: dict[str, str]) -> str:
    root = _var(env)
    parts = [
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]
    return "\n".join(parts)


def _audit_bytes(env: dict[str, str]) -> bytes:
    root = _var(env) / "audit"
    if not root.exists():
        return b""
    return b"".join(path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file())


def test_apply_is_idempotent_and_hides_the_secret(env: dict[str, str], tmp_path: Path) -> None:
    runner.invoke(app, ["init"], env=env)
    seed = _write(tmp_path, SEED)
    first = _apply(env, seed)
    assert first.exit_code == 0, first.output
    report = json.loads(first.output)
    assert [item["result"] for item in report["changes"]] == ["created"] * 7
    assert SECRET not in first.output
    assert SECRET not in _stored_text(env)

    audit = _audit_bytes(env)
    second = _apply(env, seed)
    assert second.exit_code == 0, second.output
    assert set(_results(second.output).values()) == {"unchanged"}
    assert _audit_bytes(env) == audit

    runner.invoke(app, ["role", "set", "keeper", "-a", "model.chat"], env=env)
    kept = _apply(env, seed)
    assert kept.exit_code == 0, kept.output
    assert set(_results(kept.output).values()) == {"unchanged"}
    roles = json.loads(runner.invoke(app, ["role", "list"], env=env).output)
    assert {role["id"] for role in roles} == {"staff", "keeper"}

    agents = json.loads(runner.invoke(app, ["agent", "list"], env=env).output)
    users = json.loads(runner.invoke(app, ["user", "list"], env=env).output)
    policies = json.loads(runner.invoke(app, ["policy", "list"], env=env).output)
    edited = SEED.replace("description: Practice staff", "description: Senior staff").replace(
        "approval: never", "approval: requester", 1
    )
    edited = edited.replace(
        "    description: Dev assistant\n    roles: [staff]\n",
        "    description: Dev assistant\n    roles: [staff]\n    status: disabled\n",
    )
    changed = _apply(env, _write(tmp_path, edited))
    assert changed.exit_code == 0, changed.output
    results = _results(changed.output)
    assert results["role", "staff"] == "updated"
    assert results["agent", "agentgate-practice"] == "updated"
    assert results["policy", "staff-model"] == "updated"
    assert results["policy", "practice-agent"] == "unchanged"
    assert results["credential", "dev-model"] == "unchanged"
    again_agents = json.loads(runner.invoke(app, ["agent", "list"], env=env).output)
    again_users = json.loads(runner.invoke(app, ["user", "list"], env=env).output)
    again_policies = json.loads(runner.invoke(app, ["policy", "list"], env=env).output)
    assert again_agents[0]["id"] == agents[0]["id"]
    assert again_agents[0]["status"] == "disabled"
    assert again_users[0]["id"] == users[0]["id"]
    assert {item["id"] for item in again_policies} == {item["id"] for item in policies}
    staff_policy = next(item for item in again_policies if item["name"] == "staff-model")
    assert staff_policy["approval"] == "requester"


def test_apply_rotates_a_credential_only_when_the_secret_changes(
    env: dict[str, str], tmp_path: Path
) -> None:
    seed = _write(tmp_path, SEED)
    assert _apply(env, seed).exit_code == 0
    with_field = SEED.replace(
        "    secret_env: DEMO_MODEL_KEY\n",
        "    secret_env: DEMO_MODEL_KEY\n    fields: {username: mailer}\n",
    )
    field_change = _apply(env, _write(tmp_path, with_field))
    assert field_change.exit_code == 0, field_change.output
    assert _results(field_change.output)["credential", "dev-model"] == "updated"
    assert SECRET not in field_change.output

    rotated = _apply(env, _write(tmp_path, with_field), secret=OTHER_SECRET)
    assert rotated.exit_code == 0, rotated.output
    assert _results(rotated.output)["credential", "dev-model"] == "updated"
    assert OTHER_SECRET not in rotated.output
    assert OTHER_SECRET not in _stored_text(env)
    listed = json.loads(runner.invoke(app, ["credential", "list"], env=env).output)
    assert listed[0]["version"] == 3
    assert listed[0]["name"] == "dev-model"

    same = _apply(env, _write(tmp_path, with_field), secret=OTHER_SECRET)
    assert _results(same.output)["credential", "dev-model"] == "unchanged"
    listed = json.loads(runner.invoke(app, ["credential", "list"], env=env).output)
    assert listed[0]["version"] == 3


def test_apply_detaches_a_credential_the_seed_omits(env: dict[str, str], tmp_path: Path) -> None:
    seed = _write(tmp_path, SEED)
    assert _apply(env, seed).exit_code == 0
    before = json.loads(runner.invoke(app, ["resource", "list"], env=env).output)[0]
    assert before["credential_id"] is not None
    detached = SEED.replace("    credential: dev-model\n", "")
    result = _apply(env, _write(tmp_path, detached))
    assert result.exit_code == 0, result.output
    assert _results(result.output)["resource", "dev-model"] == "updated"
    after = json.loads(runner.invoke(app, ["resource", "list"], env=env).output)[0]
    assert after["id"] == before["id"]
    assert after["credential_id"] is None


def test_apply_stops_before_writing(env: dict[str, str], tmp_path: Path) -> None:
    missing = runner.invoke(app, ["apply", str(_write(tmp_path, SEED))], env=env)
    assert missing.exit_code == 1
    assert "DEMO_MODEL_KEY" in missing.output
    assert not (_var(env) / "credentials.json").exists()

    duplicate = SEED.replace("  - id: staff\n", "  - id: staff\n  - id: staff\n", 1)
    refused = _apply(env, _write(tmp_path, duplicate))
    assert refused.exit_code == 1
    assert "more than once" in refused.output
    assert not (_var(env) / "roles.json").exists()

    unknown = SEED.replace("roles: [staff]", "roles: [missing]")
    refused = _apply(env, _write(tmp_path, unknown))
    assert refused.exit_code == 1
    assert "unknown role" in refused.output
    assert not (_var(env) / "agents.json").exists()

    bad_model = SEED.replace("base_url: http://127.0.0.1:8000/v1", "base_url: not-a-url")
    refused = _apply(env, _write(tmp_path, bad_model))
    assert refused.exit_code == 1
    assert "invalid_params" in refused.output
    assert not (_var(env) / "roles.json").exists()


def test_apply_refuses_a_type_change_without_writing_the_rest(
    env: dict[str, str], tmp_path: Path
) -> None:
    assert _apply(env, _write(tmp_path, SEED)).exit_code == 0
    changed = SEED.replace("type: api_token", "type: basic_auth").replace(
        "description: Practice staff", "description: Senior staff"
    )
    refused = _apply(env, _write(tmp_path, changed))
    assert refused.exit_code == 1
    assert "conflict" in refused.output
    roles = json.loads(runner.invoke(app, ["role", "list"], env=env).output)
    assert roles[0]["description"] == "Practice staff"
    listed = json.loads(runner.invoke(app, ["credential", "list"], env=env).output)
    assert listed[0]["type"] == "api_token"
    assert listed[0]["version"] == 1


def test_apply_refuses_an_ambiguous_stored_name(env: dict[str, str], tmp_path: Path) -> None:
    secret = tmp_path / "one.txt"
    secret.write_text("one", encoding="utf-8")
    for _ in range(2):
        added = runner.invoke(
            app,
            ["credential", "add", "dev-model", "api_token", "--value-file", str(secret)],
            env=env,
        )
        assert added.exit_code == 0, added.output
    refused = _apply(env, _write(tmp_path, SEED))
    assert refused.exit_code == 1
    assert "more than one credential" in refused.output
    assert not (_var(env) / "roles.json").exists()
