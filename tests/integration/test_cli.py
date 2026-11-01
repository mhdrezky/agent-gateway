"""Smoke test of the ``agw`` CLI against a temp data directory."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_gateway.cli import app
from agent_gateway.common.envfile import read_env_var

runner = CliRunner()


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


def test_keygen_refuses_to_overwrite(tmp_path: Path, env: dict[str, str]) -> None:
    key = tmp_path / "secrets" / "master.key"
    result = runner.invoke(app, ["keygen", "--out", str(key)])
    assert result.exit_code == 1


def test_full_setup(env: dict[str, str]) -> None:
    init = runner.invoke(app, ["init"], env=env)
    assert init.exit_code == 0, init.output
    lines = [line.split() for line in init.output.splitlines()]
    assert ["Admin", "token"] in lines
    id_row = next(row for row in lines if row[:1] == ["id"])
    saved_row = next(row for row in lines if row[:1] == ["saved"])
    assert id_row[1].startswith("tok_")
    assert saved_row[-1] == "(AGW_ADMIN_TOKEN)"
    assert "AGW_ADMIN_TOKEN" in init.output
    assert "agw_tok_" not in init.output  # saved, not printed
    saved = read_env_var(Path(env["AGW_ENV_FILE"]), "AGW_ADMIN_TOKEN")
    assert saved is not None
    assert saved.startswith("agw_tok_")
    again = runner.invoke(app, ["init"], env=env)
    assert "Already initialised" in again.output

    role = runner.invoke(app, ["role", "set", "operator", "-a", "ssh.service.*"], env=env)
    assert role.exit_code == 0, role.output

    agent = runner.invoke(app, ["agent", "create", "claude-ops", "-r", "operator"], env=env)
    assert agent.exit_code == 0, agent.output
    agent_id = json.loads(agent.output)["id"]

    token = runner.invoke(app, ["token", "create", "--agent", agent_id], env=env)
    assert token.exit_code == 0, token.output
    assert "agw_tok_" in token.output

    both = runner.invoke(app, ["token", "create", "--admin", "--agent", agent_id], env=env)
    assert both.exit_code == 2

    policy = runner.invoke(
        app,
        ["policy", "add", "-a", "ssh.service.restart", "--role", "operator", "--tag", "env:test"],
        env=env,
    )
    assert policy.exit_code == 0, policy.output

    pending = runner.invoke(app, ["approvals", "list"], env=env)
    assert json.loads(pending.output) == []

    verify = runner.invoke(app, ["audit", "verify"], env=env)
    assert verify.exit_code == 0, verify.output
    assert json.loads(verify.output)["ok"] is True


def test_errors_are_reported_cleanly(env: dict[str, str]) -> None:
    runner.invoke(app, ["init"], env=env)
    result = runner.invoke(app, ["approvals", "approve", "apr_missing"], env=env)
    assert result.exit_code == 1
    assert "approval_not_found" in result.output


def test_init_without_saving_prints_the_token(env: dict[str, str]) -> None:
    init = runner.invoke(app, ["init", "--no-save-env"], env=env)
    assert init.exit_code == 0, init.output
    assert "agw_tok_" in init.output
    assert not Path(env["AGW_ENV_FILE"]).exists()


def test_new_admin_token_replaces_the_saved_one(env: dict[str, str]) -> None:
    env_file = Path(env["AGW_ENV_FILE"])
    env_file.write_text("OTHER=1" + chr(10), encoding="utf-8")
    runner.invoke(app, ["init"], env=env)
    first = read_env_var(env_file, "AGW_ADMIN_TOKEN")
    created = runner.invoke(app, ["token", "create", "--admin"], env=env)
    assert created.exit_code == 0, created.output
    second = read_env_var(env_file, "AGW_ADMIN_TOKEN")
    assert second is not None
    assert second != first
    assert read_env_var(env_file, "OTHER") == "1"
    assert env_file.read_text(encoding="utf-8").count("AGW_ADMIN_TOKEN=") == 1


def test_agent_token_block_groups_id_agent_and_token(env: dict[str, str]) -> None:
    runner.invoke(app, ["init"], env=env)
    agent = runner.invoke(app, ["agent", "create", "web01-agent"], env=env)
    agent_id = json.loads(agent.output)["id"]
    created = runner.invoke(app, ["token", "create", "--agent", agent_id], env=env)
    rows = [line.split() for line in created.output.splitlines() if line.startswith("  ")]
    assert [row[0] for row in rows] == ["id", "agent", "token"]
    assert rows[1][1] == agent_id
    assert rows[2][1].startswith("agw_tok_")
