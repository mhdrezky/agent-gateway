"""Smoke test of the ``agw`` CLI against a temp data directory."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_gateway.cli import app

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
    return {"AGW_CONFIG_FILE": str(config)}


def test_keygen_refuses_to_overwrite(tmp_path: Path, env: dict[str, str]) -> None:
    key = tmp_path / "secrets" / "master.key"
    result = runner.invoke(app, ["keygen", "--out", str(key)])
    assert result.exit_code == 1


def test_full_setup(env: dict[str, str]) -> None:
    init = runner.invoke(app, ["init"], env=env)
    assert init.exit_code == 0, init.output
    assert "agw_tok_" in init.output
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
