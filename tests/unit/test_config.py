from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_gateway.config import CONFIG_FILE_ENV, load_settings

EXAMPLE = Path(__file__).parents[2] / "config" / "gateway.example.yaml"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(CONFIG_FILE_ENV, raising=False)
    monkeypatch.delenv("AGW_APPROVALS__TTL_MINUTES", raising=False)


def test_example_config_loads() -> None:
    settings = load_settings(EXAMPLE)
    assert settings.var_dir == Path("/app/var")
    assert settings.brokers.docker.enabled is False
    assert settings.brokers.sql.enabled is False


def test_env_overrides_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGW_APPROVALS__TTL_MINUTES", "30")
    settings = load_settings(EXAMPLE)
    assert settings.approvals.ttl_minutes == 30
    assert settings.execution.max_concurrent == 8


def test_config_file_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "gw.yaml"
    path.write_text("server:\n  port: 9000\n", encoding="utf-8")
    monkeypatch.setenv(CONFIG_FILE_ENV, str(path))
    assert load_settings().server.port == 9000


def test_unknown_keys_rejected(tmp_path: Path) -> None:
    path = tmp_path / "gw.yaml"
    path.write_text("approvals:\n  ttl_minuts: 5\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_settings(path)


def test_missing_explicit_file_fails(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_settings(tmp_path / "missing.yaml")
