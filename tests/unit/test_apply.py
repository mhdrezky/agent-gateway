"""Seed parsing for ``agw apply`` (SPEC §20.6). No gateway is started."""

from pathlib import Path

import pytest

from agent_gateway.common.errors import InvalidParamsError
from agent_gateway.modules.administration.apply import load_seed, read_secrets

EXAMPLE = Path(__file__).parents[2] / "config" / "seed.example.yaml"
SECRET = "apply-secret-9f3c2a"


def test_example_seed_loads() -> None:
    seed = load_seed(EXAMPLE)
    assert [role.id for role in seed.roles] == ["staff", "author"]
    assert seed.credentials[0].secret_env == "AGW_SAMPLE_DB_PASSWORD"
    assert seed.policies[0].approval.value == "requester"


def test_seed_must_be_a_mapping(tmp_path: Path) -> None:
    path = tmp_path / "seed.yaml"
    path.write_text("- just-a-list\n", encoding="utf-8")
    with pytest.raises(InvalidParamsError, match="mapping"):
        load_seed(path)


def test_seed_rejects_yaml_that_does_not_parse(tmp_path: Path) -> None:
    path = tmp_path / "seed.yaml"
    path.write_text(":\n  [\n", encoding="utf-8")
    with pytest.raises(InvalidParamsError, match="not valid YAML"):
        load_seed(path)


def test_seed_rejects_an_inline_secret(tmp_path: Path) -> None:
    path = tmp_path / "seed.yaml"
    path.write_text(
        "credentials:\n"
        "  - name: dev-model\n"
        "    type: api_token\n"
        "    secret_env: AGW_DEV_MODEL_KEY\n"
        f"    value: {SECRET}\n",
        encoding="utf-8",
    )
    with pytest.raises(InvalidParamsError, match="invalid seed fields") as caught:
        load_seed(path)
    assert SECRET not in str(caught.value)


def test_seed_rejects_a_repeated_name(tmp_path: Path) -> None:
    path = tmp_path / "seed.yaml"
    path.write_text("roles:\n  - id: staff\n  - id: staff\n", encoding="utf-8")
    with pytest.raises(InvalidParamsError, match="more than once"):
        load_seed(path)


def test_secret_file_drops_one_trailing_newline(tmp_path: Path) -> None:
    secret = tmp_path / "key.txt"
    secret.write_bytes(f"{SECRET}\r\n".encode())
    path = tmp_path / "seed.yaml"
    path.write_text(
        "credentials:\n  - name: dev-model\n    type: api_token\n    secret_file: key.txt\n",
        encoding="utf-8",
    )
    payloads = read_secrets(load_seed(path), path.parent)
    try:
        assert payloads["dev-model"].reveal() == SECRET
    finally:
        payloads["dev-model"].wipe()


def test_missing_environment_variable_names_the_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AGW_DEV_MODEL_KEY", raising=False)
    path = tmp_path / "seed.yaml"
    path.write_text(
        "credentials:\n"
        "  - name: dev-model\n"
        "    type: api_token\n"
        "    secret_env: AGW_DEV_MODEL_KEY\n",
        encoding="utf-8",
    )
    with pytest.raises(InvalidParamsError, match="AGW_DEV_MODEL_KEY"):
        read_secrets(load_seed(path), path.parent)
