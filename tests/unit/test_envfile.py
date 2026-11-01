from pathlib import Path

import pytest

from agent_gateway.common.envfile import read_env_var, save_env_var


def test_missing_file_or_key(tmp_path: Path) -> None:
    assert read_env_var(tmp_path / "nope", "A") is None
    (tmp_path / ".env").write_text("B=1\n", encoding="utf-8")
    assert read_env_var(tmp_path / ".env", "A") is None


def test_save_creates_then_replaces_and_keeps_other_lines(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("# mine\nVPS_HOST=example.org\n", encoding="utf-8")
    save_env_var(path, "AGW_ADMIN_TOKEN", "one", comment="admin token")
    save_env_var(path, "AGW_ADMIN_TOKEN", "two", comment="admin token")
    text = path.read_text(encoding="utf-8")
    assert text == "# mine\nVPS_HOST=example.org\n# admin token\nAGW_ADMIN_TOKEN=two\n"
    assert read_env_var(path, "AGW_ADMIN_TOKEN") == "two"
    assert read_env_var(path, "VPS_HOST") == "example.org"


@pytest.mark.parametrize(
    ("line", "expected"),
    [('A="x y"', "x y"), ("A='x'", "x"), ("export A=x", "x"), ("A = x ", "x"), ("A=", None)],
)
def test_read_formats(tmp_path: Path, line: str, expected: str | None) -> None:
    path = tmp_path / ".env"
    path.write_text(line + "\n", encoding="utf-8")
    assert read_env_var(path, "A") == expected


def test_rejects_multiline_values_and_bad_keys(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="single line"):
        save_env_var(tmp_path / ".env", "A", "x\nB=y")
    with pytest.raises(ValueError, match="invalid variable"):
        save_env_var(tmp_path / ".env", "a-b", "x")


def test_fills_the_empty_line_from_env_example(tmp_path: Path) -> None:
    example = Path(__file__).parents[2] / ".env.example"
    path = tmp_path / ".env"
    path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    assert read_env_var(path, "AGW_ADMIN_TOKEN") is None
    save_env_var(path, "AGW_ADMIN_TOKEN", "agw_tok_x", comment="unused when the key exists")
    text = path.read_text(encoding="utf-8")
    assert text.count("AGW_ADMIN_TOKEN=") == 1
    assert "unused when the key exists" not in text
    assert read_env_var(path, "AGW_ADMIN_TOKEN") == "agw_tok_x"
    assert text.startswith("# Agent Gateway")  # comments kept
