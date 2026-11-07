"""Enforce the module dependency rules of SPEC §4 by static analysis of imports."""

import ast
from pathlib import Path

import pytest

PACKAGE = "agent_gateway"
SRC = Path(__file__).parents[2] / "src" / PACKAGE

# (source package, forbidden import prefixes)
RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "brokers",
        ("apps", "cli", "modules.execution", "modules.authorization", "modules.crypto"),
    ),
    ("apps", ("brokers",)),
    # P6: the MCP server is a thin REST client; it reaches the engine only over HTTP.
    ("apps.mcp_server", ("modules", "brokers", "runtime", "cli", "apps.api_server")),
    # Only the composition root (runtime, cli, apps) wires implementations together.
    ("modules", ("apps", "cli", "runtime")),
    ("brokers", ("runtime",)),
    ("modules.administration", ("modules.crypto", "brokers", "modules.execution")),
    (
        "modules.authorization",
        ("modules.crypto", "modules.storage", "brokers.ssh", "brokers.docker"),
    ),
    ("modules.action_registry", ("modules.crypto",)),
    ("modules.approvals", ("modules.crypto",)),
    ("modules.resources", ("modules.crypto",)),
    ("modules.execution", ("modules.crypto",)),
    ("modules.model_endpoints", ("modules.crypto", "brokers")),
    ("common", ("modules", "brokers", "apps", "cli", "config")),
]


def _module_name(path: Path) -> str:
    parts = path.relative_to(SRC).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return {
        name.removeprefix(f"{PACKAGE}.")
        for name in found
        if name == PACKAGE or name.startswith(f"{PACKAGE}.")
    }


def _within(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(f"{prefix}.")


SOURCES = sorted(SRC.rglob("*.py"))


def test_sources_found() -> None:
    assert SOURCES


def test_no_relative_imports() -> None:
    offenders = [
        str(path.relative_to(SRC))
        for path in SOURCES
        if any(
            isinstance(node, ast.ImportFrom) and node.level > 0
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        )
    ]
    assert offenders == []


@pytest.mark.parametrize(("source", "forbidden"), RULES, ids=[rule[0] for rule in RULES])
def test_import_rule(source: str, forbidden: tuple[str, ...]) -> None:
    violations = [
        f"{_module_name(path)} imports {name}"
        for path in SOURCES
        if _within(_module_name(path), source)
        for name in _imports(path)
        if any(_within(name, prefix) for prefix in forbidden)
    ]
    assert violations == []
