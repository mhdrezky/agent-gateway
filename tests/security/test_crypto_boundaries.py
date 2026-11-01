"""SPEC §4: only ``credentials`` may decrypt; other modules may at most derive subkeys."""

from pathlib import Path

from tests.security.test_import_boundaries import SOURCES, _imports, _module_name, _within

# Modules that may import ``modules.crypto`` at all, and what they may import from it.
ALLOWED: dict[str, tuple[str, ...]] = {
    "modules.crypto": ("modules.crypto",),
    "modules.credentials": ("modules.crypto",),
    # Token HMAC and audit anchors need ``KeyRing.subkey`` only, never the cipher.
    "modules.identity": ("modules.crypto.ports",),
    "modules.audit": ("modules.crypto.ports",),
    # The composition root wires the real implementations together.
    "apps": ("modules.crypto",),
    "cli": ("modules.crypto",),
}


def _allowed(source: str, name: str) -> bool:
    for package, prefixes in ALLOWED.items():
        if _within(source, package):
            return any(_within(name, prefix) for prefix in prefixes)
    return False


def test_only_credentials_can_reach_the_cipher() -> None:
    violations = [
        f"{_module_name(path)} imports {name}"
        for path in SOURCES
        for name in _imports(path)
        if _within(name, "modules.crypto") and not _allowed(_module_name(path), name)
    ]
    assert violations == []


def test_rule_detects_a_violation(tmp_path: Path) -> None:
    assert not _allowed("modules.identity.service", "modules.crypto.envelope")
    assert not _allowed("modules.resources.registry", "modules.crypto.ports")
    assert _allowed("modules.identity.service", "modules.crypto.ports.KeyRing")
    assert _allowed("modules.credentials.store", "modules.crypto.envelope")
