"""Naming standard for onboarded hosts.

One base name (e.g. ``web01``) yields every object, each with a fixed suffix so its
kind is obvious wherever the name shows up (audit log, CLI output, MCP results)::

    web01-server     resource (ssh_host)
    web01-key        credential
    web01-operator   role
    web01-agent      agent
"""

import re
from dataclasses import dataclass

BASE_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
SUFFIXES = {
    "resource": "-server",
    "credential": "-key",
    "role": "-operator",
    "agent": "-agent",
}


class NamingError(ValueError):
    """A proposed name breaks the naming standard."""


@dataclass(frozen=True, slots=True)
class Names:
    resource: str
    credential: str
    role: str
    agent: str


def check_base(base: str) -> str:
    base = base.strip().lower()
    if not BASE_PATTERN.fullmatch(base) or base.endswith("-"):
        raise NamingError(
            "base name must start with a letter and use only a-z, 0-9 and '-' (max 40)"
        )
    for suffix in SUFFIXES.values():
        if base.endswith(suffix):
            raise NamingError(f"leave the suffix out of the base name: {suffix!r} is added for you")
    return base


def names_for(base: str) -> Names:
    base = check_base(base)
    return Names(**{kind: f"{base}{suffix}" for kind, suffix in SUFFIXES.items()})


def check_name(kind: str, name: str) -> str:
    """Validate a name the user typed instead of the default for ``kind``."""
    suffix = SUFFIXES[kind]
    name = name.strip().lower()
    if not name.endswith(suffix):
        raise NamingError(f"{kind} names must end with {suffix!r}")
    check_base(name.removesuffix(suffix))
    return name
