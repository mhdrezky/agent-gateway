"""Minimal ``.env`` reading and updating (``KEY=value`` lines) for local admin convenience.

Only used for values the admin chose to keep on their own machine, such as the admin
token. The file is created owner-only and must stay out of git.
"""

import os
import re
from pathlib import Path

DEFAULT_ENV_FILE = Path(".env")
ADMIN_TOKEN_VAR = "AGW_ADMIN_TOKEN"
_KEY = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def read_env_var(path: Path, key: str) -> str | None:
    """Return the value of ``key`` in ``path``, or ``None`` if the file or key is missing."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        name, sep, value = line.strip().partition("=")
        if sep and name.strip().removeprefix("export ").strip() == key:
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            return value or None
    return None


def save_env_var(path: Path, key: str, value: str, *, comment: str | None = None) -> None:
    """Set ``key=value`` in ``path``, replacing an existing line and keeping all others."""
    if not _KEY.fullmatch(key):
        raise ValueError(f"invalid variable name: {key!r}")
    if any(c in value for c in "\r\n"):
        raise ValueError("value must be a single line")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        lines = []
    entry = f"{key}={value}"
    replaced = False
    for index, line in enumerate(lines):
        name = line.strip().partition("=")[0].removeprefix("export ").strip()
        if name == key:
            lines[index] = entry
            replaced = True
    if not replaced:
        if comment:
            lines.append(f"# {comment}")
        lines.append(entry)

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
