"""Crash-safe file replacement (SPEC §6.3) and cleanup of leftovers.

These helpers are synchronous; async callers run them in a worker thread.
"""

import os
import re
import tempfile
from datetime import datetime
from pathlib import Path

TEMP_MARKER = ".tmp-"
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def is_safe_name(name: str) -> bool:
    """A single path component that cannot escape its directory or look like a temp file."""
    return SAFE_NAME.fullmatch(name) is not None and TEMP_MARKER not in name


def atomic_write_bytes(target: Path, data: bytes) -> None:
    """Write ``data`` to ``target`` so readers see either the old or the new file, never a mix.

    The caller must hold the lock for ``target``.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=f"{target.name}{TEMP_MARKER}")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    fsync_dir(target.parent)


def unlink_durable(target: Path) -> bool:
    """Remove ``target`` and persist the directory entry. Return ``True`` if it existed."""
    try:
        target.unlink()
    except FileNotFoundError:
        return False
    fsync_dir(target.parent)
    return True


def read_bytes_or_none(target: Path) -> bytes | None:
    try:
        return target.read_bytes()
    except FileNotFoundError:
        return None


def fsync_dir(directory: Path) -> None:
    """Persist directory entries (renames, unlinks). A no-op where the OS does not support it."""
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def cleanup_stale_temp_files(root: Path, *, older_than: datetime | None = None) -> list[Path]:
    """Delete ``*.tmp-*`` files left under ``root`` by a crash mid-write. Run at startup.

    With ``older_than``, only files last modified before that instant are removed, so a
    write in progress in another process (e.g. the CLI) is left alone.
    """
    if not root.is_dir():
        return []
    cutoff = older_than.timestamp() if older_than is not None else None
    removed: list[Path] = []
    for path in root.rglob(f"*{TEMP_MARKER}*"):
        if not path.is_file():
            continue
        if cutoff is not None and path.stat().st_mtime >= cutoff:
            continue
        path.unlink(missing_ok=True)
        removed.append(path)
    return removed
