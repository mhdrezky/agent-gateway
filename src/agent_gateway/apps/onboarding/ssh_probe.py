"""SSH checks done from the admin's machine before a host is registered.

Uses asyncssh directly, so it works the same on Windows, where the bundled OpenSSH tools
are often too old for current servers.
"""

import os
from dataclasses import dataclass
from pathlib import Path

import asyncssh

# Preferred first. Must match the values the SSH broker accepts for host_key_algorithm.
HOST_KEY_ALGORITHMS = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
)
CONNECT_TIMEOUT_SECONDS = 15
KEY_COMMENT = "agent-gateway"


class ProbeError(Exception):
    """The host could not be reached or did not accept the key."""


@dataclass(frozen=True, slots=True)
class HostKey:
    algorithm: str
    fingerprint: str
    key: asyncssh.SSHKey


@dataclass(frozen=True, slots=True)
class LoginCheck:
    user: str
    groups: tuple[str, ...]


def load_or_create_key(path: Path) -> tuple[asyncssh.SSHKey, bool]:
    """Load the private key at ``path``, or create an ed25519 key there. Never overwrites."""
    if path.exists():
        try:
            return asyncssh.read_private_key(path), False
        except (asyncssh.KeyImportError, ValueError) as exc:
            raise ProbeError(
                f"{path} is not a usable private key without a passphrase: {exc}"
            ) from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519", comment=KEY_COMMENT)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.export_private_key())
    path.with_suffix(path.suffix + ".pub").write_bytes(key.export_public_key())
    return key, True


def public_key_line(key: asyncssh.SSHKey) -> str:
    return key.export_public_key("openssh").decode("ascii").strip()


async def fetch_host_key(host: str, port: int) -> HostKey:
    """Ask the server for its host key, trying the strongest algorithm first."""
    last_error: Exception | None = None
    for algorithm in HOST_KEY_ALGORITHMS:
        try:
            key = await asyncssh.get_server_host_key(
                host,
                port,
                server_host_key_algs=[algorithm],
                config=None,
            )
        except (OSError, asyncssh.Error) as exc:
            last_error = exc
            if isinstance(exc, OSError):
                break  # unreachable host: other algorithms will not help
            continue
        if key is not None:
            return HostKey(algorithm, key.get_fingerprint("sha256"), key)
    raise ProbeError(f"could not read a host key from {host}:{port}: {last_error}")


async def check_login(
    host: str, port: int, user: str, client_key: asyncssh.SSHKey, host_key: HostKey
) -> LoginCheck:
    """Log in with ``client_key``, trusting only ``host_key``, and report the user's groups."""
    try:
        conn = await asyncssh.connect(
            host,
            port,
            username=user,
            client_keys=[client_key],
            known_hosts=([host_key.key], [], []),
            server_host_key_algs=[host_key.algorithm],
            config=None,
            agent_path=None,
            password=None,
            kbdint_auth=False,
            connect_timeout=CONNECT_TIMEOUT_SECONDS,
        )
    except asyncssh.PermissionDenied as exc:
        raise ProbeError(
            f"{user}@{host} rejected the key: does the user exist, and is the key in "
            f"~{user}/.ssh/authorized_keys (owned by {user}, mode 600)?"
        ) from exc
    except asyncssh.HostKeyNotVerifiable as exc:
        raise ProbeError("the host key changed since it was read; stop and investigate") from exc
    except (OSError, asyncssh.Error) as exc:
        raise ProbeError(f"ssh connection to {host}:{port} failed: {exc}") from exc
    async with conn:
        result = await conn.run("id -un; id -Gn", check=False, stdin=asyncssh.DEVNULL)
    lines = str(result.stdout or "").splitlines()
    if result.exit_status != 0 or not lines:
        raise ProbeError(f"logged in, but `id` failed: {result.stderr!r}")
    groups = tuple(lines[1].split()) if len(lines) > 1 else ()
    return LoginCheck(user=lines[0].strip(), groups=groups)
