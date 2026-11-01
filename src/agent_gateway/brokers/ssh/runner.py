"""Run fixed commands over SSH with a pinned host key."""

import hmac
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

import asyncssh

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.ssh.models import SshHostAttributes
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload

PASSPHRASE_FIELD = "passphrase"
CONNECT_TIMEOUT_SECONDS = 15


@dataclass(frozen=True, slots=True)
class CommandOutput:
    exit_code: int | None
    stdout: str
    stderr: str


class SshRunner(Protocol):
    async def run(
        self,
        attrs: SshHostAttributes,
        credential: SecretPayload | None,
        commands: Sequence[str],
    ) -> list[CommandOutput]:
        """Run each command in order over one connection."""
        ...


class _PinnedHostKeyClient(asyncssh.SSHClient):
    """Trusts exactly one host key, identified by its SHA-256 fingerprint."""

    def __init__(self, fingerprint: str) -> None:
        self._fingerprint = fingerprint

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        presented = key.get_fingerprint("sha256")
        return hmac.compare_digest(presented.encode(), self._fingerprint.encode())


def _client_key(credential: SecretPayload | None) -> asyncssh.SSHKey:
    if credential is None or credential.type is not CredentialType.SSH_PRIVATE_KEY:
        raise BrokerError("resource needs an ssh_private_key credential")
    passphrase = (
        credential.field(PASSPHRASE_FIELD) if PASSPHRASE_FIELD in credential.field_names() else None
    )
    try:
        return asyncssh.import_private_key(credential.reveal(), passphrase)
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise BrokerError("ssh credential is not a usable private key") from exc


class AsyncsshRunner:
    async def run(
        self,
        attrs: SshHostAttributes,
        credential: SecretPayload | None,
        commands: Sequence[str],
    ) -> list[CommandOutput]:
        key = _client_key(credential)
        fingerprint = attrs.host_key_fingerprint
        try:
            conn = await asyncssh.connect(
                attrs.host,
                attrs.port,
                username=attrs.username,
                client_keys=[key],
                # An empty trust set (not None, which disables checking) forces every
                # host key through validate_host_public_key. No auto-accept.
                known_hosts=([], [], []),
                server_host_key_algs="default",
                client_factory=lambda: _PinnedHostKeyClient(fingerprint),
                config=None,
                agent_path=None,
                password=None,
                kbdint_auth=False,
                connect_timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except asyncssh.HostKeyNotVerifiable as exc:
            raise BrokerError("ssh host key does not match host_key_fingerprint") from exc
        except asyncssh.PermissionDenied as exc:
            raise BrokerError("ssh authentication failed") from exc
        except (OSError, asyncssh.Error) as exc:
            raise BrokerError("ssh connection failed") from exc

        outputs: list[CommandOutput] = []
        async with conn:
            for command in commands:
                completed = await conn.run(command, check=False, stdin=asyncssh.DEVNULL)
                outputs.append(
                    CommandOutput(
                        exit_code=completed.exit_status,
                        stdout=_text(completed.stdout),
                        stderr=_text(completed.stderr),
                    )
                )
        return outputs


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
