"""Fixed command templates for the SSH broker (P3: no arbitrary shell execution).

Commands are built as argv lists from constants and validated values, then
joined with ``shlex.join`` so every argument is shell-quoted.
"""

import re
import shlex

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.ssh.models import MAX_LOG_LINES, SERVICE_PATTERN, SshHostAttributes

SYSTEM_INFO_COMMANDS: dict[str, str] = {
    "uptime": shlex.join(["uptime"]),
    "disk": shlex.join(["df", "-hP"]),
    "memory": shlex.join(["free", "-b"]),
}

_SERVICE_RE = re.compile(SERVICE_PATTERN.removeprefix("^").removesuffix("$"))


def checked_service(service: str, attrs: SshHostAttributes) -> str:
    """Return ``service`` only if it is well formed and listed in ``allowed_services``."""
    # Params were validated already; check again so this module is safe on its own.
    if not _SERVICE_RE.fullmatch(service):
        raise BrokerError("invalid service name")
    if service not in attrs.allowed_services:
        raise BrokerError(f"service {service!r} is not in this host's allowed_services")
    return service


def _privileged(argv: list[str], attrs: SshHostAttributes) -> list[str]:
    # "-n" makes sudo fail instead of prompting when no NOPASSWD rule exists.
    return ["sudo", "-n", *argv] if attrs.use_sudo else argv


def service_status_command(service: str, attrs: SshHostAttributes) -> str:
    unit = checked_service(service, attrs)
    return shlex.join(["systemctl", "status", "--no-pager", "--", unit])


def service_restart_command(service: str, attrs: SshHostAttributes) -> str:
    unit = checked_service(service, attrs)
    return shlex.join(_privileged(["systemctl", "restart", "--", unit], attrs))


def logs_tail_command(service: str, lines: int, attrs: SshHostAttributes) -> str:
    unit = checked_service(service, attrs)
    if type(lines) is not int or not 1 <= lines <= MAX_LOG_LINES:
        raise BrokerError(f"lines must be between 1 and {MAX_LOG_LINES}")
    argv = ["journalctl", "--no-pager", "-o", "short-iso", "-u", unit, "-n", str(lines)]
    return shlex.join(_privileged(argv, attrs))


def sudo_command(command: str, attrs: SshHostAttributes) -> str:
    """Wrap an arbitrary command for ``ssh.sudo``; refuses unless the host opted in."""
    if not attrs.allow_sudo:
        raise BrokerError("ssh.sudo is not enabled for this host (allow_sudo is off)")
    if chr(0) in command:
        raise BrokerError("command must not contain NUL bytes")
    # "-n": fail instead of prompting when the user has no passwordless sudo.
    return shlex.join(["sudo", "-n", "--", "bash", "-lc", command])
