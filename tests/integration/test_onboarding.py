"""``agw-onboard-ssh`` against a real in-process gateway and an in-process SSH server."""

from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import asyncssh
import httpx
import pytest
import typer

from agent_gateway.apps.api_server.app import create_app
from agent_gateway.apps.onboarding import ssh_host
from agent_gateway.apps.onboarding.naming import NamingError, check_base, check_name, names_for
from agent_gateway.apps.onboarding.registration import AdminClient, GatewayError, HostPlan
from agent_gateway.apps.onboarding.server_setup import (
    create_user_with_key,
    install_key_for_current_user,
)
from agent_gateway.apps.onboarding.ssh_probe import (
    ProbeError,
    check_login,
    fetch_host_key,
    load_or_create_key,
)
from agent_gateway.common.envfile import read_env_var
from agent_gateway.config import Settings
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.identity.models import TokenKind
from agent_gateway.runtime import Gateway, build_gateway
from tests.integration.test_ssh_runner import SshServer, ssh_server  # noqa: F401 - fixture


@pytest.fixture
async def gateway(settings: Settings) -> AsyncIterator[tuple[Gateway, str, httpx.ASGITransport]]:
    gw = build_gateway(settings)
    await gw.start(background=False)
    admin = await gw.admin.issue_token(CLI_PRINCIPAL, TokenKind.ADMIN)
    transport = httpx.ASGITransport(app=create_app(gw, manage_lifecycle=False))
    yield gw, admin.plaintext.get_secret_value(), transport
    await gw.stop()


def _write_key(path: Path, key: asyncssh.SSHKey) -> None:
    path.write_bytes(key.export_private_key())


# ---- naming -------------------------------------------------------------------------------


def test_names_follow_the_standard() -> None:
    names = names_for("Tybozen")
    assert (names.resource, names.credential, names.role, names.agent) == (
        "tybozen-server",
        "tybozen-key",
        "tybozen-operator",
        "tybozen-agent",
    )


@pytest.mark.parametrize("base", ["", "1abc", "a b", "abc-", "tybozen-agent", "x" * 41])
def test_bad_base_names(base: str) -> None:
    with pytest.raises(NamingError):
        check_base(base)


def test_custom_names_keep_the_suffix() -> None:
    assert check_name("role", "ops-operator") == "ops-operator"
    with pytest.raises(NamingError, match="-operator"):
        check_name("role", "ops")


# ---- ssh probe --------------------------------------------------------------------------------


async def test_fetch_host_key_prefers_ed25519(ssh_server: SshServer) -> None:  # noqa: F811
    host_key = await fetch_host_key("127.0.0.1", ssh_server.port)
    assert host_key.algorithm == "ssh-ed25519"
    assert host_key.fingerprint == ssh_server.host_key.get_fingerprint("sha256")


async def test_fetch_host_key_unreachable() -> None:
    with pytest.raises(ProbeError, match="could not read a host key"):
        await fetch_host_key("127.0.0.1", 1)


async def test_check_login(ssh_server: SshServer) -> None:  # noqa: F811
    host_key = await fetch_host_key("127.0.0.1", ssh_server.port)
    login = await check_login(
        "127.0.0.1", ssh_server.port, "deploy", ssh_server.client_key, host_key
    )
    assert login.user == "ran id -un; id -Gn"  # the test server echoes the command

    stranger = asyncssh.generate_private_key("ssh-ed25519")
    with pytest.raises(ProbeError, match="rejected the key"):
        await check_login("127.0.0.1", ssh_server.port, "deploy", stranger, host_key)


def test_key_is_created_once_and_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "secrets" / "vps-deploy"
    key, created = load_or_create_key(path)
    assert created
    assert path.with_suffix(".pub").read_text().startswith("ssh-ed25519 ")
    again, created_again = load_or_create_key(path)
    assert not created_again
    assert again.get_fingerprint("sha256") == key.get_fingerprint("sha256")

    (tmp_path / "junk").write_text("not a key")
    with pytest.raises(ProbeError, match="not a usable private key"):
        load_or_create_key(tmp_path / "junk")


# ---- registration through the admin API ---------------------------------------------------


def _plan(server: SshServer, base: str = "tybozen") -> HostPlan:
    return HostPlan(
        names=names_for(base),
        host="127.0.0.1",
        port=server.port,
        user="deploy",
        host_key_fingerprint=server.host_key.get_fingerprint("sha256"),
        host_key_algorithm="ssh-ed25519",
        private_key=server.client_key.export_private_key().decode(),
        tags=("env:prod",),
        allowed_services=("docker",),
    )


async def test_register_and_smoke_test(
    gateway: tuple[Gateway, str, httpx.ASGITransport],
    ssh_server: SshServer,  # noqa: F811
) -> None:
    _, admin_token, transport = gateway
    client = AdminClient("http://gateway", admin_token, transport=transport)
    try:
        await client.check_admin()
        done = await client.register(_plan(ssh_server))
        assert done.agent_token is not None
        assert done.resource_id is not None
        assert {"tybozen-server", "tybozen-key", "tybozen-operator", "tybozen-agent"} <= (
            await client.taken_names()
        )

        result = await client.smoke_test(done.agent_token, done.resource_id)
        assert result["status"] == "succeeded", result
        assert "uptime" in ssh_server.commands

        with pytest.raises(GatewayError) as exc_info:
            await client.register(_plan(ssh_server))
        assert exc_info.value.registration is not None
        assert exc_info.value.registration.credential_id is not None  # partial work reported
    finally:
        await client.aclose()


async def test_agent_token_is_rejected_as_admin(
    gateway: tuple[Gateway, str, httpx.ASGITransport],
    ssh_server: SshServer,  # noqa: F811
) -> None:
    _, admin_token, transport = gateway
    admin = AdminClient("http://gateway", admin_token, transport=transport)
    done = await admin.register(_plan(ssh_server))
    await admin.aclose()
    assert done.agent_token is not None
    agent = AdminClient("http://gateway", done.agent_token, transport=transport)
    try:
        with pytest.raises(GatewayError, match="admin"):
            await agent.check_admin()
    finally:
        await agent.aclose()


# ---- the interactive flow -----------------------------------------------------------------


@pytest.fixture
def scripted(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Any]]:
    """Feed typer.prompt / typer.confirm from a list, in order."""
    answers: list[Any] = []

    def prompt(text: str, default: Any = None, **_: Any) -> Any:
        value = answers.pop(0)
        return default if value is None else value

    def confirm(text: str, default: bool = False, **_: Any) -> bool:
        value = answers.pop(0)
        assert isinstance(value, bool), f"expected a yes/no answer for {text!r}"
        return value

    monkeypatch.setattr(typer, "prompt", prompt)
    monkeypatch.setattr(typer, "confirm", confirm)
    yield answers
    assert answers == [], "not every scripted answer was used"


async def test_interactive_onboarding(
    gateway: tuple[Gateway, str, httpx.ASGITransport],
    ssh_server: SshServer,  # noqa: F811
    scripted: list[Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    gw, admin_token, transport = gateway
    monkeypatch.setattr(
        ssh_host,
        "AdminClient",
        lambda url, token: AdminClient(url, token, transport=transport),
    )
    key_path = tmp_path / "vps-deploy"
    _write_key(key_path, ssh_server.client_key)  # an existing key is reused, not replaced
    scripted.extend(
        [
            "127.0.0.1",  # host
            str(ssh_server.port),  # port
            None,  # user: default "agent-gateway"
            True,  # fingerprint matches
            False,  # user does not exist yet: show the create-user commands
            True,  # add to systemd-journal
            False,  # do not add to docker
            True,  # passwordless sudo
            "later",  # ignored, asks again
            "ok",  # key added to authorized_keys
            "tybozen",  # base name
            True,  # use the derived names
            None,  # environment: default prod
            "docker, nginx",  # allowed services
            True,  # register
        ]
    )
    await ssh_host._onboard("http://gateway", admin_token, key_path)

    out = capsys.readouterr().out
    assert "Using existing key" in out
    summary = out[out.index("tybozen-agent on tybozen-server") :].splitlines()[1:]
    labels = [line.split()[0] for line in summary if line.startswith("  ")]
    assert labels == ["resource", "credential", "role", "agent", "policy", "token", "AGW_TOKEN"]
    assert summary[-1].split()[1].startswith("agw_tok_")
    assert 'sudo adduser --disabled-password --gecos "" agent-gateway' in out
    assert "sudo usermod -aG systemd-journal agent-gateway" in out
    assert "usermod -aG docker" not in out
    assert "agent-gateway ALL=(ALL) NOPASSWD:ALL" in out
    assert "sudo rm -f /etc/sudoers.d/agent-gateway" in out
    assert "ssh.system.info via the gateway" in out
    assert "agw_tok_" in out
    agents = await gw.admin.list_agents(CLI_PRINCIPAL)
    assert [a.name for a in agents] == ["tybozen-agent"]
    [resource] = await gw.admin.list_resources(CLI_PRINCIPAL)
    assert resource.attributes["allowed_services"] == ["docker", "nginx"]
    assert resource.tags == ("env:prod",)


async def test_unconfirmed_fingerprint_stops_before_anything_is_registered(
    gateway: tuple[Gateway, str, httpx.ASGITransport],
    ssh_server: SshServer,  # noqa: F811
    scripted: list[Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gw, admin_token, transport = gateway
    monkeypatch.setattr(
        ssh_host,
        "AdminClient",
        lambda url, token: AdminClient(url, token, transport=transport),
    )
    scripted.extend(["127.0.0.1", str(ssh_server.port), None, False])
    with pytest.raises(typer.Exit):
        await ssh_host._onboard("http://gateway", admin_token, tmp_path / "k")
    assert await gw.admin.list_resources(CLI_PRINCIPAL) == []


async def test_prompted_token_can_be_saved_to_env_file(
    gateway: tuple[Gateway, str, httpx.ASGITransport],
    scripted: list[Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, admin_token, transport = gateway
    monkeypatch.setattr(
        ssh_host,
        "AdminClient",
        lambda url, token: AdminClient(url, token, transport=transport),
    )
    env_file = tmp_path / ".env"
    scripted.extend([True, "127.0.0.1", "1", None])  # save; then an unreachable host stops it
    with pytest.raises(typer.Exit):
        await ssh_host._onboard(
            "http://gateway", admin_token, tmp_path / "k", save_token_to=env_file
        )
    assert read_env_var(env_file, "AGW_ADMIN_TOKEN") == admin_token


def test_main_reads_the_token_from_the_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, Path | None]] = []

    async def fake_onboard(
        url: str, token: str, key: Path, *, save_token_to: Path | None = None
    ) -> None:
        calls.append((token, save_token_to))

    monkeypatch.setattr(ssh_host, "_onboard", fake_onboard)
    monkeypatch.delenv("AGW_ADMIN_TOKEN", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("AGW_ADMIN_TOKEN=agw_tok_from_file" + chr(10), encoding="utf-8")
    ssh_host.main(admin_token=None, env_file=env_file)
    assert calls == [("agw_tok_from_file", None)]

    monkeypatch.setattr(typer, "prompt", lambda *a, **k: "agw_tok_typed")
    ssh_host.main(admin_token=None, env_file=tmp_path / "missing.env")
    assert calls[-1] == ("agw_tok_typed", tmp_path / "missing.env")


def test_main_explains_a_token_id_in_the_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("AGW_ADMIN_TOKEN", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(
        "AGW_ADMIN_TOKEN=tok_01M6ABD1CTSR90TRCRHSQ12Y4E" + chr(10), encoding="utf-8"
    )
    with pytest.raises(typer.Exit):
        ssh_host.main(admin_token=None, env_file=env_file)
    assert "token id" in capsys.readouterr().err


def test_create_user_commands() -> None:
    commands = create_user_with_key("agent-gateway", "ssh-ed25519 AAAA agent-gateway", ["docker"])
    assert commands[0] == 'sudo adduser --disabled-password --gecos "" agent-gateway'
    assert "sudo install -d -m 700 -o agent-gateway -g agent-gateway /home/agent-gateway/.ssh" in (
        commands
    )
    assert any("tee -a /home/agent-gateway/.ssh/authorized_keys" in c for c in commands)
    assert commands[-1] == "sudo usermod -aG docker agent-gateway"


def test_public_key_is_shell_quoted() -> None:
    [_, echo, _] = install_key_for_current_user("ssh-ed25519 AAAA it's-me")
    assert echo.startswith("echo 'ssh-ed25519 AAAA it'")  # quote in the comment is escaped
