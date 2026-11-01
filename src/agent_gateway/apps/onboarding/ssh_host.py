"""``agw-onboard-ssh``: register an SSH host with the gateway, one confirmed step at a time.

Runs on the admin's machine, talks to the running gateway's admin API, and checks the
host over SSH before anything is registered:

1. connect to the gateway with an admin token (from ``--admin-token``, ``AGW_ADMIN_TOKEN``,
   ``.env``, or a prompt; a prompted token can be saved to ``.env``)
2. host, port, and SSH user
3. the gateway's SSH key (reused if it already exists, otherwise created)
4. the host key, confirmed by the admin
5. a dedicated user (created by the admin if missing) with the public key in
   authorized_keys, verified by logging in
6. names (``<base>-server``, ``-key``, ``-operator``, ``-agent``), tags, allowed services
7. register through the admin API, then run ``ssh.system.info`` as the new agent
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Annotated, Any

import typer

from agent_gateway.apps.onboarding.naming import (
    Names,
    NamingError,
    check_base,
    check_name,
    names_for,
)
from agent_gateway.apps.onboarding.registration import (
    AdminClient,
    GatewayError,
    HostPlan,
    Registration,
)
from agent_gateway.apps.onboarding.server_setup import (
    OPTIONAL_GROUPS,
    create_user_with_key,
    install_key_for_current_user,
)
from agent_gateway.apps.onboarding.ssh_probe import (
    HostKey,
    ProbeError,
    check_login,
    fetch_host_key,
    load_or_create_key,
    public_key_line,
)
from agent_gateway.common.envfile import (
    ADMIN_TOKEN_VAR,
    DEFAULT_ENV_FILE,
    read_env_var,
    save_env_var,
)

DEFAULT_URL = "http://127.0.0.1:8080"
DEFAULT_KEY = Path("secrets/vps-deploy")
_NAME_WIDTH = 20
TOKEN_PREFIX = "agw_tok_"
TOKEN_ID_PATTERN = re.compile(r"^tok_[0-9A-Z]{26}$")
HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
USER_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
ENVIRONMENTS = ("prod", "staging", "dev")
USEFUL_GROUPS = {
    "docker": "can run docker commands (root-equivalent on that host)",
    "systemd-journal": "can read service logs (ssh.logs.tail)",
    "adm": "can read service logs (ssh.logs.tail)",
    "sudo": "may restart services if use_sudo is set and sudo needs no password",
}


def _step(number: int, title: str) -> None:
    typer.secho(f"\n[{number}/7] {title}", bold=True)


def _fail(message: str) -> None:
    typer.secho(message, fg=typer.colors.RED, err=True)


def _ask(label: str, check: Any, default: str | None = None, *, hide_input: bool = False) -> Any:
    """Prompt until ``check`` accepts the answer."""
    while True:
        value = typer.prompt(label, default=default, hide_input=hide_input)
        try:
            return check(value)
        except (ValueError, NamingError) as exc:
            _fail(str(exc))


def _token(value: str) -> str:
    """Catch the usual mix-ups before talking to the gateway."""
    value = value.strip()
    if TOKEN_ID_PATTERN.fullmatch(value):
        raise ValueError(
            "that is a token id (tok_...), not the token. The token looks like "
            "agw_tok_<id>_<secret> and was shown once when it was created; if it is lost, "
            "create a new one with `agw token create --admin`."
        )
    if not value.startswith(TOKEN_PREFIX):
        raise ValueError(f"an admin token starts with {TOKEN_PREFIX!r}")
    return value


def _host(value: str) -> str:
    value = value.strip()
    if not HOST_PATTERN.fullmatch(value):
        raise ValueError("enter a hostname or IP address")
    return value


def _port(value: str) -> int:
    port = int(value)
    if not 0 < port < 65536:
        raise ValueError("port must be between 1 and 65535")
    return port


def _user(value: str) -> str:
    value = value.strip()
    if not USER_PATTERN.fullmatch(value):
        raise ValueError("enter a valid Linux user name")
    return value


def _services(value: str) -> tuple[str, ...]:
    items = tuple(dict.fromkeys(s.strip() for s in value.split(",") if s.strip()))
    bad = [s for s in items if not SERVICE_PATTERN.fullmatch(s)]
    if bad:
        raise ValueError(f"invalid service name(s): {', '.join(bad)}")
    return items


def _environment(value: str) -> str:
    value = value.strip().lower()
    if value not in ENVIRONMENTS:
        raise ValueError(f"choose one of: {', '.join(ENVIRONMENTS)}")
    return value


def _choose_names(taken: set[str]) -> Names:
    while True:
        base = _ask("Base name (e.g. web01)", check_base)
        names = names_for(base)
        typer.echo(
            f"  resource   {names.resource}\n  credential {names.credential}\n"
            f"  role       {names.role}\n  agent      {names.agent}"
        )
        if not typer.confirm("Use these names?", default=True):
            names = Names(
                resource=_ask("Resource name", lambda v: check_name("resource", v), names.resource),
                credential=_ask(
                    "Credential name", lambda v: check_name("credential", v), names.credential
                ),
                role=_ask("Role name", lambda v: check_name("role", v), names.role),
                agent=_ask("Agent name", lambda v: check_name("agent", v), names.agent),
            )
        clashes = [
            n for n in (names.resource, names.credential, names.role, names.agent) if n in taken
        ]
        if not clashes:
            return names
        _fail(f"already in use: {', '.join(clashes)}. Pick another base name.")


def _confirm_host_key(host: str, host_key: HostKey) -> None:
    typer.echo(f"  algorithm   {host_key.algorithm}")
    typer.echo(f"  fingerprint {host_key.fingerprint}")
    short = host_key.algorithm.removeprefix("ssh-").split("-")[0]
    typer.echo(
        "\n  Check it on the server (from a session you trust) with:\n"
        f"    ssh-keygen -lf /etc/ssh/ssh_host_{short}_key.pub\n"
        f"  or against your known_hosts:\n    ssh-keygen -lf ~/.ssh/known_hosts -F {host}"
    )
    if not typer.confirm("Does the fingerprint match?", default=False):
        _fail("Stopped: the host key was not confirmed. Nothing was registered.")
        raise typer.Exit(1)


async def _authorize_and_verify(
    host: str, port: int, user: str, key: Any, host_key: HostKey
) -> None:
    public_key = public_key_line(key)
    if typer.confirm(f"  Does the user {user!r} already exist on {host}?", default=False):
        intro = f"As {user} on {host}, run:"
        commands = install_key_for_current_user(public_key)
    else:
        groups = [
            group
            for group, meaning in OPTIONAL_GROUPS.items()
            if typer.confirm(f"  Add {user} to group {group!r} ({meaning})?", default=False)
        ]
        intro = (
            f"Create {user} on {host}: log in as a user with sudo (e.g. ubuntu) and run.\n"
            "  The new user has no password, so it can only log in with the gateway's key:"
        )
        commands = create_user_with_key(user, public_key, groups)
    typer.echo(f"\n  {intro}\n")
    for command in commands:
        typer.echo(f"    {command}")
    typer.echo("")
    while True:
        answer = typer.prompt("Type 'ok' when done, or 'quit' to stop").strip().lower()
        if answer == "quit":
            _fail("Stopped. Nothing was registered.")
            raise typer.Exit(1)
        if answer != "ok":
            continue
        try:
            login = await check_login(host, port, user, key, host_key)
        except ProbeError as exc:
            _fail(f"  Login failed: {exc}")
            continue
        typer.secho(f"  Logged in as {login.user}.", fg=typer.colors.GREEN)
        for group, meaning in USEFUL_GROUPS.items():
            mark = "yes" if group in login.groups else "no "
            typer.echo(f"    [{mark}] group {group:<16} {meaning}")
        return


def _summary(names: Names, done: Registration) -> None:
    """Names, ids, and the one-time agent token together, so they are copied as one."""
    rows = [
        ("resource", names.resource, done.resource_id),
        ("credential", names.credential, done.credential_id),
        ("role", names.role, done.role_id),
        ("agent", names.agent, done.agent_id),
        ("policy", "", done.policy_id),
        ("token", "", done.token_id),
    ]
    typer.secho(
        f"\n{names.agent} on {names.resource} (agent token shown only once, store it now)",
        fg=typer.colors.YELLOW,
        bold=True,
    )
    for label, name, value in rows:
        typer.echo(f"  {label:<11}{name:<{_NAME_WIDTH}}{value or '-'}")
    typer.echo(f"  {'AGW_TOKEN':<11}{done.agent_token}")


async def _onboard(
    url: str, admin_token: str, key_path: Path, *, save_token_to: Path | None = None
) -> None:
    client = AdminClient(url, admin_token)
    try:
        _step(1, "Gateway")
        try:
            await client.check_admin()
            taken = await client.taken_names()
        except GatewayError as exc:
            _fail(f"  Cannot use the gateway at {url}: {exc}")
            raise typer.Exit(1) from None
        typer.secho(f"  Connected to {url} as admin.", fg=typer.colors.GREEN)
        if save_token_to is not None and typer.confirm(
            f"  Save this admin token to {save_token_to} as {ADMIN_TOKEN_VAR}?", default=True
        ):
            await asyncio.to_thread(
                save_env_var,
                save_token_to,
                ADMIN_TOKEN_VAR,
                admin_token,
                comment="Agent Gateway admin token (secret)",
            )
            typer.echo(f"  Saved to {save_token_to}; it is read automatically next time.")

        _step(2, "Host")
        host = _ask("Host (name or IP)", _host)
        port = _ask("SSH port", _port, "22")
        user = _ask("SSH user on the host (a dedicated user is best)", _user, "agent-gateway")

        _step(3, "Gateway SSH key")
        try:
            key, created = load_or_create_key(key_path)
        except ProbeError as exc:
            _fail(f"  {exc}")
            raise typer.Exit(1) from None
        private_key = await asyncio.to_thread(key_path.read_text, encoding="utf-8")
        state = "Created" if created else "Using existing"
        typer.echo(f"  {state} key {key_path} ({key.get_fingerprint('sha256')})")

        _step(4, "Host key")
        try:
            host_key = await fetch_host_key(host, port)
        except ProbeError as exc:
            _fail(f"  {exc}")
            raise typer.Exit(1) from None
        _confirm_host_key(host, host_key)

        _step(5, "Authorize the gateway key on the host")
        await _authorize_and_verify(host, port, user, key, host_key)

        _step(6, "Names and access")
        names = _choose_names(taken)
        environment = _ask("Environment (prod/staging/dev)", _environment, "prod")
        services = _ask(
            "Services agents may check/restart (comma separated, empty for none)",
            _services,
            "",
        )
        plan = HostPlan(
            names=names,
            host=host,
            port=port,
            user=user,
            host_key_fingerprint=host_key.fingerprint,
            host_key_algorithm=host_key.algorithm,
            private_key=private_key,
            tags=(f"env:{environment}",),
            allowed_services=services,
        )
        typer.echo(
            f"\n  {user}@{host}:{port} as {names.resource} (env:{environment}), "
            f"agent {names.agent} with role {names.role} on ssh.*"
        )
        if environment == "prod":
            typer.echo("  Medium-risk actions (restarts) will wait for approval.")
        if not typer.confirm("Register?", default=True):
            _fail("Stopped. Nothing was registered.")
            raise typer.Exit(1)

        _step(7, "Register and test")
        try:
            done = await client.register(plan)
        except GatewayError as exc:
            _fail(f"  Registration failed: {exc}")
            if exc.registration is not None and exc.registration.created():
                _fail("  Already created (remove or reuse them):")
                for line in exc.registration.created():
                    _fail(f"    {line}")
            raise typer.Exit(1) from None
        typer.echo(f"  Registered {names.resource}; testing it as {names.agent}...")

        if done.agent_token is None or done.resource_id is None:
            raise typer.Exit(1)
        try:
            result = await client.smoke_test(done.agent_token, done.resource_id)
        except GatewayError as exc:
            result = {"status": "error", "error": str(exc)}
        if result.get("status") == "succeeded":
            uptime = result["result"]["data"]["uptime"]["stdout"].strip()
            typer.secho(f"  ssh.system.info via the gateway: {uptime}", fg=typer.colors.GREEN)
        else:
            _fail(f"  ssh.system.info did not succeed: {json.dumps(result)[:400]}")

        typer.echo(
            "\nMCP config for the agent's project (.mcp.json), with the token in the "
            "AGW_TOKEN environment variable:\n"
            + json.dumps(
                {
                    "mcpServers": {
                        "agent-gateway": {
                            "type": "http",
                            "url": f"{url.rstrip('/')}/mcp",
                            "headers": {"Authorization": "Bearer ${AGW_TOKEN}"},
                        }
                    }
                },
                indent=2,
            )
        )
        _summary(names, done)
    finally:
        await client.aclose()


def main(
    url: Annotated[str, typer.Option(help="Gateway URL.", envvar="AGW_URL")] = DEFAULT_URL,
    admin_token: Annotated[
        str | None,
        typer.Option(help="Admin token (prompted if not set).", envvar="AGW_ADMIN_TOKEN"),
    ] = None,
    key: Annotated[
        Path, typer.Option(help="Gateway SSH private key; created if missing.")
    ] = DEFAULT_KEY,
    env_file: Annotated[
        Path, typer.Option(help=f"File holding {ADMIN_TOKEN_VAR}, written by `agw init`.")
    ] = DEFAULT_ENV_FILE,
) -> None:
    """Register an SSH host with the gateway, step by step."""
    save_to: Path | None = None
    token = admin_token
    if token is None:
        token = read_env_var(env_file, ADMIN_TOKEN_VAR)
        if token is not None:
            typer.echo(f"Using the admin token from {env_file} ({ADMIN_TOKEN_VAR}).")
        else:
            typer.echo(f"{ADMIN_TOKEN_VAR} is not set in {env_file.resolve()}.")
    if token is None:
        token = _ask("Admin token", _token, hide_input=True)
        save_to = env_file
    else:
        try:
            _token(token)
        except ValueError as exc:
            _fail(str(exc))
            raise typer.Exit(1) from None
    asyncio.run(_onboard(url, token, key, save_token_to=save_to))


def run() -> None:
    typer.run(main)


if __name__ == "__main__":
    run()
