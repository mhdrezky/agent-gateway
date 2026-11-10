"""``agw``: the local admin CLI (SPEC §20.3).

The CLI works on the same ``var/`` directory as the server, under the same file locks,
so it can run while the server is up. Whoever can read the master key is the admin.
``agw apply`` creates or updates the objects in a seed file (SPEC §20.6).
"""

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import BaseModel, ValidationError

from agent_gateway.common.envfile import ADMIN_TOKEN_VAR, DEFAULT_ENV_FILE, save_env_var
from agent_gateway.common.errors import GatewayError, ResourceNotFoundError
from agent_gateway.config import Settings, load_settings
from agent_gateway.modules.administration.apply import apply_file
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.approvals.models import ApprovalStatus
from agent_gateway.modules.audit.models import Actor, ActorType
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.catalog.models import catalog_out
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.crypto.keyring import generate_master_key
from agent_gateway.modules.identity.models import AgentStatus, IssuedToken, TokenKind, UserMatch
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.runtime import Gateway, build_gateway

app = typer.Typer(help="Agent Gateway admin CLI.", no_args_is_help=True)
agent_app = typer.Typer(help="Manage agents.", no_args_is_help=True)
token_app = typer.Typer(help="Manage API tokens.", no_args_is_help=True)
resource_app = typer.Typer(help="Manage resources.", no_args_is_help=True)
credential_app = typer.Typer(help="Manage credentials (write-only).", no_args_is_help=True)
role_app = typer.Typer(help="Manage roles.", no_args_is_help=True)
policy_app = typer.Typer(help="Manage policies.", no_args_is_help=True)
user_app = typer.Typer(help="Map OIDC users to roles (users.json).", no_args_is_help=True)
approvals_app = typer.Typer(help="Review pending approvals.", no_args_is_help=True)
audit_app = typer.Typer(help="Inspect the audit log.", no_args_is_help=True)
elevation_app = typer.Typer(
    help="Time-boxed windows for privileged actions (ssh.sudo).", no_args_is_help=True
)
catalog_app = typer.Typer(
    help="What resources offer, read by `agw sync` (tables, MCP tools).", no_args_is_help=True
)
for sub, name in [
    (agent_app, "agent"),
    (token_app, "token"),
    (resource_app, "resource"),
    (credential_app, "credential"),
    (role_app, "role"),
    (policy_app, "policy"),
    (user_app, "user"),
    (approvals_app, "approvals"),
    (audit_app, "audit"),
    (elevation_app, "elevation"),
    (catalog_app, "catalog"),
]:
    app.add_typer(sub, name=name)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to gateway.yaml.", envvar="AGW_CONFIG_FILE"),
]


def _settings(config: Path | None) -> Settings:
    return load_settings(config)


def _run(config: Path | None, fn: Callable[[Gateway], Awaitable[Any]]) -> Any:
    gateway = build_gateway(_settings(config))

    async def main() -> Any:
        return await fn(gateway)

    try:
        return asyncio.run(main())
    except GatewayError as exc:
        typer.secho(f"error ({exc.code}): {exc.message}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None


def _print(value: Any) -> None:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif isinstance(value, list):
        value = [v.model_dump(mode="json") if isinstance(v, BaseModel) else v for v in value]
    typer.echo(json.dumps(value, indent=2))


def _token_block(title: str, rows: list[tuple[str, str]]) -> None:
    """Print a token's id and related values together, aligned, as one block."""
    typer.secho(f"\n{title}", fg=typer.colors.YELLOW, bold=True)
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        typer.echo(f"  {label:<{width}}  {value}")


def _show_token_once(issued: IssuedToken) -> None:
    rows = [("id", issued.token.id)]
    if issued.token.agent_id is not None:
        rows.append(("agent", issued.token.agent_id))
    rows.append(("token", issued.plaintext.get_secret_value()))
    _token_block(
        f"{issued.token.kind.value.capitalize()} token (shown only once, store it now)", rows
    )


EnvFileOption = Annotated[
    Path,
    typer.Option(help="Where to save the admin token as AGW_ADMIN_TOKEN.", envvar="AGW_ENV_FILE"),
]
SaveEnvOption = Annotated[
    bool, typer.Option("--save-env/--no-save-env", help="Save the admin token to --env-file.")
]


def _deliver_admin_token(issued: IssuedToken, env_file: Path, save: bool) -> None:
    """Save the admin token to ``env_file`` and say where; print it if saving is off or fails."""
    if save:
        try:
            save_env_var(
                env_file,
                ADMIN_TOKEN_VAR,
                issued.plaintext.get_secret_value(),
                comment="Agent Gateway admin token (secret)",
            )
        except OSError as exc:
            typer.secho(f"Could not write {env_file}: {exc}", fg=typer.colors.RED, err=True)
        else:
            _token_block(
                "Admin token",
                [
                    ("id", issued.token.id),
                    ("saved", f"{env_file.resolve()} ({ADMIN_TOKEN_VAR})"),
                ],
            )
            typer.echo(
                "  Anyone who can read that file is a gateway admin: keep it private and out of "
                "git.\n  agw-onboard-ssh reads it automatically."
            )
            return
    _show_token_once(issued)


# ---- setup ------------------------------------------------------------------------------


@app.command()
def keygen(
    out: Annotated[Path, typer.Option(help="Where to write the new master key.")] = Path(
        "secrets/master.key"
    ),
) -> None:
    """Generate a new master key file. Refuses to overwrite an existing key."""
    if out.exists():
        typer.secho(
            f"{out} already exists; refusing to overwrite it.", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(1)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(generate_master_key() + "\n")
    typer.echo(f"Master key written to {out}. Back it up separately; it cannot be recovered.")


@app.command()
def init(
    config: ConfigOption = None,
    env_file: EnvFileOption = DEFAULT_ENV_FILE,
    save_env: SaveEnvOption = True,
) -> None:
    """Create the data directory and the first admin token (saved to .env by default)."""

    async def go(gw: Gateway) -> None:
        gw.settings.var_dir.mkdir(parents=True, exist_ok=True)
        await gw.start(background=False)
        if any(t.kind is TokenKind.ADMIN for t in await gw.admin.list_tokens(CLI_PRINCIPAL)):
            typer.echo("Already initialised; use `agw token create --admin` for another token.")
            return
        issued = await gw.admin.issue_token(CLI_PRINCIPAL, TokenKind.ADMIN)
        typer.echo(f"Initialised {gw.settings.var_dir}.")
        _deliver_admin_token(issued, env_file, save_env)

    _run(config, go)


@app.command()
def apply(
    seed: Annotated[
        Path,
        typer.Argument(
            help="Seed file. Secrets come from env vars or files it names, never from the file.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    config: ConfigOption = None,
) -> None:
    """Create or update the objects a seed declares. Objects absent from the seed are kept."""
    _print(_run(config, lambda gw: apply_file(gw.admin, CLI_PRINCIPAL, seed)))


@app.command()
def serve(
    config: ConfigOption = None,
    host: Annotated[str | None, typer.Option(help="Override server.host.")] = None,
    port: Annotated[int | None, typer.Option(help="Override server.port.")] = None,
) -> None:
    """Run the REST API server."""
    import uvicorn

    from agent_gateway.apps.api_server.app import create_app

    settings = _settings(config)
    uvicorn.run(
        create_app(build_gateway(settings)),
        host=host or settings.server.host,
        port=port or settings.server.port,
        workers=1,
    )


# ---- agents and tokens ------------------------------------------------------------------


@agent_app.command("create")
def agent_create(
    name: str,
    role: Annotated[list[str] | None, typer.Option("--role", "-r")] = None,
    description: str = "",
    config: ConfigOption = None,
) -> None:
    _print(
        _run(
            config,
            lambda gw: gw.admin.create_agent(
                CLI_PRINCIPAL, name, description=description, roles=role or []
            ),
        )
    )


@agent_app.command("list")
def agent_list(config: ConfigOption = None) -> None:
    _print(_run(config, lambda gw: gw.admin.list_agents(CLI_PRINCIPAL)))


@agent_app.command("set-roles")
def agent_set_roles(
    agent_id: str,
    role: Annotated[list[str], typer.Option("--role", "-r")],
    config: ConfigOption = None,
) -> None:
    _print(_run(config, lambda gw: gw.admin.update_agent(CLI_PRINCIPAL, agent_id, roles=role)))


@agent_app.command("disable")
def agent_disable(agent_id: str, config: ConfigOption = None) -> None:
    _print(
        _run(
            config,
            lambda gw: gw.admin.update_agent(CLI_PRINCIPAL, agent_id, status=AgentStatus.DISABLED),
        )
    )


@agent_app.command("enable")
def agent_enable(agent_id: str, config: ConfigOption = None) -> None:
    _print(
        _run(
            config,
            lambda gw: gw.admin.update_agent(CLI_PRINCIPAL, agent_id, status=AgentStatus.ACTIVE),
        )
    )


@token_app.command("create")
def token_create(
    agent: Annotated[str | None, typer.Option(help="Agent id for an agent token.")] = None,
    admin: Annotated[bool, typer.Option("--admin", help="Create an admin token.")] = False,
    expires_days: Annotated[int | None, typer.Option(min=1)] = None,
    config: ConfigOption = None,
    env_file: EnvFileOption = DEFAULT_ENV_FILE,
    save_env: Annotated[
        bool,
        typer.Option("--save-env/--no-save-env", help="With --admin: save it to --env-file."),
    ] = True,
) -> None:
    if admin == (agent is not None):
        typer.secho("Pass exactly one of --agent or --admin.", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    expires_at = datetime.now(UTC) + timedelta(days=expires_days) if expires_days else None
    kind = TokenKind.ADMIN if admin else TokenKind.AGENT
    issued = _run(
        config,
        lambda gw: gw.admin.issue_token(CLI_PRINCIPAL, kind, agent_id=agent, expires_at=expires_at),
    )
    if admin:
        _deliver_admin_token(issued, env_file, save_env)
    else:
        _show_token_once(issued)


@token_app.command("list")
def token_list(agent: str | None = None, config: ConfigOption = None) -> None:
    _print(_run(config, lambda gw: gw.admin.list_tokens(CLI_PRINCIPAL, agent_id=agent)))


@token_app.command("revoke")
def token_revoke(token_id: str, config: ConfigOption = None) -> None:
    _print(_run(config, lambda gw: gw.admin.revoke_token(CLI_PRINCIPAL, token_id)))


# ---- resources and credentials ----------------------------------------------------------


@resource_app.command("add")
def resource_add(
    type: ResourceType,
    name: str,
    attributes: Annotated[str, typer.Option(help="Attributes as a JSON object.")] = "{}",
    tag: Annotated[list[str] | None, typer.Option("--tag", "-t")] = None,
    credential: Annotated[str | None, typer.Option(help="Credential id.")] = None,
    config: ConfigOption = None,
) -> None:
    attrs = json.loads(attributes)
    _print(
        _run(
            config,
            lambda gw: gw.admin.create_resource(
                CLI_PRINCIPAL,
                type,
                name,
                tags=tag or [],
                attributes=attrs,
                credential_id=credential,
            ),
        )
    )


@resource_app.command("list")
def resource_list(config: ConfigOption = None) -> None:
    _print(_run(config, lambda gw: gw.admin.list_resources(CLI_PRINCIPAL)))


@resource_app.command("delete")
def resource_delete(resource_id: str, config: ConfigOption = None) -> None:
    deleted = _run(config, lambda gw: gw.admin.delete_resource(CLI_PRINCIPAL, resource_id))
    typer.echo("deleted" if deleted else "not found")


@resource_app.command("sudo")
def resource_sudo(
    resource_id: str,
    enable: Annotated[
        bool, typer.Option("--enable/--disable", help="Allow or stop ssh.sudo on this host.")
    ],
    config: ConfigOption = None,
) -> None:
    """Turn the privileged ssh.sudo action on or off for one SSH host. Takes effect at once."""

    async def go(gw: Gateway) -> Resource:
        resources = await gw.admin.list_resources(CLI_PRINCIPAL, type=ResourceType.SSH_HOST)
        current = next((r for r in resources if r.id == resource_id), None)
        if current is None:
            raise ResourceNotFoundError(f"ssh_host resource {resource_id} not found")
        return await gw.admin.update_resource(
            CLI_PRINCIPAL, resource_id, attributes={**current.attributes, "allow_sudo": enable}
        )

    updated = _run(config, go)
    state = "ENABLED" if updated.attributes.get("allow_sudo") else "disabled"
    typer.echo(f"ssh.sudo is {state} on {updated.name} ({updated.id}).")


def _read_secret(value_file: Path | None) -> str:
    if value_file is not None:
        return value_file.read_text(encoding="utf-8")
    return str(typer.prompt("Secret value", hide_input=True))


@credential_app.command("add")
def credential_add(
    name: str,
    type: CredentialType,
    value_file: Annotated[
        Path | None, typer.Option(help="Read the secret from this file instead of a prompt.")
    ] = None,
    field: Annotated[
        list[str] | None, typer.Option(help="Extra non-secret-by-name field as key=value.")
    ] = None,
    config: ConfigOption = None,
) -> None:
    fields = dict(f.split("=", 1) for f in field or [])
    payload = SecretPayload(type, _read_secret(value_file), fields)
    _print(_run(config, lambda gw: gw.admin.create_credential(CLI_PRINCIPAL, name, payload)))


@credential_app.command("list")
def credential_list(config: ConfigOption = None) -> None:
    _print(_run(config, lambda gw: gw.admin.list_credentials(CLI_PRINCIPAL)))


# ---- roles and policies -----------------------------------------------------------------


@role_app.command("set")
def role_set(
    role_id: str,
    action: Annotated[list[str], typer.Option("--action", "-a")],
    description: str = "",
    config: ConfigOption = None,
) -> None:
    role = Role(id=role_id, description=description, actions=tuple(action))
    _print(_run(config, lambda gw: gw.admin.put_role(CLI_PRINCIPAL, role)))


@role_app.command("list")
def role_list(config: ConfigOption = None) -> None:
    _print(_run(config, lambda gw: gw.admin.list_roles(CLI_PRINCIPAL)))


@policy_app.command("add")
def policy_add(
    action: Annotated[list[str], typer.Option("--action", "-a")],
    agent: Annotated[str | None, typer.Option(help="Subject agent id.")] = None,
    role: Annotated[str | None, typer.Option(help="Subject role (of agents).")] = None,
    user: Annotated[str | None, typer.Option(help="Subject user (OIDC sub claim).")] = None,
    user_role: Annotated[str | None, typer.Option(help="Subject role of users.")] = None,
    resource: Annotated[list[str] | None, typer.Option(help="Resource id.")] = None,
    tag: Annotated[list[str] | None, typer.Option(help="Resource tag (all must match).")] = None,
    effect: PolicyEffect = PolicyEffect.ALLOW,
    approval: ApprovalMode = ApprovalMode.BY_RISK,
    config: ConfigOption = None,
) -> None:
    try:
        subject = PolicySubject(agent_id=agent, role=role, user=user, user_role=user_role)
    except ValidationError:
        typer.secho(
            "error: give exactly one of --agent, --role, --user, or --user-role",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1) from None
    selector = ResourceSelector(ids=tuple(resource or ()), tags=tuple(tag or ()))
    _print(
        _run(
            config,
            lambda gw: gw.admin.create_policy(
                CLI_PRINCIPAL,
                subject=subject,
                actions=action,
                resources=selector,
                effect=effect,
                approval=approval,
            ),
        )
    )


@policy_app.command("list")
def policy_list(config: ConfigOption = None) -> None:
    _print(_run(config, lambda gw: gw.admin.list_policies(CLI_PRINCIPAL)))


@policy_app.command("delete")
def policy_delete(policy_id: str, config: ConfigOption = None) -> None:
    deleted = _run(config, lambda gw: gw.admin.delete_policy(CLI_PRINCIPAL, policy_id))
    typer.echo("deleted" if deleted else "not found")


# ---- users (OIDC subject or group → roles) ----------------------------------------------


@user_app.command("add")
def user_add(
    role: Annotated[list[str], typer.Option("--role", "-r")],
    subject: Annotated[str | None, typer.Option(help="The token's sub claim.")] = None,
    group: Annotated[str | None, typer.Option(help="A value of the groups claim.")] = None,
    config: ConfigOption = None,
) -> None:
    if (subject is None) == (group is None):
        typer.secho(
            "error: give exactly one of --subject or --group", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(1)
    match = UserMatch(subject=subject, group=group)
    _print(_run(config, lambda gw: gw.admin.add_user(CLI_PRINCIPAL, match, role)))


@user_app.command("list")
def user_list(config: ConfigOption = None) -> None:
    _print(_run(config, lambda gw: gw.admin.list_users(CLI_PRINCIPAL)))


@user_app.command("delete")
def user_delete(user_id: str, config: ConfigOption = None) -> None:
    deleted = _run(config, lambda gw: gw.admin.delete_user(CLI_PRINCIPAL, user_id))
    typer.echo("deleted" if deleted else "not found")


# ---- approvals and audit ----------------------------------------------------------------


@approvals_app.command("list")
def approvals_list(
    all_: Annotated[bool, typer.Option("--all", help="Include decided approvals.")] = False,
    config: ConfigOption = None,
) -> None:
    status = None if all_ else ApprovalStatus.PENDING
    _print(_run(config, lambda gw: gw.admin.list_approvals(CLI_PRINCIPAL, status=status)))


@approvals_app.command("approve")
def approvals_approve(approval_id: str, config: ConfigOption = None) -> None:
    """Approve; the running server picks the execution up within a few seconds."""
    _print(_run(config, lambda gw: gw.admin.approve(CLI_PRINCIPAL, approval_id)))


@approvals_app.command("reject")
def approvals_reject(
    approval_id: str, reason: str | None = None, config: ConfigOption = None
) -> None:
    _print(_run(config, lambda gw: gw.admin.reject(CLI_PRINCIPAL, approval_id, reason)))


@audit_app.command("verify")
def audit_verify(config: ConfigOption = None) -> None:
    result = _run(config, lambda gw: gw.admin.verify_audit(CLI_PRINCIPAL))
    _print(result)
    if not result.ok:
        raise typer.Exit(1)


# ---- elevation windows ------------------------------------------------------------------


@elevation_app.command("list")
def elevation_list(
    all_: Annotated[bool, typer.Option("--all", help="Include expired and revoked.")] = False,
    config: ConfigOption = None,
) -> None:
    _print(_run(config, lambda gw: gw.admin.list_elevations(CLI_PRINCIPAL, active_only=not all_)))


@elevation_app.command("grant")
def elevation_grant(
    agent: Annotated[str, typer.Option(help="Agent id.")],
    resource: Annotated[str, typer.Option(help="Resource id.")],
    minutes: Annotated[int, typer.Option(min=1, max=240)] = 15,
    action: str = "ssh.sudo",
    config: ConfigOption = None,
) -> None:
    """Open a window now, without waiting for an approval."""
    _print(
        _run(
            config,
            lambda gw: gw.admin.grant_elevation(
                CLI_PRINCIPAL, agent_id=agent, resource_id=resource, action=action, minutes=minutes
            ),
        )
    )


@elevation_app.command("revoke")
def elevation_revoke(elevation_id: str, config: ConfigOption = None) -> None:
    """Close a window early; the next privileged command needs approval again."""
    _print(_run(config, lambda gw: gw.admin.revoke_elevation(CLI_PRINCIPAL, elevation_id)))


if __name__ == "__main__":
    app()


# ---- catalog and sync (SPEC §11.6) --------------------------------------------------------

CLI_ACTOR = Actor(type=ActorType.ADMIN, id=CLI_PRINCIPAL.token_id)


async def _resource_id(gw: Gateway, ref: str) -> str:
    return (await gw.catalog.resolve(ref)).id


@app.command()
def sync(
    resource: Annotated[
        str | None,
        typer.Argument(help="Resource id or name. Without it, every resource with a catalog."),
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Read what a resource offers into its catalog. Never grants anything.

    SQL databases: tables and columns of the resource's schema. MCP servers: tools, which
    become actions mcp.<resource>.<tool>. A running server picks the result up by itself.
    """

    async def run(gw: Gateway) -> list[dict[str, Any]]:
        if resource is not None:
            targets = [await _resource_id(gw, resource)]
        else:
            targets = [
                r.id
                for r in await gw.admin.list_resources(CLI_PRINCIPAL)
                if gw.catalog.supports(r.type)
            ]
        results: list[dict[str, Any]] = []
        for resource_id in targets:
            try:
                report = await gw.catalog.sync(CLI_ACTOR, resource_id)
            except GatewayError as exc:
                results.append({"resource": resource_id, "error": exc.code, "message": exc.message})
                continue
            # Tools left out are listed under "skipped"; the sync itself succeeded.
            results.append({"resource": resource_id, **report.out().model_dump()})
        return results

    results = _run(config, run)
    _print(results)
    if any("error" in item for item in results):
        raise typer.Exit(1)


@catalog_app.command("show")
def catalog_show(resource: str, config: ConfigOption = None) -> None:
    """The last catalog of a resource (id or name)."""

    async def run(gw: Gateway) -> Any:
        return catalog_out(await gw.catalog.catalog(await _resource_id(gw, resource)))

    _print(_run(config, run))


@catalog_app.command("ack")
def catalog_ack(
    resource: str,
    tools: Annotated[list[str], typer.Argument(help="Tools in needs_review to accept.")],
    config: ConfigOption = None,
) -> None:
    """Accept the current schema and risk of MCP tools waiting for review."""

    async def run(gw: Gateway) -> Any:
        resource_id = await _resource_id(gw, resource)
        return catalog_out(await gw.catalog.acknowledge(CLI_ACTOR, resource_id, tools))

    _print(_run(config, run))
