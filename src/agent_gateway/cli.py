"""``agw``: the local admin CLI (SPEC §20.3).

The CLI works on the same ``var/`` directory as the server, under the same file locks,
so it can run while the server is up. Whoever can read the master key is the admin.
"""

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import BaseModel

from agent_gateway.common.errors import GatewayError
from agent_gateway.config import Settings, load_settings
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.approvals.models import ApprovalStatus
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.crypto.keyring import generate_master_key
from agent_gateway.modules.identity.models import AgentStatus, TokenKind
from agent_gateway.modules.resources.models import ResourceType
from agent_gateway.runtime import Gateway, build_gateway

app = typer.Typer(help="Agent Gateway admin CLI.", no_args_is_help=True)
agent_app = typer.Typer(help="Manage agents.", no_args_is_help=True)
token_app = typer.Typer(help="Manage API tokens.", no_args_is_help=True)
resource_app = typer.Typer(help="Manage resources.", no_args_is_help=True)
credential_app = typer.Typer(help="Manage credentials (write-only).", no_args_is_help=True)
role_app = typer.Typer(help="Manage roles.", no_args_is_help=True)
policy_app = typer.Typer(help="Manage policies.", no_args_is_help=True)
approvals_app = typer.Typer(help="Review pending approvals.", no_args_is_help=True)
audit_app = typer.Typer(help="Inspect the audit log.", no_args_is_help=True)
for sub, name in [
    (agent_app, "agent"),
    (token_app, "token"),
    (resource_app, "resource"),
    (credential_app, "credential"),
    (role_app, "role"),
    (policy_app, "policy"),
    (approvals_app, "approvals"),
    (audit_app, "audit"),
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


def _show_token_once(plaintext: str) -> None:
    typer.secho("\nToken (shown only once, store it now):", fg=typer.colors.YELLOW, err=True)
    typer.echo(plaintext)


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
def init(config: ConfigOption = None) -> None:
    """Create the data directory and the first admin token."""

    async def go(gw: Gateway) -> None:
        gw.settings.var_dir.mkdir(parents=True, exist_ok=True)
        await gw.start(background=False)
        if any(t.kind is TokenKind.ADMIN for t in await gw.admin.list_tokens(CLI_PRINCIPAL)):
            typer.echo("Already initialised; use `agw token create --admin` for another token.")
            return
        issued = await gw.admin.issue_token(CLI_PRINCIPAL, TokenKind.ADMIN)
        typer.echo(f"Initialised {gw.settings.var_dir}. Admin token id: {issued.token.id}")
        _show_token_once(issued.plaintext.get_secret_value())

    _run(config, go)


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
    typer.echo(f"Token id: {issued.token.id}")
    _show_token_once(issued.plaintext.get_secret_value())


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
    role: Annotated[str | None, typer.Option(help="Subject role.")] = None,
    resource: Annotated[list[str] | None, typer.Option(help="Resource id.")] = None,
    tag: Annotated[list[str] | None, typer.Option(help="Resource tag (all must match).")] = None,
    effect: PolicyEffect = PolicyEffect.ALLOW,
    approval: ApprovalMode = ApprovalMode.BY_RISK,
    config: ConfigOption = None,
) -> None:
    subject = PolicySubject(agent_id=agent, role=role)
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


if __name__ == "__main__":
    app()
