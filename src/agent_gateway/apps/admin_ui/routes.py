"""Admin web UI at ``/admin``: server-rendered pages over ``AdminService`` and the engine.

No JavaScript and no third-party assets: plain forms with POST-redirect-GET, a strict
Content-Security-Policy, CSRF tokens on every form, and an HttpOnly session cookie.
Every change goes through ``AdminService``, so it is audited exactly like the CLI.
"""

import json
from collections.abc import Awaitable
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.datastructures import FormData

from agent_gateway import __version__
from agent_gateway.apps.admin_ui.session import (
    COOKIE_NAME,
    COOKIE_PATH,
    SESSION_TTL,
    Session,
    SessionStore,
    csrf_matches,
)
from agent_gateway.apps.api_server.deps import FailureLimiter, authenticate_request
from agent_gateway.common.errors import (
    AuthenticationError,
    GatewayError,
    NotFoundError,
    RateLimitedError,
)
from agent_gateway.modules.approvals.models import Approval, ApprovalStatus
from agent_gateway.modules.audit.models import AuditEventType
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.execution.models import Execution, ExecutionStatus
from agent_gateway.modules.identity.models import AgentStatus, IssuedToken, TokenKind
from agent_gateway.modules.resources.models import Resource
from agent_gateway.runtime import Gateway

router = APIRouter(prefix="/admin", include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["version"] = __version__
templates.env.filters["pretty"] = lambda value: json.dumps(value, indent=2, sort_keys=True)
templates.env.filters["ts"] = lambda value: (
    value.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(value, datetime) else "-"
)

AUDIT_PAGE_SIZE = 200
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class LoginRequiredError(Exception):
    """No valid admin session: send the browser to the login page."""


class CsrfFailedError(Exception):
    """A form was posted without this session's CSRF token."""


# ---- plumbing -------------------------------------------------------------------------------


def _gateway(request: Request) -> Gateway:
    gateway: Gateway = request.app.state.gateway
    return gateway


def _store(request: Request) -> SessionStore:
    store: SessionStore = request.app.state.admin_sessions
    return store


async def current_session(request: Request) -> Session:
    store = _store(request)
    session = store.get(request.cookies.get(COOKIE_NAME))
    if session is None:
        raise LoginRequiredError
    # Revoking or expiring the admin token ends every session opened with it.
    tokens = await _gateway(request).admin.list_tokens(session.principal)
    token = next((t for t in tokens if t.id == session.principal.token_id), None)
    now = _gateway(request).clock.now()
    if (
        token is None
        or token.revoked_at is not None
        or (token.expires_at is not None and token.expires_at <= now)
    ):
        store.end(session.id)
        raise LoginRequiredError
    return session


SessionDep = Annotated[Session, Depends(current_session)]


async def _form(request: Request, session: Session) -> FormData:
    form = await request.form()
    submitted = form.get("csrf")
    if not csrf_matches(session, submitted if isinstance(submitted, str) else None):
        raise CsrfFailedError
    return form


def _text(form: FormData, name: str, default: str = "") -> str:
    value = form.get(name)
    return value.strip() if isinstance(value, str) else default


def _secret(value: str) -> str:
    """Trim surrounding whitespace; keep the final newline PEM keys expect."""
    trimmed = value.strip()
    return trimmed + chr(10) if trimmed.startswith("-----BEGIN") else trimmed


def _lines(value: str) -> list[str]:
    return [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]


def _render(
    request: Request, session: Session | None, template: str, status_code: int = 200, **ctx: Any
) -> HTMLResponse:
    context: dict[str, Any] = {
        "session": session,
        "csrf": session.csrf if session else "",
        "flashes": session.pop_flashes() if session else [],
        "path": request.url.path,
        **ctx,
    }
    return templates.TemplateResponse(request, template, context, status_code=status_code)


def _back(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


async def _attempt[T](session: Session, action: Awaitable[T], ok: str | None = None) -> T | None:
    """Run an admin action; report the outcome as a flash message instead of an error page."""
    try:
        result = await action
    except GatewayError as exc:
        session.flash("error", f"{exc.code}: {exc.message}")
        return None
    except ValueError as exc:
        session.flash("error", str(exc))
        return None
    if ok:
        session.flash("ok", ok)
    return result


async def _names(gateway: Gateway, session: Session) -> dict[str, str]:
    """Id -> human name for agents and resources, for readable tables."""
    agents = await gateway.admin.list_agents(session.principal)
    resources = await gateway.admin.list_resources(session.principal)
    return {a.id: a.name for a in agents} | {r.id: r.name for r in resources}


# ---- login ----------------------------------------------------------------------------------


@router.get("/login")
async def login_page(request: Request) -> Response:
    if _store(request).get(request.cookies.get(COOKIE_NAME)) is not None:
        return _back("/admin")
    return _render(request, None, "login.html")


@router.post("/login")
async def login(request: Request) -> Response:
    gateway = _gateway(request)
    limiter: FailureLimiter = request.app.state.limiter
    form = await request.form()
    token = form.get("token")
    try:
        principal = await authenticate_request(
            request, gateway, limiter, token if isinstance(token, str) else ""
        )
    except RateLimitedError:
        return _render(request, None, "login.html", 429, error="Too many attempts; wait a minute.")
    except AuthenticationError:
        return _render(request, None, "login.html", 401, error="Invalid or expired token.")
    if principal.kind is not TokenKind.ADMIN:
        return _render(
            request, None, "login.html", 403, error="That is an agent token; use an admin token."
        )
    session = _store(request).create(principal)
    response = _back("/admin")
    response.set_cookie(
        COOKIE_NAME,
        session.id,
        max_age=int(SESSION_TTL.total_seconds()),
        path=COOKIE_PATH,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
    )
    return response


@router.post("/logout")
async def logout(request: Request, session: SessionDep) -> Response:
    await _form(request, session)
    _store(request).end(session.id)
    response = _back("/admin/login")
    response.delete_cookie(COOKIE_NAME, path=COOKIE_PATH)
    return response


# ---- dashboard ------------------------------------------------------------------------------


@router.get("")
async def dashboard(request: Request, session: SessionDep) -> Response:
    gateway = _gateway(request)
    actor = session.principal
    pending = await gateway.admin.list_approvals(actor, status=ApprovalStatus.PENDING)
    recent, _ = await gateway.engine.list_for(actor, limit=10)
    return _render(
        request,
        session,
        "dashboard.html",
        pending=len(pending),
        agents=len(await gateway.admin.list_agents(actor)),
        resources=len(await gateway.admin.list_resources(actor)),
        tokens=sum(1 for t in await gateway.admin.list_tokens(actor) if t.revoked_at is None),
        recent=recent,
        names=await _names(gateway, session),
    )


# ---- approvals ------------------------------------------------------------------------------


@router.get("/approvals")
async def approvals_page(
    request: Request, session: SessionDep, status: str = "pending", auto: int = 0
) -> Response:
    gateway = _gateway(request)
    try:
        wanted = None if status == "all" else ApprovalStatus(status)
    except ValueError:
        status, wanted = "pending", ApprovalStatus.PENDING
    approvals = await gateway.admin.list_approvals(session.principal, status=wanted)
    rows: list[tuple[Approval, Execution | None]] = []
    for approval in sorted(approvals, key=lambda a: a.requested_at, reverse=True):
        try:
            execution = await gateway.engine.get(session.principal, approval.execution_id)
        except GatewayError:
            execution = None
        rows.append((approval, execution))
    return _render(
        request,
        session,
        "approvals.html",
        rows=rows,
        status=status,
        auto=bool(auto),
        names=await _names(gateway, session),
        statuses=["pending", "approved", "rejected", "expired", "all"],
    )


@router.post("/approvals/{approval_id}/approve")
async def approve(request: Request, session: SessionDep, approval_id: str) -> Response:
    await _form(request, session)
    gateway = _gateway(request)
    if await _attempt(session, gateway.admin.approve(session.principal, approval_id), "Approved."):
        await gateway.engine.dispatch_approvals()
    return _back("/admin/approvals")


@router.post("/approvals/{approval_id}/reject")
async def reject(request: Request, session: SessionDep, approval_id: str) -> Response:
    form = await _form(request, session)
    gateway = _gateway(request)
    reason = _text(form, "reason") or None
    if await _attempt(
        session, gateway.admin.reject(session.principal, approval_id, reason), "Rejected."
    ):
        await gateway.engine.dispatch_approvals()
    return _back("/admin/approvals")


# ---- executions -----------------------------------------------------------------------------


@router.get("/executions")
async def executions_page(
    request: Request, session: SessionDep, cursor: str | None = None, agent: str = ""
) -> Response:
    gateway = _gateway(request)
    items, next_cursor = await gateway.engine.list_for(session.principal, cursor=cursor, limit=50)
    if agent:
        items = [e for e in items if e.agent_id == agent]
    return _render(
        request,
        session,
        "executions.html",
        items=items,
        next_cursor=next_cursor,
        agent=agent,
        agents=await gateway.admin.list_agents(session.principal),
        names=await _names(gateway, session),
    )


@router.get("/executions/{execution_id}")
async def execution_page(request: Request, session: SessionDep, execution_id: str) -> Response:
    gateway = _gateway(request)
    try:
        execution = await gateway.engine.get(session.principal, execution_id)
    except NotFoundError:
        session.flash("error", f"Execution {execution_id} not found.")
        return _back("/admin/executions")
    return _render(
        request,
        session,
        "execution.html",
        e=execution,
        names=await _names(gateway, session),
        terminal=execution.status
        in {ExecutionStatus.SUCCEEDED, ExecutionStatus.FAILED, ExecutionStatus.DENIED},
    )


# ---- agents and tokens ----------------------------------------------------------------------


@router.get("/agents")
async def agents_page(request: Request, session: SessionDep) -> Response:
    gateway = _gateway(request)
    return _render(
        request,
        session,
        "agents.html",
        agents=sorted(await gateway.admin.list_agents(session.principal), key=lambda a: a.name),
        roles=[r.id for r in await gateway.admin.list_roles(session.principal)],
    )


@router.post("/agents")
async def create_agent(request: Request, session: SessionDep) -> Response:
    form = await _form(request, session)
    name = _text(form, "name")
    await _attempt(
        session,
        _gateway(request).admin.create_agent(
            session.principal,
            name,
            description=_text(form, "description"),
            roles=_lines(_text(form, "roles")),
        ),
        f"Agent {name} created.",
    )
    return _back("/admin/agents")


@router.post("/agents/{agent_id}/roles")
async def set_agent_roles(request: Request, session: SessionDep, agent_id: str) -> Response:
    form = await _form(request, session)
    await _attempt(
        session,
        _gateway(request).admin.update_agent(
            session.principal, agent_id, roles=_lines(_text(form, "roles"))
        ),
        "Roles updated.",
    )
    return _back("/admin/agents")


@router.post("/agents/{agent_id}/status")
async def set_agent_status(request: Request, session: SessionDep, agent_id: str) -> Response:
    form = await _form(request, session)
    status = AgentStatus(_text(form, "status"))
    await _attempt(
        session,
        _gateway(request).admin.update_agent(session.principal, agent_id, status=status),
        f"Agent {status.value}.",
    )
    return _back("/admin/agents")


def _token_page(request: Request, session: Session, issued: IssuedToken | None) -> Response:
    if issued is None:
        return _back("/admin/tokens")
    # Rendered directly, never redirected or stored: the plaintext exists only in this page.
    mcp_url = str(request.base_url).rstrip("/") + "/mcp"
    return _render(request, session, "token_once.html", issued=issued, mcp_url=mcp_url)


@router.post("/agents/{agent_id}/tokens")
async def issue_agent_token(request: Request, session: SessionDep, agent_id: str) -> Response:
    await _form(request, session)
    issued = await _attempt(
        session,
        _gateway(request).admin.issue_token(session.principal, TokenKind.AGENT, agent_id=agent_id),
    )
    return _token_page(request, session, issued)


@router.get("/tokens")
async def tokens_page(request: Request, session: SessionDep) -> Response:
    gateway = _gateway(request)
    tokens = await gateway.admin.list_tokens(session.principal)
    return _render(
        request,
        session,
        "tokens.html",
        tokens=sorted(tokens, key=lambda t: t.created_at, reverse=True),
        names=await _names(gateway, session),
        current=session.principal.token_id,
    )


@router.post("/tokens/admin")
async def issue_admin_token(request: Request, session: SessionDep) -> Response:
    await _form(request, session)
    issued = await _attempt(
        session, _gateway(request).admin.issue_token(session.principal, TokenKind.ADMIN)
    )
    return _token_page(request, session, issued)


@router.post("/tokens/{token_id}/revoke")
async def revoke_token(request: Request, session: SessionDep, token_id: str) -> Response:
    await _form(request, session)
    await _attempt(
        session,
        _gateway(request).admin.revoke_token(session.principal, token_id),
        f"Token {token_id} revoked.",
    )
    return _back("/admin/tokens")


# ---- resources ------------------------------------------------------------------------------


async def _resource(gateway: Gateway, session: Session, resource_id: str) -> Resource | None:
    resources = await gateway.admin.list_resources(session.principal)
    return next((r for r in resources if r.id == resource_id), None)


@router.get("/resources")
async def resources_page(request: Request, session: SessionDep) -> Response:
    gateway = _gateway(request)
    resources = await gateway.admin.list_resources(session.principal)
    return _render(
        request, session, "resources.html", resources=sorted(resources, key=lambda r: r.name)
    )


@router.get("/resources/{resource_id}")
async def resource_page(request: Request, session: SessionDep, resource_id: str) -> Response:
    gateway = _gateway(request)
    resource = await _resource(gateway, session, resource_id)
    if resource is None:
        session.flash("error", f"Resource {resource_id} not found.")
        return _back("/admin/resources")
    credentials = {c.id: c.name for c in await gateway.admin.list_credentials(session.principal)}
    return _render(
        request,
        session,
        "resource.html",
        r=resource,
        credential=credentials.get(resource.credential_id or "", resource.credential_id),
    )


async def _update_attributes(
    request: Request, session: Session, resource_id: str, changes: dict[str, Any], ok: str
) -> Response:
    gateway = _gateway(request)
    resource = await _resource(gateway, session, resource_id)
    if resource is None:
        session.flash("error", f"Resource {resource_id} not found.")
        return _back("/admin/resources")
    await _attempt(
        session,
        gateway.admin.update_resource(
            session.principal, resource_id, attributes={**resource.attributes, **changes}
        ),
        ok,
    )
    return _back(f"/admin/resources/{resource_id}")


@router.post("/resources/{resource_id}/sudo")
async def set_sudo(request: Request, session: SessionDep, resource_id: str) -> Response:
    form = await _form(request, session)
    enable = _text(form, "allow_sudo") == "on"
    state = "enabled" if enable else "disabled"
    return await _update_attributes(
        request, session, resource_id, {"allow_sudo": enable}, f"ssh.sudo {state}."
    )


@router.post("/resources/{resource_id}/services")
async def set_services(request: Request, session: SessionDep, resource_id: str) -> Response:
    form = await _form(request, session)
    services = _lines(_text(form, "services"))
    return await _update_attributes(
        request, session, resource_id, {"allowed_services": services}, "Allowed services saved."
    )


@router.post("/resources/{resource_id}/tags")
async def set_tags(request: Request, session: SessionDep, resource_id: str) -> Response:
    form = await _form(request, session)
    await _attempt(
        session,
        _gateway(request).admin.update_resource(
            session.principal, resource_id, tags=_lines(_text(form, "tags"))
        ),
        "Tags saved.",
    )
    return _back(f"/admin/resources/{resource_id}")


@router.post("/resources/{resource_id}/delete")
async def delete_resource(request: Request, session: SessionDep, resource_id: str) -> Response:
    form = await _form(request, session)
    if _text(form, "confirm") != resource_id:
        session.flash("error", "Type the resource id to confirm deletion.")
        return _back(f"/admin/resources/{resource_id}")
    await _attempt(
        session,
        _gateway(request).admin.delete_resource(session.principal, resource_id),
        "Resource deleted.",
    )
    return _back("/admin/resources")


# ---- roles and policies ---------------------------------------------------------------------


@router.get("/roles")
async def roles_page(request: Request, session: SessionDep) -> Response:
    gateway = _gateway(request)
    actions = sorted(gateway.registry.all(), key=lambda a: a.definition.id)
    return _render(
        request,
        session,
        "roles.html",
        roles=await gateway.admin.list_roles(session.principal),
        actions=[a.definition for a in actions],
    )


@router.post("/roles")
async def save_role(request: Request, session: SessionDep) -> Response:
    form = await _form(request, session)
    role_id = _text(form, "id")
    try:
        role = Role(
            id=role_id,
            description=_text(form, "description"),
            actions=tuple(_lines(_text(form, "actions"))),
        )
    except ValueError as exc:
        session.flash("error", f"Invalid role: {exc}")
        return _back("/admin/roles")
    await _attempt(
        session, _gateway(request).admin.put_role(session.principal, role), f"Role {role_id} saved."
    )
    return _back("/admin/roles")


@router.post("/roles/{role_id}/delete")
async def delete_role(request: Request, session: SessionDep, role_id: str) -> Response:
    await _form(request, session)
    await _attempt(
        session,
        _gateway(request).admin.delete_role(session.principal, role_id),
        f"Role {role_id} deleted.",
    )
    return _back("/admin/roles")


@router.get("/policies")
async def policies_page(request: Request, session: SessionDep) -> Response:
    gateway = _gateway(request)
    actor = session.principal
    return _render(
        request,
        session,
        "policies.html",
        policies=await gateway.admin.list_policies(actor),
        roles=[r.id for r in await gateway.admin.list_roles(actor)],
        agents=await gateway.admin.list_agents(actor),
        resources=await gateway.admin.list_resources(actor),
        names=await _names(gateway, session),
        effects=[e.value for e in PolicyEffect],
        modes=[m.value for m in ApprovalMode],
    )


@router.post("/policies")
async def create_policy(request: Request, session: SessionDep) -> Response:
    form = await _form(request, session)
    subject_value = _text(form, "subject")
    kind, _, value = subject_value.partition(":")
    try:
        subject = PolicySubject(agent_id=value) if kind == "agent" else PolicySubject(role=value)
        selector = ResourceSelector(
            ids=tuple(v for v in form.getlist("resources") if isinstance(v, str) and v),
            tags=tuple(_lines(_text(form, "tags"))),
        )
        effect = PolicyEffect(_text(form, "effect", "allow"))
        mode = ApprovalMode(_text(form, "approval", "by_risk"))
    except ValueError as exc:
        session.flash("error", f"Invalid policy: {exc}")
        return _back("/admin/policies")
    await _attempt(
        session,
        _gateway(request).admin.create_policy(
            session.principal,
            subject=subject,
            actions=_lines(_text(form, "actions")),
            resources=selector,
            effect=effect,
            approval=mode,
        ),
        "Policy created.",
    )
    return _back("/admin/policies")


@router.post("/policies/{policy_id}/delete")
async def delete_policy(request: Request, session: SessionDep, policy_id: str) -> Response:
    await _form(request, session)
    await _attempt(
        session,
        _gateway(request).admin.delete_policy(session.principal, policy_id),
        "Policy deleted.",
    )
    return _back("/admin/policies")


# ---- credentials ----------------------------------------------------------------------------


@router.get("/credentials")
async def credentials_page(request: Request, session: SessionDep) -> Response:
    gateway = _gateway(request)
    return _render(
        request,
        session,
        "credentials.html",
        credentials=await gateway.admin.list_credentials(session.principal),
        types=[t.value for t in CredentialType],
    )


@router.post("/credentials")
async def create_credential(request: Request, session: SessionDep) -> Response:
    form = await _form(request, session)
    name = _text(form, "name")
    value = form.get("value")
    if not isinstance(value, str) or not value.strip():
        session.flash("error", "The secret value is empty.")
        return _back("/admin/credentials")
    payload = SecretPayload(CredentialType(_text(form, "type")), _secret(value))
    await _attempt(
        session,
        _gateway(request).admin.create_credential(session.principal, name, payload),
        f"Credential {name} stored (encrypted).",
    )
    return _back("/admin/credentials")


@router.post("/credentials/{credential_id}/rotate")
async def rotate_credential(request: Request, session: SessionDep, credential_id: str) -> Response:
    form = await _form(request, session)
    gateway = _gateway(request)
    credentials = await gateway.admin.list_credentials(session.principal)
    current = next((c for c in credentials if c.id == credential_id), None)
    value = form.get("value")
    if current is None or not isinstance(value, str) or not value.strip():
        session.flash("error", "Credential not found or the new value is empty.")
        return _back("/admin/credentials")
    await _attempt(
        session,
        gateway.admin.rotate_credential(
            session.principal, credential_id, SecretPayload(current.type, _secret(value))
        ),
        f"Credential {current.name} rotated.",
    )
    return _back("/admin/credentials")


@router.post("/credentials/{credential_id}/delete")
async def delete_credential(request: Request, session: SessionDep, credential_id: str) -> Response:
    form = await _form(request, session)
    if _text(form, "confirm") != credential_id:
        session.flash("error", "Type the credential id to confirm deletion.")
        return _back("/admin/credentials")
    await _attempt(
        session,
        _gateway(request).admin.delete_credential(session.principal, credential_id),
        "Credential deleted.",
    )
    return _back("/admin/credentials")


# ---- audit ----------------------------------------------------------------------------------


@router.get("/audit")
async def audit_page(request: Request, session: SessionDep, event: str = "") -> Response:
    gateway = _gateway(request)
    try:
        wanted = AuditEventType(event) if event else None
    except ValueError:
        event, wanted = "", None
    entries = await gateway.admin.audit_entries(session.principal, event=wanted)
    return _render(
        request,
        session,
        "audit.html",
        entries=list(reversed(entries))[:AUDIT_PAGE_SIZE],
        total=len(entries),
        event=event,
        events=[e.value for e in AuditEventType],
    )


@router.post("/audit/verify")
async def verify_audit(request: Request, session: SessionDep) -> Response:
    await _form(request, session)
    result = await _attempt(session, _gateway(request).admin.verify_audit(session.principal))
    if result is not None:
        if result.ok:
            session.flash("ok", f"Audit chain OK ({result.entries_checked} entries).")
        else:
            session.flash(
                "error",
                f"Audit chain BROKEN at seq {result.first_bad_seq}: {result.reason}",
            )
    return _back("/admin/audit")
