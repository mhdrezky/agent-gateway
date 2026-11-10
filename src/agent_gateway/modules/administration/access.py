"""Access administration for people through an app (SPEC §23, contract §4, §6, §8).

``AccessAdmin`` reads roles, users, user-side policies, resources, and actions as the console
sees them, computes a user's effective access, and changes the access configuration only
through plans: export the whole configuration, plan a desired one (diff + problems), apply
the plan. An apply is one audit entry with the full diff, written before anything changes
(fail closed). Credentials, agents, tokens, and agent-side policies are never touched here.
"""

import asyncio
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import AwareDatetime, Field, TypeAdapter, ValidationError

from agent_gateway.common.canonical import sha256_digest
from agent_gateway.common.clock import Clock, to_rfc3339
from agent_gateway.common.errors import (
    InvalidParamsError,
    NotFoundError,
    PlanExpiredError,
    PlanHasProblemsError,
    PlanStaleError,
    SecondAdminRequiredError,
)
from agent_gateway.common.ids import IdPrefix, new_id
from agent_gateway.common.models import Record
from agent_gateway.config import AdminSettings
from agent_gateway.modules.action_registry.models import ActionDefinition
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.administration.access_models import (
    AccessConfig,
    AccessDenied,
    AccessGrant,
    AccessView,
    AdminActionInfo,
    ApplyOut,
    CatalogState,
    Change,
    ConfigRole,
    ConfigUser,
    PlanOut,
    PlanStatus,
    Problem,
    ProblemCode,
    ResourceView,
    RoleSource,
    RoleVia,
    RoleView,
    UserPolicy,
    UserRecord,
    match_key,
)
from agent_gateway.modules.administration.catalog_port import CatalogPort
from agent_gateway.modules.administration.directory import Directory
from agent_gateway.modules.approvals.models import Approver
from agent_gateway.modules.audit.models import Actor, ActorType, AuditEventType, AuditRecord
from agent_gateway.modules.audit.ports import AuditLog
from agent_gateway.modules.authorization.engine import (
    grants,
    pattern_matches,
    roles_grant,
    selector_matches,
    user_subject_matches,
)
from agent_gateway.modules.authorization.models import (
    ACTION_PATTERN,
    ApprovalMode,
    AuthorizationRequest,
    Policy,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.authorization.ports import PolicyEngine
from agent_gateway.modules.identity.models import (
    Agent,
    Principal,
    TokenKind,
    User,
    UserIdentity,
)
from agent_gateway.modules.identity.ports import IdentityService
from agent_gateway.modules.identity.users import matching_users, user_roles
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.modules.resources.ports import ResourceRegistry
from agent_gateway.modules.storage.ports import Collection

PLAN_TTL = timedelta(minutes=15)
ALLOWED_TABLES = "allowed_tables"
NO_RESOURCE_TAG = "gateway:no-resource"
_DATETIME = TypeAdapter(AwareDatetime)
_ROLE_ID = TypeAdapter(Role)


# ---- who is acting ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class AdminActor:
    """The caller of an admin change: a static admin token, or an access admin signed in
    through an agent (``X-User-Token``)."""

    label: str
    actor: Actor
    via_agent: str | None = None
    user: UserIdentity | None = None

    @classmethod
    def of(cls, principal: Principal) -> "AdminActor":
        if principal.is_admin or principal.user is None:
            return cls(
                label=f"admin:{principal.token_id}",
                actor=Actor(type=ActorType.ADMIN, id=principal.token_id),
            )
        return cls(
            label=principal.user.subject,
            actor=Actor(type=ActorType.USER, id=principal.user.subject),
            via_agent=principal.agent_id,
            user=principal.user,
        )

    def details(self) -> dict[str, Any]:
        return {} if self.via_agent is None else {"via_agent": self.via_agent}


# ---- stored plans ----------------------------------------------------------------------


class StoredPlan(Record):
    """A plan as kept in ``var/access_plans.json`` until applied or expired."""

    base_digest: str
    created_by: str
    created_at: AwareDatetime
    expires_at: AwareDatetime
    status: Literal["open", "applied", "expired"] = "open"
    config: dict[str, Any]
    changes: tuple[dict[str, Any], ...] = ()
    problems: tuple[dict[str, Any], ...] = ()
    applied_by: str | None = None
    applied_at: AwareDatetime | None = None
    via_agent: str | None = Field(default=None, max_length=64)


# ---- the current state ------------------------------------------------------------------


@dataclass(slots=True)
class _State:
    roles: list[Role]
    agents: list[Agent]
    users: list[User]
    policies: list[Policy]
    resources: list[Resource]
    held: dict[str, list[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for agent in sorted(self.agents, key=lambda a: a.name):
            for role in agent.roles:
                self.held.setdefault(role, []).append(agent.name)

    def resource_names(self) -> dict[str, str]:
        return {r.id: r.name for r in self.resources}

    def resource_by_name(self, name: str) -> Resource | None:
        return next((r for r in self.resources if r.name == name), None)


def policy_name(policy: Policy) -> str:
    """The name a policy has in a config. Unnamed (CLI/REST) policies use their id."""
    return policy.name if policy.name is not None else policy.id.lower()


# ---- operations an apply performs -------------------------------------------------------


@dataclass(slots=True)
class _Ops:
    put_roles: list[Role] = field(default_factory=list)
    delete_roles: list[str] = field(default_factory=list)
    put_users: list[User] = field(default_factory=list)
    new_users: list[tuple[str, ConfigUser]] = field(default_factory=list)
    delete_users: list[str] = field(default_factory=list)
    put_policies: list[Policy] = field(default_factory=list)
    new_policies: list[UserPolicy] = field(default_factory=list)
    delete_policies: list[str] = field(default_factory=list)
    tables: list[tuple[Resource, list[str]]] = field(default_factory=list)


@dataclass(slots=True)
class _Planned:
    changes: list[Change] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    ops: _Ops = field(default_factory=_Ops)

    def problem(self, code: ProblemCode, message: str) -> None:
        item = Problem(code=code, message=message)
        if item not in self.problems:
            self.problems.append(item)


class AccessAdmin:
    def __init__(
        self,
        *,
        settings: AdminSettings,
        roles: Collection[Role],
        policies: Collection[Policy],
        users: Collection[User],
        resources: ResourceRegistry,
        identity: IdentityService,
        registry: ActionRegistry,
        plans: Collection[StoredPlan],
        audit: AuditLog,
        clock: Clock,
        catalog: CatalogPort,
        directory: Directory,
        policy_engine: PolicyEngine,
        extra_actions: Sequence[ActionDefinition] = (),
    ) -> None:
        self.settings = settings
        self._roles = roles
        self._policies = policies
        self._users = users
        self._resources = resources
        self._identity = identity
        self._registry = registry
        self._plans = plans
        self._audit = audit
        self._clock = clock
        self.catalog = catalog
        self.directory = directory
        self._engine = policy_engine
        self._extra = tuple(extra_actions)
        self._lock = asyncio.Lock()

    # ---- who is an admin ----------------------------------------------------------------

    def is_access_admin(self, roles: Iterable[str]) -> bool:
        return bool(set(roles) & set(self.settings.user_roles))

    # ---- actions ------------------------------------------------------------------------

    def actions(self) -> list[ActionDefinition]:
        """Every action a role or policy may name: the registry plus fixed extras
        (``model.chat``)."""
        found = {a.definition.id: a.definition for a in self._registry.all()}
        for extra in self._extra:
            found.setdefault(extra.id, extra)
        return [found[key] for key in sorted(found)]

    def privileged_ids(self) -> set[str]:
        return {a.id for a in self.actions() if a.privileged}

    def is_privileged(self, action_id: str) -> bool:
        return action_id in self.privileged_ids()

    # ---- reads (contract §4) ------------------------------------------------------------

    async def _state(self) -> _State:
        return _State(
            roles=sorted(await self._roles.all(), key=lambda r: r.id),
            agents=await self._identity.list_agents(),
            users=sorted(await self._users.all(), key=lambda u: u.id),
            policies=await self._policies.all(),
            resources=await self._resources.list(),
        )

    async def names(self) -> tuple[dict[str, str], dict[str, str]]:
        """Agent names and resource names by id, for views that show names."""
        agents = {a.id: a.name for a in await self._identity.list_agents()}
        resources = {r.id: r.name for r in await self._resources.list()}
        return agents, resources

    async def agent_by_name(self, name: str) -> Agent | None:
        return next((a for a in await self._identity.list_agents() if a.name == name), None)

    async def role_views(self) -> list[RoleView]:
        state = await self._state()
        return [
            RoleView(
                id=role.id,
                description=role.description,
                actions=list(role.actions),
                held_by_agents=state.held.get(role.id, []),
                editable=role.id not in state.held,
            )
            for role in state.roles
        ]

    async def user_records(self) -> list[UserRecord]:
        return [
            UserRecord(id=u.id, match=u.match, roles=list(u.roles))
            for u in sorted(await self._users.all(), key=lambda u: u.id)
        ]

    async def user_policies(self) -> list[UserPolicy]:
        return _export_policies(await self._state())

    async def resource_views(self) -> list[ResourceView]:
        views: list[ResourceView] = []
        for resource in sorted(await self._resources.list(), key=lambda r: r.name):
            summary = await self.catalog.summary(resource)
            views.append(
                ResourceView(
                    id=resource.id,
                    name=resource.name,
                    type=str(resource.type),
                    tags=list(resource.tags),
                    has_credential=resource.credential_id is not None,
                    allowed_tables=_tables_of(resource),
                    catalog=CatalogState(
                        synced_at=summary.synced_at,
                        snapshot_id=summary.snapshot_id,
                        pending_review=summary.pending_review,
                    ),
                )
            )
        return views

    async def action_infos(self, *, include_privileged: bool) -> list[AdminActionInfo]:
        infos: list[AdminActionInfo] = []
        for action in self.actions():
            if action.privileged and not include_privileged:
                continue
            infos.append(
                AdminActionInfo(
                    id=action.id,
                    resource_type=str(action.resource_type),
                    resource=await self.catalog.action_resource(action.id),
                    description=action.description,
                    risk=str(action.risk),
                    read_only=action.read_only,
                    source="mcp" if action.id.startswith("mcp.") else "builtin",
                    state=await self.catalog.action_state(action.id),
                )
            )
        return infos

    # ---- effective access (contract §6) -------------------------------------------------

    async def access_view(
        self, subject: str, groups: Sequence[str], agent: Principal
    ) -> AccessView:
        """What ``subject`` (with ``groups`` from the directory) may reach through ``agent``:
        the same user ∩ agent decision a real call gets. Privileged actions are left out."""
        state = await self._state()
        matched = matching_users(state.users, subject, groups)
        roles: dict[str, list[RoleVia]] = {}
        for item in matched:
            via = RoleVia(
                kind="subject" if item.match.subject is not None else "group",
                value=item.match.subject or item.match.group or "",
                user_record=item.id,
            )
            for role in item.roles:
                roles.setdefault(role, []).append(via)
        identity = UserIdentity(
            subject=subject,
            user_ids=tuple(u.id for u in matched),
            roles=user_roles(matched),
            groups=tuple(groups),
        )
        principal = agent.model_copy(update={"user": identity})
        now = self._clock.now()
        grants: list[AccessGrant] = []
        denied: list[AccessDenied] = []
        for action in self.actions():
            if action.privileged:
                continue
            reasons: list[str] = []
            found = False
            for resource in sorted(state.resources, key=lambda r: r.name):
                if resource.type is not action.resource_type:
                    continue
                decision = self._engine.decide(
                    AuthorizationRequest(
                        principal=principal,
                        action=action,
                        resource=resource,
                        roles=state.roles,
                        policies=state.policies,
                        now=now,
                    )
                )
                if not decision.allowed:
                    reasons.append(decision.reason)
                    continue
                found = True
                kind: Literal["allow", "requester", "admin"] = "allow"
                if decision.approval_required:
                    kind = "requester" if decision.approver is Approver.REQUESTER else "admin"
                grants.append(
                    AccessGrant(
                        action=action.id,
                        resource=resource.name,
                        decision=kind,
                        policy=_user_side_policy(
                            state.policies, principal, action, resource, decision.policy_id, now
                        ),
                        reason=decision.reason,
                    )
                )
            if not found and roles_grant(state.roles, identity.roles, action):
                reason = reasons[0] if reasons else f"no resource of type {action.resource_type}"
                denied.append(AccessDenied(action=action.id, reason=reason))
        return AccessView(
            subject=subject,
            groups=sorted(groups),
            roles=[RoleSource(role=role, via=via) for role, via in roles.items()],
            grants=grants,
            denied=denied,
        )

    # ---- config, plan, apply (contract §8) ----------------------------------------------

    async def export(self) -> AccessConfig:
        return _export(await self._state())

    async def digest(self) -> str:
        return _digest(_export(await self._state()))

    async def plan(self, config: AccessConfig, actor: AdminActor) -> PlanOut:
        state = await self._state()
        planned = await self._compute(config, state, actor)
        now = self._clock.now()
        stored = StoredPlan(
            id=new_id(IdPrefix.PLAN),
            base_digest=_digest(_export(state)),
            created_by=actor.label,
            created_at=now,
            expires_at=now + PLAN_TTL,
            config=config.model_dump(mode="json", by_alias=True),
            changes=tuple(c.model_dump(mode="json") for c in planned.changes),
            problems=tuple(p.model_dump(mode="json") for p in planned.problems),
            via_agent=actor.via_agent,
        )
        await self._plans.put(stored)
        return _plan_out(stored)

    async def plans(self, *, status: PlanStatus | None = None) -> list[PlanOut]:
        now = self._clock.now()
        result: list[PlanOut] = []
        for stored in sorted(await self._plans.all(), key=lambda p: p.created_at, reverse=True):
            current = stored
            if stored.status == "open" and now >= stored.expires_at:
                current = stored.model_copy(update={"status": "expired"})
            if status is None or current.status == status:
                result.append(_plan_out(current))
        return result

    async def apply(self, plan_id: str, actor: AdminActor) -> ApplyOut:
        async with self._lock:
            stored = await self._plans.get(plan_id)
            if stored is None:
                raise NotFoundError(f"plan {plan_id} not found")
            if stored.status == "applied":
                raise PlanStaleError(f"plan {plan_id} was already applied")
            now = self._clock.now()
            if stored.status == "expired" or now >= stored.expires_at:
                await self._plans.update(
                    plan_id, lambda p: p.model_copy(update={"status": "expired"})
                )
                raise PlanExpiredError(f"plan {plan_id} has expired")
            if stored.problems:
                raise PlanHasProblemsError(f"plan {plan_id} has problems and cannot be applied")
            if self.settings.apply_requires_second_admin and actor.label == stored.created_by:
                raise SecondAdminRequiredError(
                    "another admin must apply this plan, not the one who made it"
                )
            state = await self._state()
            if _digest(_export(state)) != stored.base_digest:
                raise PlanStaleError(f"the access configuration changed since plan {plan_id}")
            config = AccessConfig.model_validate(stored.config)
            planned = await self._compute(config, state, None)
            changes = [Change.model_validate(c) for c in stored.changes]
            await self._audit.append(
                AuditRecord(
                    event=AuditEventType.ACCESS_APPLIED,
                    actor=actor.actor,
                    details={
                        **actor.details(),
                        "plan_id": plan_id,
                        "planned_by": stored.created_by,
                        "changes": [c.model_dump(mode="json") for c in changes],
                    },
                )
            )
            await self._write(planned.ops)
            applied_at = self._clock.now()
            await self._plans.update(
                plan_id,
                lambda p: p.model_copy(
                    update={
                        "status": "applied",
                        "applied_by": actor.label,
                        "applied_at": applied_at,
                    }
                ),
            )
            return ApplyOut(
                applied_at=to_rfc3339(applied_at), applied_by=actor.label, changes=changes
            )

    async def _write(self, ops: _Ops) -> None:
        for role in ops.put_roles:
            await self._roles.put(role)
        for user in ops.put_users:
            await self._users.put(user)
        for _, item in ops.new_users:
            await self._users.put(
                User(id=new_id(IdPrefix.USER), match=item.match, roles=tuple(item.roles))
            )
        resources = {r.name: r.id for r in await self._resources.list()}
        for policy in ops.put_policies:
            await self._policies.put(policy)
        for spec in ops.new_policies:
            await self._policies.put(_to_policy(spec, new_id(IdPrefix.POLICY), None, resources))
        for policy_id in ops.delete_policies:
            await self._policies.delete(policy_id)
        for user_id in ops.delete_users:
            await self._users.delete(user_id)
        for role_id in ops.delete_roles:
            await self._roles.delete(role_id)
        for resource, tables in ops.tables:
            await self._resources.update(
                resource.id, attributes={**resource.attributes, ALLOWED_TABLES: tables}
            )

    # ---- planning -----------------------------------------------------------------------

    async def _compute(
        self, config: AccessConfig, state: _State, actor: AdminActor | None
    ) -> _Planned:
        planned = _Planned()
        current = _export(state)
        known = self.actions()
        privileged = [a.id for a in known if a.privileged]
        current_roles = {r.id: r for r in current.roles}
        stored_roles = {r.id: r for r in state.roles}

        def check_actions(what: str, patterns: Iterable[str]) -> None:
            for pattern in patterns:
                if not any(pattern_matches(pattern, a.id) for a in known):
                    planned.problem("missing_action", f"{what} names unknown action '{pattern}'")
                for action_id in privileged:
                    if pattern_matches(pattern, action_id):
                        planned.problem(
                            "privileged_action",
                            f"{what} grants privileged action '{action_id}' ('{pattern}'); "
                            "privileged actions stay with the gateway admin",
                        )

        # roles
        for role in sorted(config.roles, key=lambda r: r.id):
            _validate_role(role)
            if role.id in state.held:
                stored = stored_roles.get(role.id)
                if stored is None or (stored.description, list(stored.actions)) != (
                    role.description,
                    role.actions,
                ):
                    agents = ", ".join(state.held[role.id])
                    planned.problem(
                        "role_held_by_agent",
                        f"role '{role.id}' is held by agent {agents}; change it on the gateway",
                    )
                continue
            before = current_roles.get(role.id)
            if before == role:
                continue
            planned.changes.append(
                Change(
                    kind="role",
                    name=role.id,
                    op="create" if before is None else "update",
                    before=None if before is None else before.model_dump(mode="json"),
                    after=role.model_dump(mode="json"),
                )
            )
            planned.ops.put_roles.append(
                Role(id=role.id, description=role.description, actions=tuple(role.actions))
            )
            check_actions(f"role '{role.id}'", role.actions)
        wanted_roles = {r.id for r in config.roles}
        for role_id, before in sorted(current_roles.items()):
            if role_id not in wanted_roles:
                planned.changes.append(
                    Change(
                        kind="role",
                        name=role_id,
                        op="delete",
                        before=before.model_dump(mode="json"),
                    )
                )
                planned.ops.delete_roles.append(role_id)
        resulting_roles = wanted_roles | set(state.held)
        existing_roles = set(stored_roles)

        def check_role(what: str, role: str, changed: bool) -> None:
            if role in resulting_roles:
                return
            if changed or role in existing_roles:
                planned.problem(
                    "missing_role", f"{what} names role '{role}', which would not exist"
                )

        # users
        current_users = {u.id: u for u in state.users}
        claimed: dict[str, ConfigUser] = {}
        unmatched: list[ConfigUser] = []
        for item in config.users:
            if item.id is not None and item.id in current_users:
                claimed[item.id] = item
            else:
                unmatched.append(item)
        for item in unmatched:
            target = next(
                (u for u in state.users if u.id not in claimed and u.match == item.match),
                None,
            )
            if target is not None:
                claimed[target.id] = item
                continue
            name = match_key(item.match)
            planned.changes.append(
                Change(
                    kind="user",
                    name=name,
                    op="create",
                    after=item.model_copy(update={"id": None}).model_dump(mode="json"),
                )
            )
            planned.ops.new_users.append((name, item))
            for role_id in item.roles:
                check_role(f"user '{name}'", role_id, True)
        for user_id, item in sorted(claimed.items()):
            stored_user = current_users[user_id]
            roles = tuple(dict.fromkeys(item.roles))
            name = match_key(item.match)
            if stored_user.match == item.match and stored_user.roles == roles:
                for role_id in roles:
                    check_role(f"user '{name}'", role_id, False)
                continue
            after = User(id=user_id, match=item.match, roles=roles)
            planned.changes.append(
                Change(
                    kind="user",
                    name=name,
                    op="update",
                    before=_user_dump(stored_user),
                    after=_user_dump(after),
                )
            )
            planned.ops.put_users.append(after)
            for role_id in roles:
                check_role(f"user '{name}'", role_id, True)
        for user in state.users:
            if user.id not in claimed:
                planned.changes.append(
                    Change(
                        kind="user",
                        name=match_key(user.match),
                        op="delete",
                        before=_user_dump(user),
                    )
                )
                planned.ops.delete_users.append(user.id)

        # policies
        current_policies = {policy_name(p): p for p in state.policies if p.subject.is_user_side}
        exported = {p.name: p for p in current.policies}
        resources_by_name = {r.name: r for r in state.resources}
        for spec in sorted(config.policies, key=lambda p: p.name):
            _validate_policy(spec)
            what = f"policy '{spec.name}'"
            if not spec.subject.is_user_side:
                planned.problem(
                    "agent_side_policy",
                    f"{what} has an agent subject; agent-side policies stay with the gateway admin",
                )
                continue
            before_spec = exported.get(spec.name)
            if before_spec == spec:
                if spec.subject.user_role is not None:
                    check_role(what, spec.subject.user_role, False)
                continue
            stored_policy = current_policies.get(spec.name)
            planned.changes.append(
                Change(
                    kind="policy",
                    name=spec.name,
                    op="create" if before_spec is None else "update",
                    before=None if before_spec is None else before_spec.model_dump(mode="json"),
                    after=spec.model_dump(mode="json"),
                )
            )
            check_actions(what, spec.actions)
            if spec.subject.user_role is not None:
                check_role(what, spec.subject.user_role, True)
            missing = [n for n in spec.resources.names if n not in resources_by_name]
            for name in missing:
                planned.problem("missing_resource", f"{what} names unknown resource '{name}'")
            if missing:
                continue
            ids = {n: resources_by_name[n].id for n in spec.resources.names}
            if stored_policy is None:
                planned.ops.new_policies.append(spec)
            else:
                keep = stored_policy.name
                planned.ops.put_policies.append(_to_policy(spec, stored_policy.id, keep, ids))
        wanted_policies = {p.name for p in config.policies}
        for name, stored_policy in sorted(current_policies.items()):
            if name not in wanted_policies:
                before_policy = exported.get(name)
                planned.changes.append(
                    Change(
                        kind="policy",
                        name=name,
                        op="delete",
                        before=None
                        if before_policy is None
                        else before_policy.model_dump(mode="json"),
                    )
                )
                planned.ops.delete_policies.append(stored_policy.id)

        # tables a sql_database resource allows
        for name, tables in sorted(config.resource_tables.items()):
            resource = resources_by_name.get(name)
            if resource is None or resource.type is not ResourceType.SQL_DATABASE:
                planned.problem(
                    "missing_resource", f"resource_tables names unknown sql_database '{name}'"
                )
                continue
            wanted = list(dict.fromkeys(tables))
            before_tables = _tables_of(resource) or []
            if wanted == before_tables:
                continue
            try:
                self._resources.normalized_attributes(
                    resource.type, {**resource.attributes, ALLOWED_TABLES: wanted}
                )
            except InvalidParamsError as exc:
                raise InvalidParamsError(f"resource_tables.{name}: {exc.message}") from None
            planned.changes.append(
                Change(
                    kind="resource_tables",
                    name=name,
                    op="update",
                    before=before_tables,
                    after=wanted,
                )
            )
            planned.ops.tables.append((resource, wanted))
            catalog = await self.catalog.tables(resource)
            if catalog is not None:
                for table in wanted:
                    if table not in catalog:
                        planned.problem(
                            "table_not_in_catalog",
                            f"table '{table}' is not in the last catalog of resource '{name}'",
                        )

        # admins
        admin_roles = set(self.settings.user_roles) & resulting_roles
        if self.settings.user_roles and not any(
            set(item.roles) & admin_roles for item in config.users
        ):
            planned.problem("last_admin", "no user would keep an admin role (admin.user_roles)")
        if actor is not None and actor.user is not None:
            future = [
                User(id=item.id or f"new-{index}", match=item.match, roles=tuple(item.roles))
                for index, item in enumerate(config.users)
            ]
            mine = user_roles(matching_users(future, actor.user.subject, actor.user.groups))
            if not set(mine) & admin_roles:
                planned.problem("self_lockout", "this plan would remove your own admin role")

        order = {"role": 0, "user": 1, "policy": 2, "resource_tables": 3}
        planned.changes.sort(key=lambda c: (order[c.kind], c.name))
        return planned


# ---- helpers -----------------------------------------------------------------------------


def _tables_of(resource: Resource) -> list[str] | None:
    if resource.type is not ResourceType.SQL_DATABASE:
        return None
    tables = resource.attributes.get(ALLOWED_TABLES, [])
    return [str(t) for t in tables] if isinstance(tables, list | tuple) else []


def _user_dump(user: User) -> dict[str, Any]:
    return ConfigUser(id=user.id, match=user.match, roles=list(user.roles)).model_dump(mode="json")


def _export_policies(state: _State) -> list[UserPolicy]:
    names = state.resource_names()
    result: list[UserPolicy] = []
    for policy in state.policies:
        subject = policy.subject
        if not subject.is_user_side:
            continue
        result.append(
            UserPolicy.model_validate(
                {
                    "name": policy_name(policy),
                    "subject": {"user_role": subject.user_role}
                    if subject.user_role is not None
                    else {"user": subject.user},
                    "actions": list(policy.actions),
                    "resources": {
                        "names": sorted(names[i] for i in policy.resources.ids if i in names),
                        "tags": list(policy.resources.tags),
                    }
                    if any(i in names for i in policy.resources.ids) or policy.resources.tags
                    # Every resource it named is gone, so it matches nothing; a config still
                    # needs a selector, and this tag is on no resource.
                    else {"names": [], "tags": [NO_RESOURCE_TAG]},
                    "effect": str(policy.effect),
                    "approval": str(policy.approval),
                    "expires_at": None
                    if policy.expires_at is None
                    else to_rfc3339(policy.expires_at),
                }
            )
        )
    return sorted(result, key=lambda p: p.name)


def _export(state: _State) -> AccessConfig:
    return AccessConfig(
        roles=[
            ConfigRole(id=r.id, description=r.description, actions=list(r.actions))
            for r in state.roles
            if r.id not in state.held
        ],
        users=[ConfigUser(id=u.id, match=u.match, roles=list(u.roles)) for u in state.users],
        policies=_export_policies(state),
        resource_tables={
            r.name: _tables_of(r) or []
            for r in sorted(state.resources, key=lambda r: r.name)
            if r.type is ResourceType.SQL_DATABASE
        },
    )


def _digest(config: AccessConfig) -> str:
    return sha256_digest(config.model_dump(mode="json", by_alias=True))


def _plan_out(stored: StoredPlan) -> PlanOut:
    return PlanOut(
        plan_id=stored.id,
        base_digest=stored.base_digest,
        created_by=stored.created_by,
        expires_at=to_rfc3339(stored.expires_at),
        status=stored.status,
        changes=[Change.model_validate(c) for c in stored.changes],
        problems=[Problem.model_validate(p) for p in stored.problems],
    )


def _validate_role(role: ConfigRole) -> None:
    try:
        _ROLE_ID.validate_python(
            {"id": role.id, "description": role.description, "actions": role.actions}
        )
    except ValidationError as exc:
        raise InvalidParamsError(f"role '{role.id}': {_first_error(exc)}") from None


def _validate_policy(spec: UserPolicy) -> None:
    for pattern in spec.actions:
        if re.fullmatch(ACTION_PATTERN, pattern) is None:
            raise InvalidParamsError(f"policy '{spec.name}': invalid action '{pattern}'")
    if spec.expires_at is not None:
        try:
            _DATETIME.validate_python(spec.expires_at)
        except ValidationError:
            raise InvalidParamsError(f"policy '{spec.name}': invalid expires_at") from None


def _first_error(exc: ValidationError) -> str:
    error = exc.errors(include_input=False, include_url=False)[0]
    loc = ".".join(str(p) for p in error["loc"])
    return f"{loc}: {error['msg']}" if loc else str(error["msg"])


def _to_policy(
    spec: UserPolicy, policy_id: str, keep_name: str | None, resource_ids: dict[str, str]
) -> Policy:
    """The stored policy for ``spec``. An unnamed policy exported under its id stays unnamed."""
    name: str | None = spec.name
    if keep_name is None and spec.name == policy_id.lower():
        name = None
    subject = spec.subject
    return Policy(
        id=policy_id,
        name=name,
        subject=PolicySubject(user_role=subject.user_role)
        if subject.user_role is not None
        else PolicySubject(user=subject.user),
        actions=tuple(spec.actions),
        resources=ResourceSelector(
            ids=tuple(resource_ids[n] for n in spec.resources.names if n in resource_ids),
            tags=tuple(spec.resources.tags),
        ),
        effect=PolicyEffect(spec.effect),
        approval=ApprovalMode(spec.approval),
        expires_at=None if spec.expires_at is None else _DATETIME.validate_python(spec.expires_at),
    )


def _user_side_policy(
    policies: Sequence[Policy],
    principal: Principal,
    action: ActionDefinition,
    resource: Resource,
    deciding: str | None,
    now: datetime,
) -> str | None:
    """The user-side policy behind a grant: the deciding one if it is user side, else the
    first live user-side allow that matches. That is the policy an access admin can change."""
    matching = [
        p
        for p in policies
        if p.effect is PolicyEffect.ALLOW
        and (p.expires_at is None or p.expires_at > now)
        and user_subject_matches(p, principal)
        and grants(p.actions, action)
        and selector_matches(p.resources, resource)
    ]
    chosen = next((p for p in matching if p.id == deciding), matching[0] if matching else None)
    return None if chosen is None else policy_name(chosen)


def agent_view_principal(agent: Agent) -> Principal:
    """An agent principal for computing access as if a call came through ``agent``."""
    return Principal(
        kind=TokenKind.AGENT,
        token_id="admin-view",  # noqa: S106 - an actor id, not a secret
        agent_id=agent.id,
        roles=agent.roles,
    )


__all__ = [
    "PLAN_TTL",
    "AccessAdmin",
    "AdminActor",
    "StoredPlan",
    "agent_view_principal",
    "policy_name",
]
