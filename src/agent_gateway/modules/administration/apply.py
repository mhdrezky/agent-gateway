"""Declarative, idempotent onboarding (SPEC §20.6).

``apply_file`` creates or updates the objects a seed lists. It does not delete objects
the seed omits, and it does not issue tokens. Secrets are read from the environment or
from a file the seed names; they are never taken from the seed itself.
"""

import os
import re
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import AwareDatetime, Field, ValidationError, field_validator, model_validator

from agent_gateway.common.errors import ConflictError, InvalidParamsError
from agent_gateway.common.models import StrictModel
from agent_gateway.modules.administration.service import AdminService
from agent_gateway.modules.authorization.models import (
    ActionPattern,
    ApprovalMode,
    Policy,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialMeta, CredentialType, SecretPayload
from agent_gateway.modules.identity.models import (
    NAME_PATTERN,
    Agent,
    AgentStatus,
    Principal,
    User,
    UserMatch,
)
from agent_gateway.modules.resources.models import TAG_PATTERN, Resource, ResourceType

_ENV_NAME = r"^[A-Za-z_][A-Za-z0-9_]*$"
_POLICY_NAME = r"^[a-z][a-z0-9_-]*$"


class ApplyKind(StrEnum):
    ROLE = "role"
    AGENT = "agent"
    USER = "user"
    CREDENTIAL = "credential"
    RESOURCE = "resource"
    POLICY = "policy"


class ApplyResult(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    UNCHANGED = "unchanged"


class ApplyChange(StrictModel):
    kind: ApplyKind
    name: str
    result: ApplyResult


class ApplyReport(StrictModel):
    changes: tuple[ApplyChange, ...] = ()


class SeedRole(StrictModel):
    id: str = Field(min_length=1, max_length=64, pattern=_POLICY_NAME)
    description: str = ""
    actions: tuple[ActionPattern, ...] = ()

    @field_validator("actions")
    @classmethod
    def _unique(cls, actions: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(actions))


class SeedAgent(StrictModel):
    name: str = Field(min_length=1, max_length=64, pattern=NAME_PATTERN)
    description: str = Field(default="", max_length=500)
    roles: tuple[str, ...] = ()
    status: AgentStatus = AgentStatus.ACTIVE

    @field_validator("roles")
    @classmethod
    def _unique(cls, roles: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(roles))


class SeedUser(StrictModel):
    subject: str | None = Field(default=None, min_length=1, max_length=255)
    group: str | None = Field(default=None, min_length=1, max_length=255)
    roles: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _one_match(self) -> "SeedUser":
        if (self.subject is None) == (self.group is None):
            raise ValueError("user needs exactly one of subject or group")
        return self

    @field_validator("roles")
    @classmethod
    def _unique(cls, roles: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(roles))


class SeedCredential(StrictModel):
    name: str = Field(min_length=1, max_length=64, pattern=NAME_PATTERN)
    type: CredentialType
    secret_env: str | None = Field(default=None, pattern=_ENV_NAME)
    secret_file: str | None = Field(default=None, min_length=1, max_length=4096)
    fields: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _one_source(self) -> "SeedCredential":
        if (self.secret_env is None) == (self.secret_file is None):
            raise ValueError("credential needs exactly one of secret_env or secret_file")
        return self

    @field_validator("fields")
    @classmethod
    def _field_names(cls, fields: dict[str, str]) -> dict[str, str]:
        if any(name == "" for name in fields):
            raise ValueError("empty field name")
        return fields


class SeedResource(StrictModel):
    name: str = Field(min_length=1, max_length=64, pattern=NAME_PATTERN)
    type: ResourceType
    tags: tuple[str, ...] = ()
    attributes: dict[str, Any] = Field(default_factory=dict)
    credential: str | None = Field(default=None, pattern=NAME_PATTERN)

    @field_validator("tags")
    @classmethod
    def _tags(cls, tags: tuple[str, ...]) -> tuple[str, ...]:
        for tag in tags:
            if re.fullmatch(TAG_PATTERN, tag) is None:
                raise ValueError("invalid tag")
        return tuple(dict.fromkeys(tags))


class SeedSubject(StrictModel):
    role: str | None = Field(default=None, pattern=_POLICY_NAME)
    agent: str | None = Field(default=None, pattern=NAME_PATTERN)
    user: str | None = Field(default=None, min_length=1, max_length=255)
    user_role: str | None = Field(default=None, pattern=_POLICY_NAME)

    @model_validator(mode="after")
    def _one(self) -> "SeedSubject":
        given = [v for v in (self.role, self.agent, self.user, self.user_role) if v is not None]
        if len(given) != 1:
            raise ValueError("subject needs exactly one of role, agent, user, or user_role")
        return self


class SeedSelector(StrictModel):
    names: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @field_validator("names")
    @classmethod
    def _names(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(names))

    @field_validator("tags")
    @classmethod
    def _tags(cls, tags: tuple[str, ...]) -> tuple[str, ...]:
        for tag in tags:
            if re.fullmatch(TAG_PATTERN, tag) is None:
                raise ValueError("invalid tag")
        return tuple(dict.fromkeys(tags))

    @model_validator(mode="after")
    def _some(self) -> "SeedSelector":
        if not self.names and not self.tags:
            raise ValueError("resources needs names or tags")
        return self


class SeedPolicy(StrictModel):
    name: str = Field(min_length=1, max_length=64, pattern=_POLICY_NAME)
    subject: SeedSubject
    actions: tuple[ActionPattern, ...] = Field(min_length=1)
    resources: SeedSelector
    effect: PolicyEffect = PolicyEffect.ALLOW
    approval: ApprovalMode = ApprovalMode.BY_RISK
    expires_at: AwareDatetime | None = None

    @field_validator("actions")
    @classmethod
    def _unique(cls, actions: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(actions))


class Seed(StrictModel):
    roles: tuple[SeedRole, ...] = ()
    agents: tuple[SeedAgent, ...] = ()
    users: tuple[SeedUser, ...] = ()
    credentials: tuple[SeedCredential, ...] = ()
    resources: tuple[SeedResource, ...] = ()
    policies: tuple[SeedPolicy, ...] = ()


def load_seed(path: Path) -> Seed:
    """Parse a seed file. Secret values are not read here."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidParamsError(f"cannot read seed file: {exc.strerror}") from None
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        raise InvalidParamsError("seed file is not valid YAML") from None
    if not isinstance(document, dict):
        raise InvalidParamsError("seed file must be a mapping")
    try:
        seed = Seed.model_validate(document)
    except ValidationError as exc:
        raise _invalid_seed(exc) from None
    _reject_duplicate_entries(seed)
    return seed


def read_secrets(seed: Seed, base: Path) -> dict[str, SecretPayload]:
    """Load every credential secret. Callers wipe the payloads when they are finished."""
    payloads: dict[str, SecretPayload] = {}
    try:
        for credential in seed.credentials:
            payloads[credential.name] = SecretPayload(
                credential.type, _secret_value(credential, base), dict(credential.fields)
            )
    except Exception:
        for payload in payloads.values():
            payload.wipe()
        raise
    return payloads


async def apply_file(admin: AdminService, actor: Principal, path: Path) -> ApplyReport:
    """Apply one seed file. A second apply of the same file only reports ``unchanged``."""
    seed = load_seed(path)
    secrets = read_secrets(seed, path.parent)
    try:
        return await apply_seed(admin, actor, seed, secrets)
    finally:
        for payload in secrets.values():
            payload.wipe()


async def apply_seed(
    admin: AdminService,
    actor: Principal,
    seed: Seed,
    secrets: Mapping[str, SecretPayload],
) -> ApplyReport:
    roles = await admin.list_roles(actor)
    agents = await admin.list_agents(actor)
    users = await admin.list_users(actor)
    credentials = await admin.list_credentials(actor)
    resources = await admin.list_resources(actor)
    policies = await admin.list_policies(actor)
    _reject_ambiguous(seed, agents, users, credentials, resources, policies)
    _reject_unresolved(seed, roles, agents, credentials, resources)
    _reject_type_changes(seed, credentials, resources)
    for resource in seed.resources:
        admin.preview_resource_attributes(actor, resource.type, resource.attributes)

    changes: list[ApplyChange] = []
    changes.extend(await _apply_credentials(admin, actor, seed, secrets, credentials))
    changes.extend(await _apply_roles(admin, actor, seed, roles))
    changes.extend(await _apply_users(admin, actor, seed, users))
    changes.extend(await _apply_agents(admin, actor, seed, agents))
    changes.extend(await _apply_resources(admin, actor, seed))
    changes.extend(await _apply_policies(admin, actor, seed))
    return ApplyReport(changes=tuple(changes))


def _secret_value(credential: SeedCredential, base: Path) -> str:
    if credential.secret_env is not None:
        value = os.environ.get(credential.secret_env)
        if value is None or value == "":
            raise InvalidParamsError(
                f"credential {credential.name!r} expects environment variable "
                f"{credential.secret_env}"
            )
        return value
    if credential.secret_file is None:
        raise InvalidParamsError(f"credential {credential.name!r} has no secret source")
    file = Path(credential.secret_file)
    path = file if file.is_absolute() else base / file
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise InvalidParamsError(
            f"credential {credential.name!r} secret file cannot be read"
        ) from None
    if text.endswith("\n"):
        text = text[:-1]
    if text.endswith("\r"):
        text = text[:-1]
    if text == "":
        raise InvalidParamsError(f"credential {credential.name!r} secret file is empty")
    return text


def _reject_duplicate_entries(seed: Seed) -> None:
    _unique([role.id for role in seed.roles], "role")
    _unique([agent.name for agent in seed.agents], "agent")
    _unique([_user_name(user) for user in seed.users], "user")
    _unique([credential.name for credential in seed.credentials], "credential")
    _unique([resource.name for resource in seed.resources], "resource")
    _unique([policy.name for policy in seed.policies], "policy")


def _unique(names: Sequence[str], kind: str) -> None:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            raise InvalidParamsError(f"seed lists {kind} {name!r} more than once")
        seen.add(name)


def _reject_ambiguous(
    seed: Seed,
    agents: Sequence[Agent],
    users: Sequence[User],
    credentials: Sequence[CredentialMeta],
    resources: Sequence[Resource],
    policies: Sequence[Policy],
) -> None:
    for agent in seed.agents:
        _only(agents, _agent_name, agent.name, "agent", agent.name)
    for user in seed.users:
        match = _match(user)
        _only(users, _user_match, match, "user", _user_name(user))
    for credential in seed.credentials:
        _only(credentials, _credential_name, credential.name, "credential", credential.name)
    for resource in seed.resources:
        _only(resources, _resource_name, resource.name, "resource", resource.name)
    for policy in seed.policies:
        _only(policies, _policy_name, policy.name, "policy", policy.name)


def _reject_unresolved(
    seed: Seed,
    roles: Sequence[Role],
    agents: Sequence[Agent],
    credentials: Sequence[CredentialMeta],
    resources: Sequence[Resource],
) -> None:
    role_ids = {role.id for role in roles} | {role.id for role in seed.roles}
    agent_names = {agent.name for agent in agents} | {agent.name for agent in seed.agents}
    resource_names = {item.name for item in resources} | {item.name for item in seed.resources}
    credential_names = {item.name for item in credentials} | {
        item.name for item in seed.credentials
    }
    for agent in seed.agents:
        for role in agent.roles:
            if role not in role_ids:
                raise InvalidParamsError(f"seed agent {agent.name!r} names unknown role {role!r}")
    for user in seed.users:
        for role in user.roles:
            if role not in role_ids:
                raise InvalidParamsError(
                    f"seed user {_user_name(user)!r} names unknown role {role!r}"
                )
    for resource in seed.resources:
        if resource.credential is not None and resource.credential not in credential_names:
            raise InvalidParamsError(
                f"seed resource {resource.name!r} names unknown credential {resource.credential!r}"
            )
    for policy in seed.policies:
        subject = policy.subject
        if subject.role is not None and subject.role not in role_ids:
            raise InvalidParamsError(
                f"seed policy {policy.name!r} names unknown role {subject.role!r}"
            )
        if subject.user_role is not None and subject.user_role not in role_ids:
            raise InvalidParamsError(
                f"seed policy {policy.name!r} names unknown role {subject.user_role!r}"
            )
        if subject.agent is not None and subject.agent not in agent_names:
            raise InvalidParamsError(
                f"seed policy {policy.name!r} names unknown agent {subject.agent!r}"
            )
        for name in policy.resources.names:
            if name not in resource_names:
                raise InvalidParamsError(
                    f"seed policy {policy.name!r} names unknown resource {name!r}"
                )


def _reject_type_changes(
    seed: Seed, credentials: Sequence[CredentialMeta], resources: Sequence[Resource]
) -> None:
    for credential in seed.credentials:
        stored = _only(
            credentials, _credential_name, credential.name, "credential", credential.name
        )
        if stored is not None and stored.type is not credential.type:
            raise ConflictError(
                f"credential {credential.name!r} is {stored.type.value}; "
                f"the seed asks for {credential.type.value}"
            )
    for resource in seed.resources:
        stored_resource = _only(resources, _resource_name, resource.name, "resource", resource.name)
        if stored_resource is not None and stored_resource.type is not resource.type:
            raise ConflictError(
                f"resource {resource.name!r} is {stored_resource.type.value}; "
                f"the seed asks for {resource.type.value}"
            )


async def _apply_credentials(
    admin: AdminService,
    actor: Principal,
    seed: Seed,
    secrets: Mapping[str, SecretPayload],
    credentials: Sequence[CredentialMeta],
) -> list[ApplyChange]:
    changes: list[ApplyChange] = []
    for spec in seed.credentials:
        payload = secrets[spec.name]
        current = _only(credentials, _credential_name, spec.name, "credential", spec.name)
        if current is None:
            await admin.create_credential(actor, spec.name, payload)
            result = ApplyResult.CREATED
        elif await admin.credential_secret_matches(actor, current.id, payload):
            result = ApplyResult.UNCHANGED
        else:
            await admin.rotate_credential(actor, current.id, payload)
            result = ApplyResult.UPDATED
        changes.append(ApplyChange(kind=ApplyKind.CREDENTIAL, name=spec.name, result=result))
    return changes


async def _apply_roles(
    admin: AdminService, actor: Principal, seed: Seed, roles: Sequence[Role]
) -> list[ApplyChange]:
    changes: list[ApplyChange] = []
    for spec in seed.roles:
        desired = Role(id=spec.id, description=spec.description, actions=spec.actions)
        current = next((role for role in roles if role.id == spec.id), None)
        if current == desired:
            result = ApplyResult.UNCHANGED
        else:
            await admin.put_role(actor, desired)
            result = ApplyResult.CREATED if current is None else ApplyResult.UPDATED
        changes.append(ApplyChange(kind=ApplyKind.ROLE, name=spec.id, result=result))
    return changes


async def _apply_users(
    admin: AdminService, actor: Principal, seed: Seed, users: Sequence[User]
) -> list[ApplyChange]:
    changes: list[ApplyChange] = []
    for spec in seed.users:
        label = _user_name(spec)
        match = _match(spec)
        current = _only(users, _user_match, match, "user", label)
        if current is None:
            await admin.add_user(actor, match, spec.roles)
            result = ApplyResult.CREATED
        elif current.roles == spec.roles:
            result = ApplyResult.UNCHANGED
        else:
            await admin.set_user_roles(actor, current.id, spec.roles)
            result = ApplyResult.UPDATED
        changes.append(ApplyChange(kind=ApplyKind.USER, name=label, result=result))
    return changes


async def _apply_agents(
    admin: AdminService, actor: Principal, seed: Seed, agents: Sequence[Agent]
) -> list[ApplyChange]:
    changes: list[ApplyChange] = []
    for spec in seed.agents:
        current = _only(agents, _agent_name, spec.name, "agent", spec.name)
        if current is None:
            await admin.create_agent(
                actor,
                spec.name,
                description=spec.description,
                roles=spec.roles,
                status=spec.status,
            )
            result = ApplyResult.CREATED
        elif (
            current.description == spec.description
            and current.roles == spec.roles
            and current.status == spec.status
        ):
            result = ApplyResult.UNCHANGED
        else:
            await admin.update_agent(
                actor,
                current.id,
                description=spec.description,
                roles=spec.roles,
                status=spec.status,
            )
            result = ApplyResult.UPDATED
        changes.append(ApplyChange(kind=ApplyKind.AGENT, name=spec.name, result=result))
    return changes


async def _apply_resources(admin: AdminService, actor: Principal, seed: Seed) -> list[ApplyChange]:
    stored = await admin.list_resources(actor)
    credentials = _index_by_name(
        await admin.list_credentials(actor), lambda item: item.name, "credential"
    )
    changes: list[ApplyChange] = []
    for spec in seed.resources:
        current = _only(stored, _resource_name, spec.name, "resource", spec.name)
        credential_id = None if spec.credential is None else credentials[spec.credential].id
        attributes = admin.preview_resource_attributes(actor, spec.type, spec.attributes)
        if current is None:
            await admin.create_resource(
                actor,
                spec.type,
                spec.name,
                tags=spec.tags,
                attributes=spec.attributes,
                credential_id=credential_id,
            )
            result = ApplyResult.CREATED
        elif (
            current.tags == spec.tags
            and current.attributes == attributes
            and current.credential_id == credential_id
        ):
            result = ApplyResult.UNCHANGED
        else:
            await admin.update_resource(
                actor,
                current.id,
                tags=spec.tags,
                attributes=spec.attributes,
                credential_id=credential_id,
                detach_credential=credential_id is None,
            )
            result = ApplyResult.UPDATED
        changes.append(ApplyChange(kind=ApplyKind.RESOURCE, name=spec.name, result=result))
    return changes


async def _apply_policies(admin: AdminService, actor: Principal, seed: Seed) -> list[ApplyChange]:
    agents = _index_by_name(await admin.list_agents(actor), lambda agent: agent.name, "agent")
    resources = _index_by_name(
        await admin.list_resources(actor), lambda resource: resource.name, "resource"
    )
    stored = await admin.list_policies(actor)
    changes: list[ApplyChange] = []
    for spec in seed.policies:
        subject = _subject(spec.subject, agents)
        selector = ResourceSelector(
            ids=tuple(resources[name].id for name in spec.resources.names),
            tags=spec.resources.tags,
        )
        current = _only(stored, _policy_name, spec.name, "policy", spec.name)
        if current is None:
            await admin.create_policy(
                actor,
                name=spec.name,
                subject=subject,
                actions=spec.actions,
                resources=selector,
                effect=spec.effect,
                approval=spec.approval,
                expires_at=spec.expires_at,
            )
            result = ApplyResult.CREATED
        else:
            desired = current.model_copy(
                update={
                    "subject": subject,
                    "actions": spec.actions,
                    "resources": selector,
                    "effect": spec.effect,
                    "approval": spec.approval,
                    "expires_at": spec.expires_at,
                }
            )
            if desired == current:
                result = ApplyResult.UNCHANGED
            else:
                await admin.replace_policy(actor, desired)
                result = ApplyResult.UPDATED
        changes.append(ApplyChange(kind=ApplyKind.POLICY, name=spec.name, result=result))
    return changes


def _subject(subject: SeedSubject, agents: Mapping[str, Agent]) -> PolicySubject:
    if subject.role is not None:
        return PolicySubject(role=subject.role)
    if subject.user is not None:
        return PolicySubject(user=subject.user)
    if subject.user_role is not None:
        return PolicySubject(user_role=subject.user_role)
    if subject.agent is None:
        raise InvalidParamsError("policy subject is empty")
    return PolicySubject(agent_id=agents[subject.agent].id)


def _match(user: SeedUser) -> UserMatch:
    return UserMatch(subject=user.subject, group=user.group)


def _user_name(user: SeedUser) -> str:
    if user.subject is not None:
        return f"subject:{user.subject}"
    if user.group is not None:
        return f"group:{user.group}"
    raise InvalidParamsError("user needs exactly one of subject or group")


def _agent_name(agent: Agent) -> str:
    return agent.name


def _user_match(user: User) -> UserMatch:
    return user.match


def _credential_name(credential: CredentialMeta) -> str:
    return credential.name


def _resource_name(resource: Resource) -> str:
    return resource.name


def _policy_name(policy: Policy) -> str:
    # Policies made by the CLI or REST have no name; "" never matches a seed name.
    return policy.name or ""


def _only[T, K](
    items: Sequence[T], read: Callable[[T], K], key: K, kind: str, name: str
) -> T | None:
    found = [item for item in items if read(item) == key]
    if len(found) > 1:
        raise ConflictError(f"more than one {kind} matches {name!r}")
    return found[0] if found else None


def _index_by_name[T](items: Sequence[T], read: Callable[[T], str], kind: str) -> dict[str, T]:
    found: dict[str, T] = {}
    for item in items:
        name = read(item)
        if name in found:
            raise ConflictError(f"more than one {kind} matches {name!r}")
        found[name] = item
    return found


def _invalid_seed(exc: ValidationError) -> InvalidParamsError:
    fields = sorted({".".join(map(str, err["loc"])) or "(root)" for err in exc.errors()})
    return InvalidParamsError(f"invalid seed fields: {', '.join(fields)}")
