"""Request and response bodies that are specific to the REST API."""

from typing import Any, Literal

from pydantic import AwareDatetime, Field, SecretStr

from agent_gateway.common.models import StrictModel
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
)
from agent_gateway.modules.credentials.models import CredentialType
from agent_gateway.modules.execution.models import Execution
from agent_gateway.modules.identity.models import AgentStatus, Token, TokenKind
from agent_gateway.modules.resources.models import ResourceType


class Health(StrictModel):
    status: str
    version: str


class ContractOut(StrictModel):
    versions: list[str]


class ToolOutcome(StrictModel):
    """``structuredContent`` of a ``/mcp/actions`` tool call (contract §4.2)."""

    status: Literal["ok", "pending", "denied", "error"]
    execution_id: str | None = None
    result: dict[str, Any] | None = None
    summary: str | None = None
    error: str | None = None


class WhoAmI(StrictModel):
    kind: TokenKind
    token_id: str
    agent_id: str | None
    roles: tuple[str, ...]


class ActionInfo(StrictModel):
    id: str
    description: str
    risk: RiskLevel
    resource_type: ResourceType
    params_schema: dict[str, Any]


class ResourceInfo(StrictModel):
    """What an agent may see of a resource: no attributes, no credential reference."""

    id: str
    type: ResourceType
    name: str
    tags: tuple[str, ...]


class ExecutionPage(StrictModel):
    items: list[Execution]
    next_cursor: str | None


class AgentCreate(StrictModel):
    name: str
    description: str = ""
    roles: list[str] = Field(default_factory=list)


class AgentUpdate(StrictModel):
    description: str | None = None
    roles: list[str] | None = None
    status: AgentStatus | None = None


class TokenCreate(StrictModel):
    expires_at: AwareDatetime | None = None


class IssuedTokenOut(StrictModel):
    """The only response that ever carries a token in plaintext; shown once."""

    token: Token
    plaintext: str


class ResourceCreate(StrictModel):
    type: ResourceType
    name: str
    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    credential_id: str | None = None


class ResourceUpdate(StrictModel):
    name: str | None = None
    tags: list[str] | None = None
    attributes: dict[str, Any] | None = None
    credential_id: str | None = None


class CredentialSecret(StrictModel):
    value: SecretStr
    fields: dict[str, SecretStr] = Field(default_factory=dict)


class CredentialCreate(CredentialSecret):
    name: str
    type: CredentialType


class RoleBody(StrictModel):
    description: str = ""
    actions: list[str] = Field(default_factory=list)


class PolicyBody(StrictModel):
    subject: PolicySubject
    actions: list[str]
    resources: ResourceSelector
    effect: PolicyEffect
    approval: ApprovalMode = ApprovalMode.BY_RISK
    expires_at: AwareDatetime | None = None


class RejectBody(StrictModel):
    reason: str | None = Field(default=None, max_length=500)
