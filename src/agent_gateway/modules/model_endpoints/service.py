"""Model listing and one chat turn per call (SPEC §10.4, §15.4).

Allowed models are decided by the policy engine with the fixed ``model.chat`` action, so
roles, policies, and user ∩ agent apply as for any action. Message text is never stored:
each call leaves one ``model.chat`` audit event with token counts, not the text.
"""

import logging
from typing import Any

import httpx
from pydantic import ValidationError

from agent_gateway.common.clock import Clock
from agent_gateway.common.errors import ModelNotFoundError
from agent_gateway.modules.audit.models import Actor, ActorType, AuditEventType, AuditRecord
from agent_gateway.modules.audit.ports import AuditLog
from agent_gateway.modules.authorization.models import AuthorizationRequest, Policy, Role
from agent_gateway.modules.authorization.ports import PolicyEngine
from agent_gateway.modules.credentials.models import SecretPayload
from agent_gateway.modules.credentials.ports import CredentialStore
from agent_gateway.modules.execution.redact import redact
from agent_gateway.modules.identity.models import Principal, TokenKind
from agent_gateway.modules.model_endpoints.models import (
    MODEL_CHAT,
    ChatIn,
    ChatOut,
    ModelAttributes,
    ModelInfo,
)
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.modules.resources.ports import ResourceRegistry
from agent_gateway.modules.storage.ports import Collection

CHAT_PATH = "/v1/chat/completions"
INVALID_RESPONSE = "model call failed: invalid response"
CREDENTIAL_UNAVAILABLE = "model call failed: credential unavailable"
MISCONFIGURED = "model call failed: model resource is misconfigured"
REASON_AGENT_ONLY = "only agent tokens can call models"
REASON_APPROVAL = "policy requires approval, which a chat turn cannot wait for"
# Path names are caller input; keep what reaches the audit log short.
MAX_LOGGED_NAME = 64


class ModelService:
    def __init__(
        self,
        *,
        resources: ResourceRegistry,
        credentials: CredentialStore,
        roles: Collection[Role],
        policies: Collection[Policy],
        policy_engine: PolicyEngine,
        audit: AuditLog,
        clock: Clock,
        transport: httpx.AsyncBaseTransport | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._resources = resources
        self._credentials = credentials
        self._roles = roles
        self._policies = policies
        self._policy_engine = policy_engine
        self._audit = audit
        self._clock = clock
        # Tests inject a fake upstream; in production each call opens its own client.
        self._transport = transport
        self._log = logger or logging.getLogger("agent_gateway.models")

    async def visible(self, principal: Principal) -> list[ModelInfo]:
        """Model resources the caller may chat with, by name."""
        roles, policies = await self._roles.all(), await self._policies.all()
        found: list[ModelInfo] = []
        for resource in await self._resources.list(type=ResourceType.MODEL):
            attributes = self._attributes(resource)
            if (
                attributes is not None
                and self._denial(principal, resource, roles, policies) is None
            ):
                found.append(ModelInfo(name=resource.name, model_id=attributes.model_id))
        return sorted(found, key=lambda m: m.name)

    async def chat(self, principal: Principal, name: str, turn: ChatIn) -> ChatOut:
        details: dict[str, Any] = {
            "model": name[:MAX_LOGGED_NAME],
            "user": principal.user.subject if principal.user else None,
            "correlation_id": turn.correlation_id,
        }
        resource = await self._find(name)
        if resource is None:
            await self._record(principal, None, {**details, "outcome": "not_found"})
            raise ModelNotFoundError(f"model {name[:MAX_LOGGED_NAME]!r} not found")

        roles, policies = await self._roles.all(), await self._policies.all()
        denial = self._denial(principal, resource, roles, policies)
        if denial is not None:
            await self._record(
                principal, resource, {**details, "outcome": "denied", "reason": denial}
            )
            return ChatOut(status="denied", error=f"model '{name}' is not allowed for this caller")

        attributes = self._attributes(resource)
        if attributes is None:
            await self._record(
                principal, resource, {**details, "outcome": "error", "reason": MISCONFIGURED}
            )
            return ChatOut(status="error", error=MISCONFIGURED)
        details["model_id"] = attributes.model_id

        out = await self._call(resource, attributes, turn)
        if out.status != "ok":
            await self._record(
                principal, resource, {**details, "outcome": "error", "reason": out.error}
            )
            return out
        usage = out.usage or {}
        message = out.message or {}
        await self._record(
            principal,
            resource,
            {
                **details,
                "outcome": "ok",
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "tool_calls": len(message.get("tool_calls") or []),
            },
        )
        return out

    async def _call(self, resource: Resource, attributes: ModelAttributes, turn: ChatIn) -> ChatOut:
        body: dict[str, Any] = {
            "model": attributes.model_id,
            "messages": turn.messages,
            **attributes.options,
        }
        if turn.tools:
            body["tools"] = turn.tools
            body["tool_choice"] = "auto"
        if turn.temperature is not None:
            body["temperature"] = turn.temperature
        if turn.max_tokens is not None:
            body["max_tokens"] = turn.max_tokens

        credential: SecretPayload | None = None
        secrets: list[str] = []
        headers: dict[str, str] = {}
        try:
            if resource.credential_id is not None:
                try:
                    credential = await self._credentials.open(resource.credential_id)
                except Exception:
                    self._log.exception("cannot open the credential of model %s", resource.id)
                    return ChatOut(status="error", error=CREDENTIAL_UNAVAILABLE)
                secrets = credential.secret_values()
                headers["Authorization"] = f"Bearer {credential.reveal()}"
            try:
                async with httpx.AsyncClient(
                    transport=self._transport, timeout=attributes.timeout_seconds
                ) as client:
                    response = await client.post(
                        f"{attributes.base_url}{CHAT_PATH}", json=body, headers=headers
                    )
                    response.raise_for_status()
                    data = response.json()
            except httpx.HTTPError as exc:
                self._log.warning("model %s call failed: %r", resource.id, exc)
                return ChatOut(status="error", error=f"model call failed: {type(exc).__name__}")
            except ValueError:
                return ChatOut(status="error", error=INVALID_RESPONSE)
        finally:
            if credential is not None:
                credential.wipe()

        message, usage = _parse(data)
        if message is None:
            self._log.warning("model %s returned an unexpected body", resource.id)
            return ChatOut(status="error", error=INVALID_RESPONSE)
        return ChatOut(
            status="ok",
            message=redact(message, secrets),
            usage=redact(usage, secrets),
            model_id=attributes.model_id,
        )

    async def _find(self, name: str) -> Resource | None:
        for resource in await self._resources.list(type=ResourceType.MODEL):
            if resource.name == name:
                return resource
        return None

    def _denial(
        self,
        principal: Principal,
        resource: Resource,
        roles: list[Role],
        policies: list[Policy],
    ) -> str | None:
        """Why the caller may not chat with ``resource``; ``None`` when it may.

        A chat turn cannot wait for an approval, so an allow that needs one is a denial.
        """
        if principal.kind is not TokenKind.AGENT:
            return REASON_AGENT_ONLY
        decision = self._policy_engine.decide(
            AuthorizationRequest(
                principal=principal,
                action=MODEL_CHAT,
                resource=resource,
                roles=roles,
                policies=policies,
                now=self._clock.now(),
            )
        )
        if not decision.allowed:
            return decision.reason
        return REASON_APPROVAL if decision.approval_required else None

    def _attributes(self, resource: Resource) -> ModelAttributes | None:
        try:
            return ModelAttributes.model_validate(resource.attributes)
        except ValidationError:
            self._log.warning("model resource %s has invalid attributes", resource.id)
            return None

    async def _record(
        self, principal: Principal, resource: Resource | None, details: dict[str, Any]
    ) -> None:
        actor = (
            Actor(type=ActorType.AGENT, id=principal.agent_id)
            if principal.agent_id is not None
            else Actor(type=ActorType.ADMIN, id=principal.token_id)
        )
        await self._audit.append(
            AuditRecord(
                event=AuditEventType.MODEL_CHAT,
                actor=actor,
                action=MODEL_CHAT.id,
                resource_id=resource.id if resource else None,
                details=details,
            )
        )


def _parse(data: Any) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """``choices[0].message`` and ``usage`` of an OpenAI chat completion, if well formed."""
    if not isinstance(data, dict):
        return None, {}
    choices = data.get("choices")
    first = choices[0] if isinstance(choices, list) and choices else None
    message = first.get("message") if isinstance(first, dict) else None
    usage = data.get("usage")
    return (
        message if isinstance(message, dict) else None,
        usage if isinstance(usage, dict) else {},
    )
