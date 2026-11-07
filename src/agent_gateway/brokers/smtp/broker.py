"""SMTP broker: ``mail.send`` to recipients in the resource's allowed domains (SPEC §11.5)."""

from collections.abc import Mapping

from pydantic import BaseModel, ValidationError

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.brokers.output import BrokerError, run_safely
from agent_gateway.brokers.smtp.models import MailSendParams, SmtpServerAttributes
from agent_gateway.brokers.smtp.sender import MailSender, SmtplibSender, login_from
from agent_gateway.modules.action_registry.decorators import action, collect_actions
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.resources.models import ResourceType


def server_attributes(ctx: ActionContext) -> SmtpServerAttributes:
    if ctx.resource.type is not ResourceType.SMTP_SERVER:
        raise BrokerError("resource is not an smtp_server")
    try:
        return SmtpServerAttributes.model_validate(ctx.resource.attributes)
    except ValidationError as exc:
        raise BrokerError("smtp_server resource attributes are invalid") from exc


def check_recipients(attrs: SmtpServerAttributes, params: MailSendParams) -> None:
    if len(params.to) > attrs.max_recipients:
        raise BrokerError(f"give 1 to {attrs.max_recipients} recipients")
    for address in params.to:
        if not attrs.allows(address):
            raise BrokerError(f"recipient domain of '{address}' is not allowed")


class SmtpBroker:
    def __init__(self, sender: MailSender | None = None) -> None:
        self._sender = sender or SmtplibSender()

    @property
    def name(self) -> str:
        return "smtp"

    def resource_attribute_models(self) -> Mapping[ResourceType, type[BaseModel]]:
        return {ResourceType.SMTP_SERVER: SmtpServerAttributes}

    def register(self, registry: ActionRegistry) -> None:
        for registered in collect_actions(self):
            registry.register(registered)

    @action(
        id="mail.send",
        resource_type=ResourceType.SMTP_SERVER,
        risk=RiskLevel.MEDIUM,
        description=(
            "Send a plain-text email. Every recipient must be in the server's allowed domains."
        ),
        input_model=MailSendParams,
    )
    async def send(self, ctx: ActionContext, params: MailSendParams) -> ActionResult:
        async def body() -> ActionResult:
            attrs = server_attributes(ctx)
            check_recipients(attrs, params)
            login = login_from(ctx.credential, attrs)
            outcome = await self._sender.send(attrs, login, params)
            refused = {r.lower() for r in outcome.refused}
            data = {
                "sent_to": [r for r in params.to if r.lower() not in refused],
                "refused": list(outcome.refused),
                "message_id": outcome.message_id,
            }
            return ActionResult(ok=True, data=data)

        return await run_safely(ctx, "mail.send", body)
