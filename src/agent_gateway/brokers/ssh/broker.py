"""SSH broker: the four SSH actions of SPEC §11.3."""

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ValidationError

from agent_gateway.brokers.base import ActionContext, ActionResult
from agent_gateway.brokers.output import BrokerError, OutputSanitizer, run_safely
from agent_gateway.brokers.ssh.commands import (
    SYSTEM_INFO_COMMANDS,
    logs_tail_command,
    service_restart_command,
    service_status_command,
)
from agent_gateway.brokers.ssh.models import (
    LogsParams,
    NoParams,
    ServiceParams,
    SshHostAttributes,
)
from agent_gateway.brokers.ssh.runner import AsyncsshRunner, CommandOutput, SshRunner
from agent_gateway.modules.action_registry.decorators import action, collect_actions
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.ports import ActionRegistry
from agent_gateway.modules.resources.models import ResourceType

# systemctl status: 0 = active, 3 = not running. Both are valid answers.
STATUS_OK_CODES = frozenset({0, 3})


def host_attributes(ctx: ActionContext) -> SshHostAttributes:
    if ctx.resource.type is not ResourceType.SSH_HOST:
        raise BrokerError("resource is not an ssh_host")
    try:
        return SshHostAttributes.model_validate(ctx.resource.attributes)
    except ValidationError as exc:
        raise BrokerError("ssh_host resource attributes are invalid") from exc


class SshBroker:
    def __init__(self, runner: SshRunner | None = None) -> None:
        self._runner = runner or AsyncsshRunner()

    @property
    def name(self) -> str:
        return "ssh"

    def resource_attribute_models(self) -> Mapping[ResourceType, type[BaseModel]]:
        return {ResourceType.SSH_HOST: SshHostAttributes}

    def register(self, registry: ActionRegistry) -> None:
        for registered in collect_actions(self):
            registry.register(registered)

    async def _run_one(self, ctx: ActionContext, command: str) -> CommandOutput:
        attrs = host_attributes(ctx)
        [output] = await self._runner.run(attrs, ctx.credential, [command])
        return output

    @staticmethod
    def _result(ctx: ActionContext, output: CommandOutput, ok: bool, **extra: Any) -> ActionResult:
        sanitizer = OutputSanitizer(ctx)
        data = {
            **extra,
            "exit_code": output.exit_code,
            "stdout": sanitizer.clean(output.stdout),
            "stderr": sanitizer.clean(output.stderr),
        }
        return ActionResult(ok=ok, data=data, truncated=sanitizer.truncated)

    @action(
        id="ssh.system.info",
        resource_type=ResourceType.SSH_HOST,
        risk=RiskLevel.LOW,
        description="Show uptime, disk usage, and memory usage of the host.",
        input_model=NoParams,
    )
    async def system_info(self, ctx: ActionContext, params: NoParams) -> ActionResult:
        async def body() -> ActionResult:
            attrs = host_attributes(ctx)
            names = list(SYSTEM_INFO_COMMANDS)
            outputs = await self._runner.run(
                attrs, ctx.credential, [SYSTEM_INFO_COMMANDS[n] for n in names]
            )
            sanitizer = OutputSanitizer(ctx)
            data = {
                name: {
                    "exit_code": out.exit_code,
                    "stdout": sanitizer.clean(out.stdout),
                    "stderr": sanitizer.clean(out.stderr),
                }
                for name, out in zip(names, outputs, strict=True)
            }
            ok = all(out.exit_code == 0 for out in outputs)
            return ActionResult(ok=ok, data=data, truncated=sanitizer.truncated)

        return await run_safely(ctx, "ssh.system.info", body)

    @action(
        id="ssh.service.status",
        resource_type=ResourceType.SSH_HOST,
        risk=RiskLevel.LOW,
        description="Show `systemctl status` of a service listed in the host's allowed_services.",
        input_model=ServiceParams,
    )
    async def service_status(self, ctx: ActionContext, params: ServiceParams) -> ActionResult:
        async def body() -> ActionResult:
            command = service_status_command(params.service, host_attributes(ctx))
            output = await self._run_one(ctx, command)
            return self._result(
                ctx,
                output,
                output.exit_code in STATUS_OK_CODES,
                service=params.service,
                active=output.exit_code == 0,
            )

        return await run_safely(ctx, "ssh.service.status", body)

    @action(
        id="ssh.service.restart",
        resource_type=ResourceType.SSH_HOST,
        risk=RiskLevel.MEDIUM,
        description="Restart a systemd service listed in the host's allowed_services.",
        input_model=ServiceParams,
    )
    async def service_restart(self, ctx: ActionContext, params: ServiceParams) -> ActionResult:
        async def body() -> ActionResult:
            command = service_restart_command(params.service, host_attributes(ctx))
            output = await self._run_one(ctx, command)
            return self._result(ctx, output, output.exit_code == 0, service=params.service)

        return await run_safely(ctx, "ssh.service.restart", body)

    @action(
        id="ssh.logs.tail",
        resource_type=ResourceType.SSH_HOST,
        risk=RiskLevel.LOW,
        description=(
            "Show the last journal lines (at most 500) of a service listed in the host's "
            "allowed_services."
        ),
        input_model=LogsParams,
    )
    async def logs_tail(self, ctx: ActionContext, params: LogsParams) -> ActionResult:
        async def body() -> ActionResult:
            command = logs_tail_command(params.service, params.lines, host_attributes(ctx))
            output = await self._run_one(ctx, command)
            return self._result(
                ctx, output, output.exit_code == 0, service=params.service, lines=params.lines
            )

        return await run_safely(ctx, "ssh.logs.tail", body)
