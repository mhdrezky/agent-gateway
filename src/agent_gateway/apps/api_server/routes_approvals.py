"""Approvals the requesting user decides (SPEC §13b). REST only, never an MCP tool."""

from fastapi import APIRouter

from agent_gateway.apps.api_server.deps import GatewayDep, PrincipalDep
from agent_gateway.apps.api_server.mcp_actions import tool_name
from agent_gateway.apps.api_server.schemas import ApprovalView, ApprovalViewStatus, DecideBody
from agent_gateway.modules.approvals.models import Approval, ApprovalStatus
from agent_gateway.modules.execution.models import Execution, ExecutionStatus

router = APIRouter(prefix="/v1/approvals")


@router.get("/mine")
async def my_approvals(
    gateway: GatewayDep, principal: PrincipalDep, status: ApprovalViewStatus | None = None
) -> list[ApprovalView]:
    views = [approval_view(a, e) for a, e in await gateway.engine.my_approvals(principal)]
    return [v for v in views if status is None or v.status == status]


@router.post("/{approval_id}/decide")
async def decide(
    approval_id: str, body: DecideBody, gateway: GatewayDep, principal: PrincipalDep
) -> ApprovalView:
    approval, execution = await gateway.engine.decide_as_requester(
        principal, approval_id, confirm=body.decision == "confirm"
    )
    return approval_view(approval, execution)


def approval_view(approval: Approval, execution: Execution) -> ApprovalView:
    status = view_status(approval, execution)
    result = execution.result
    return ApprovalView(
        id=approval.id,
        execution_id=execution.id,
        tool=tool_name(execution.action),
        summary=f"{execution.action} on {execution.resource_id}",
        params=execution.params,
        status=status,
        created_at=approval.requested_at,
        expires_at=approval.expires_at,
        decided_at=approval.decided_at,
        result=result.data if result is not None and result.ok else None,
        error=(execution.error or (result.error if result else None))
        if status == "failed"
        else None,
    )


def view_status(approval: Approval, execution: Execution) -> ApprovalViewStatus:
    match approval.status:
        case ApprovalStatus.PENDING:
            return "pending"
        case ApprovalStatus.EXPIRED:
            return "expired"
        case ApprovalStatus.REJECTED:
            return "denied" if execution.status is ExecutionStatus.DENIED else "rejected"
        case ApprovalStatus.APPROVED:
            return "failed" if execution.status is ExecutionStatus.FAILED else "confirmed"
