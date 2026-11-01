"""Elevation windows (SPEC §13a).

A window only removes the per-command approval for a privileged action. It never grants
anything by itself: the role, the policy, the resource's own switch (``allow_sudo``), and
the server's sudoers still have to allow the command, and any of them can still stop it.
"""

from datetime import timedelta

from agent_gateway.common.clock import Clock
from agent_gateway.common.errors import ConflictError, NotFoundError
from agent_gateway.common.ids import IdPrefix, new_id
from agent_gateway.modules.audit.models import Actor, AuditEventType, AuditRecord
from agent_gateway.modules.audit.ports import AuditLog
from agent_gateway.modules.elevation.models import Elevation
from agent_gateway.modules.storage.ports import Collection, ItemNotFoundError

MAX_MINUTES = 240


class ElevationService:
    def __init__(self, elevations: Collection[Elevation], audit: AuditLog, clock: Clock) -> None:
        self._elevations = elevations
        self._audit = audit
        self._clock = clock

    async def active_for(self, agent_id: str, resource_id: str, action: str) -> Elevation | None:
        now = self._clock.now()
        matches = [
            e
            for e in await self._elevations.all()
            if e.agent_id == agent_id
            and e.resource_id == resource_id
            and e.action == action
            and e.active(now)
        ]
        return max(matches, key=lambda e: e.expires_at, default=None)

    async def list(self, *, active_only: bool = True) -> list[Elevation]:
        now = self._clock.now()
        items = await self._elevations.all()
        if active_only:
            items = [e for e in items if e.active(now)]
        return sorted(items, key=lambda e: e.granted_at, reverse=True)

    async def grant(
        self,
        *,
        agent_id: str,
        resource_id: str,
        action: str,
        minutes: int,
        actor: Actor,
        approval_id: str | None = None,
    ) -> Elevation:
        if not 0 < minutes <= MAX_MINUTES:
            raise ValueError(f"minutes must be between 1 and {MAX_MINUTES}")
        now = self._clock.now()
        elevation = Elevation(
            id=new_id(IdPrefix.ELEVATION),
            agent_id=agent_id,
            resource_id=resource_id,
            action=action,
            granted_by=f"{actor.type.value}:{actor.id}",
            granted_at=now,
            expires_at=now + timedelta(minutes=minutes),
            approval_id=approval_id,
        )
        # Audited before it is stored: an unavailable audit log means no window (fail closed).
        await self._audit.append(
            AuditRecord(
                event=AuditEventType.ELEVATION_GRANTED,
                actor=actor,
                action=action,
                resource_id=resource_id,
                details={
                    "elevation_id": elevation.id,
                    "agent_id": agent_id,
                    "minutes": minutes,
                    "expires_at": elevation.expires_at.isoformat(),
                    "approval_id": approval_id,
                },
            )
        )
        await self._elevations.put(elevation)
        return elevation

    async def revoke(self, elevation_id: str, actor: Actor) -> Elevation:
        current = await self._elevations.get(elevation_id)
        if current is None:
            raise NotFoundError(f"elevation {elevation_id} not found")
        if current.revoked_at is not None:
            raise ConflictError(f"elevation {elevation_id} is already revoked")
        now = self._clock.now()
        await self._audit.append(
            AuditRecord(
                event=AuditEventType.ELEVATION_REVOKED,
                actor=actor,
                action=current.action,
                resource_id=current.resource_id,
                details={"elevation_id": elevation_id, "agent_id": current.agent_id},
            )
        )
        try:
            return await self._elevations.update(
                elevation_id,
                lambda e: e.model_copy(
                    update={"revoked_at": now, "revoked_by": f"{actor.type.value}:{actor.id}"}
                ),
            )
        except ItemNotFoundError:
            raise NotFoundError(f"elevation {elevation_id} not found") from None
