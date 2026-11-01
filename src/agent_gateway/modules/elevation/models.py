"""An elevation: one agent may run one privileged action on one resource until it expires."""

from datetime import datetime

from pydantic import AwareDatetime

from agent_gateway.common.models import Record


class Elevation(Record):
    agent_id: str
    resource_id: str
    action: str
    granted_by: str
    granted_at: AwareDatetime
    expires_at: AwareDatetime
    revoked_at: AwareDatetime | None = None
    revoked_by: str | None = None
    # The approval that opened this window, when it was opened by one.
    approval_id: str | None = None

    def active(self, now: datetime) -> bool:
        return self.revoked_at is None and now < self.expires_at
