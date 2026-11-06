"""Admin UI sessions: an admin token is exchanged once for an opaque session cookie.

The token never reaches the browser after login: the cookie holds a random session id,
sessions live only in this process (one uvicorn worker), and every request re-checks that
the admin token behind the session is still valid, so revoking it ends the session.
"""

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from agent_gateway.common.clock import Clock
from agent_gateway.modules.identity.models import Principal

COOKIE_NAME = "agw_admin"
COOKIE_PATH = "/admin"
SESSION_TTL = timedelta(hours=8)
MAX_SESSIONS = 100


@dataclass(slots=True)
class Session:
    id: str
    principal: Principal
    csrf: str
    expires_at: datetime
    flashes: list[tuple[str, str]] = field(default_factory=list)

    def flash(self, kind: str, message: str) -> None:
        self.flashes.append((kind, message))

    def pop_flashes(self) -> list[tuple[str, str]]:
        flashes, self.flashes = self.flashes, []
        return flashes


class SessionStore:
    def __init__(self, clock: Clock, ttl: timedelta = SESSION_TTL) -> None:
        self._clock = clock
        self._ttl = ttl
        self._sessions: dict[str, Session] = {}

    def create(self, principal: Principal) -> Session:
        self._prune()
        if len(self._sessions) >= MAX_SESSIONS:
            oldest = min(self._sessions.values(), key=lambda s: s.expires_at)
            del self._sessions[oldest.id]
        session = Session(
            id=secrets.token_urlsafe(32),
            principal=principal,
            csrf=secrets.token_urlsafe(32),
            expires_at=self._clock.now() + self._ttl,
        )
        self._sessions[session.id] = session
        return session

    def get(self, session_id: str | None) -> Session | None:
        if not session_id:
            return None
        session = self._sessions.get(session_id)
        if session is None:
            return None
        if session.expires_at <= self._clock.now():
            del self._sessions[session_id]
            return None
        return session

    def end(self, session_id: str | None) -> None:
        if session_id:
            self._sessions.pop(session_id, None)

    def _prune(self) -> None:
        now = self._clock.now()
        for sid in [sid for sid, s in self._sessions.items() if s.expires_at <= now]:
            del self._sessions[sid]


def csrf_matches(session: Session, submitted: str | None) -> bool:
    return submitted is not None and secrets.compare_digest(session.csrf, submitted)
