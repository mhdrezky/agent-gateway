"""SMTP broker against real Mailpit containers. See README.md in this folder."""

import asyncio
import os
import uuid
from typing import Any

import httpx
import pytest

from agent_gateway.brokers.smtp import SmtpBroker
from agent_gateway.brokers.smtp.models import MailSendParams
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.resources.models import ResourceType
from tests.unit.broker_support import make_ctx

pytestmark = pytest.mark.broker

REQUIRED = ["AGW_TEST_SMTP_HOST", "AGW_TEST_SMTP_PORT", "AGW_TEST_MAILPIT_API"]
SENDER = "agentgate@example.test"


@pytest.fixture
def env() -> dict[str, str]:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        pytest.skip(f"missing {', '.join(missing)}")
    return {name: os.environ[name] for name in REQUIRED}


def _ctx(env: dict[str, str], credential: SecretPayload | None = None, **overrides: Any) -> Any:
    attributes: dict[str, Any] = {
        "host": env["AGW_TEST_SMTP_HOST"],
        "port": int(env["AGW_TEST_SMTP_PORT"]),
        "security": "none",
        "from_address": SENDER,
        "allowed_domains": ["example.test"],
        "timeout_seconds": 5,
        **overrides,
    }
    return make_ctx(ResourceType.SMTP_SERVER, attributes, credential)


def _params(to: list[str], subject: str, body: str = "Two open POs.") -> MailSendParams:
    return MailSendParams(to=tuple(to), subject=subject, body=body)


async def _search(env: dict[str, str], subject: str, *, expect: int) -> list[dict[str, Any]]:
    """Messages in Mailpit with this subject, waiting briefly for ``expect`` of them."""
    async with httpx.AsyncClient(base_url=env["AGW_TEST_MAILPIT_API"], timeout=5) as client:
        for _ in range(20):
            response = await client.get("/api/v1/search", params={"query": f'subject:"{subject}"'})
            response.raise_for_status()
            messages: list[dict[str, Any]] = response.json()["messages"]
            if len(messages) >= expect > 0:
                return messages
            await asyncio.sleep(0.25)
        return messages


async def _text(env: dict[str, str], message_id: str) -> str:
    async with httpx.AsyncClient(base_url=env["AGW_TEST_MAILPIT_API"], timeout=5) as client:
        response = await client.get(f"/api/v1/message/{message_id}")
        response.raise_for_status()
        text: str = response.json()["Text"]
        return text


def _subject() -> str:
    return f"agw-live-{uuid.uuid4().hex}"


async def test_send_is_delivered(env: dict[str, str]) -> None:
    subject = _subject()
    to = ["buyer@example.test", "ops@north.example.test"]
    result = await SmtpBroker().send(_ctx(env), _params(to, subject, "Line one.\nLine two."))
    assert result.ok, result.error
    assert result.data["sent_to"] == to
    assert result.data["refused"] == []

    [message] = await _search(env, subject, expect=1)
    assert message["From"]["Address"] == SENDER
    assert sorted(r["Address"] for r in message["To"]) == sorted(to)
    assert message["Subject"] == subject
    assert f"<{message['MessageID']}>" == result.data["message_id"]
    assert (await _text(env, message["ID"])).replace("\r\n", "\n").strip() == (
        "Line one.\nLine two."
    )


async def test_disallowed_domain_is_never_sent(env: dict[str, str]) -> None:
    subject = _subject()
    params = _params(["buyer@example.test", "leak@elsewhere.com"], subject)
    result = await SmtpBroker().send(_ctx(env), params)
    assert not result.ok
    assert result.error == "recipient domain of 'leak@elsewhere.com' is not allowed"
    assert await _search(env, subject, expect=0) == []


async def test_starttls_not_offered_fails_closed(env: dict[str, str]) -> None:
    subject = _subject()
    login = SecretPayload(CredentialType.BASIC_AUTH, "pw-hunter2", {"username": "agent"})
    ctx = _ctx(env, login, security="starttls")
    result = await SmtpBroker().send(ctx, _params(["buyer@example.test"], subject))
    assert not result.ok
    assert result.error == "smtp server does not offer STARTTLS"
    assert await _search(env, subject, expect=0) == []


async def test_implicit_tls_against_plain_server_fails(env: dict[str, str]) -> None:
    subject = _subject()
    ctx = _ctx(env, security="ssl")
    result = await SmtpBroker().send(ctx, _params(["buyer@example.test"], subject))
    assert not result.ok
    assert result.error == "smtp TLS handshake failed"
    assert await _search(env, subject, expect=0) == []


async def test_untrusted_starttls_certificate_is_refused(env: dict[str, str]) -> None:
    tls_port = os.environ.get("AGW_TEST_SMTP_TLS_PORT")
    if not tls_port:
        pytest.skip("missing AGW_TEST_SMTP_TLS_PORT")
    login = SecretPayload(CredentialType.BASIC_AUTH, "pw-hunter2", {"username": "agent"})
    ctx = _ctx(env, login, port=int(tls_port), security="starttls")
    result = await SmtpBroker().send(ctx, _params(["buyer@example.test"], _subject()))
    assert not result.ok
    assert result.error == "smtp TLS handshake failed"
    assert "hunter2" not in result.model_dump_json()


async def test_unreachable_server(env: dict[str, str]) -> None:
    ctx = _ctx(env, port=1)
    result = await SmtpBroker().send(ctx, _params(["buyer@example.test"], _subject()))
    assert not result.ok
    assert result.error in {"smtp connection failed", "smtp server timed out"}
