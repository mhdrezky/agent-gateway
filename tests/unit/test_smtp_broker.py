"""SMTP broker, ported from the agentgate doorman mail connector tests."""

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, ClassVar

import pytest
from pydantic import ValidationError

from agent_gateway.brokers.smtp import SmtpBroker
from agent_gateway.brokers.smtp.models import MailSendParams, SmtpServerAttributes
from agent_gateway.brokers.smtp.sender import Login, SendOutcome
from agent_gateway.config import BrokerSettings, Settings, SmtpBrokerSettings
from agent_gateway.modules.action_registry.models import RiskLevel
from agent_gateway.modules.action_registry.registry import InMemoryActionRegistry
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.resources.models import ResourceType
from agent_gateway.runtime import default_brokers
from tests.fakes.registry import FakeActionRegistry
from tests.unit.broker_support import make_ctx

PASSWORD = "app-password-hunter2"
LOGIN = SecretPayload(CredentialType.BASIC_AUTH, PASSWORD, {"username": "agent@example.test"})


def smtp_attributes(**overrides: Any) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "host": "mail.test",
        "port": 1025,
        "security": "none",
        "from_address": "agentgate@example.test",
        "allowed_domains": ["example.test"],
    }
    attrs.update(overrides)
    return attrs


def _mail(**changes: Any) -> dict[str, Any]:
    return {"to": ["buyer@example.test"], "subject": "Open POs", "body": "Two.", **changes}


def _ctx(credential: SecretPayload | None = None, **overrides: Any) -> Any:
    return make_ctx(ResourceType.SMTP_SERVER, smtp_attributes(**overrides), credential)


class _FakeSmtp:
    """Records what the sender does instead of opening a connection."""

    calls: ClassVar[list[str]] = []
    messages: ClassVar[list[EmailMessage]] = []
    extensions: ClassVar[set[str]] = {"starttls", "auth"}
    refused: ClassVar[dict[str, tuple[int, bytes]]] = {}
    error: ClassVar[Exception | None] = None

    def __init__(self, host: str, port: int, **kwargs: Any) -> None:
        self.calls.append(f"connect {type(self).__name__} {host}:{port}")
        assert kwargs["timeout"] == 15
        if type(self).__name__ == "SMTP_SSL":
            assert isinstance(kwargs["context"], ssl.SSLContext)

    def __enter__(self) -> "_FakeSmtp":
        return self

    def __exit__(self, *_: object) -> None:
        self.calls.append("quit")

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def has_extn(self, name: str) -> bool:
        return name in self.extensions

    def starttls(self, *, context: ssl.SSLContext) -> None:
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname
        self.calls.append("starttls")

    def login(self, user: str, _password: str) -> None:
        self.calls.append(f"login {user}")
        if self.error is not None:
            raise self.error

    def send_message(self, message: EmailMessage) -> dict[str, tuple[int, bytes]]:
        if self.error is not None:
            raise self.error
        self.calls.append(f"send {message['To']}")
        self.messages.append(message)
        return dict(self.refused)


class SMTP(_FakeSmtp):
    pass


class SMTP_SSL(_FakeSmtp):  # noqa: N801 - mirrors smtplib.SMTP_SSL
    pass


@pytest.fixture
def smtp_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    monkeypatch.setattr(_FakeSmtp, "calls", [])
    monkeypatch.setattr(_FakeSmtp, "messages", [])
    monkeypatch.setattr(_FakeSmtp, "extensions", {"starttls", "auth"})
    monkeypatch.setattr(_FakeSmtp, "refused", {})
    monkeypatch.setattr(_FakeSmtp, "error", None)
    monkeypatch.setattr(smtplib, "SMTP", SMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", SMTP_SSL)
    return _FakeSmtp.calls


def test_registers_mail_send_as_medium() -> None:
    registry = InMemoryActionRegistry()
    SmtpBroker().register(registry)
    [registered] = registry.all()
    assert registered.definition.id == "mail.send"
    assert registered.definition.broker == "mail"
    assert registered.definition.risk is RiskLevel.MEDIUM
    assert registered.definition.resource_type is ResourceType.SMTP_SERVER
    assert not registered.definition.privileged
    assert not registered.definition.read_only


def test_default_brokers_include_smtp_only_when_enabled() -> None:
    assert "smtp" not in {b.name for b in default_brokers(Settings())}
    enabled = Settings(brokers=BrokerSettings(smtp=SmtpBrokerSettings(enabled=True)))
    assert "smtp" in {b.name for b in default_brokers(enabled)}


def test_resource_attribute_schema() -> None:
    model = SmtpBroker().resource_attribute_models()[ResourceType.SMTP_SERVER]
    attrs = model.model_validate(smtp_attributes(allowed_domains=[" .Example.TEST "]))
    assert isinstance(attrs, SmtpServerAttributes)
    assert attrs.allowed_domains == ("example.test",)
    defaults = {k: v for k, v in smtp_attributes().items() if k not in ("security", "port")}
    assert SmtpServerAttributes.model_validate(defaults).security == "starttls"
    assert SmtpServerAttributes.model_validate(defaults).port == 587
    refused: list[dict[str, Any]] = [
        {"security": "tls"},
        {"allowed_domains": []},
        {"from_address": "Agent <agentgate@example.test>"},
        {"from_address": "agentgate@example.test\r\nBcc: x@evil.com"},
        {"max_recipients": 51},
        {"password": "x"},
    ]
    for bad in refused:
        with pytest.raises(ValidationError):
            model.model_validate(smtp_attributes(**bad))


def test_params_normalize() -> None:
    params = MailSendParams.model_validate(
        _mail(to=" ops@north.example.test ", subject=" Open POs \n", body=" Two.\n")
    )
    assert params.to == ("ops@north.example.test",)
    assert params.subject == "Open POs"
    assert params.body == "Two."


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"to": ["not-an-address"]}, "to"),
        ({"to": ["Buyer <buyer@example.test>"]}, "to"),
        ({"to": ["a@example.test, b@evil.com"]}, "to"),
        ({"to": ["buyer@example.test\r\nBcc: x@evil.com"]}, "to"),
        ({"to": []}, "to"),
        ({"to": [" "]}, "to"),
        ({"to": [f"u{i}@example.test" for i in range(51)]}, "to"),
        ({"subject": "two\nlines"}, "subject"),
        ({"subject": "two\rlines"}, "subject"),
        ({"subject": "Hi\r\nBcc: x@evil.com"}, "subject"),
        ({"subject": "x" * 201}, "subject"),
        ({"subject": ""}, "subject"),
        ({"body": ""}, "body"),
        ({"body": "x" * 20_001}, "body"),
        ({"cc": ["buyer@example.test"]}, "cc"),
    ],
)
def test_params_refuse(changes: dict[str, Any], field: str) -> None:
    with pytest.raises(ValidationError, match=field):
        MailSendParams.model_validate(_mail(**changes))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"to": ["someone@elsewhere.com"]}, "not allowed"),
        ({"to": ["buyer@example.test.evil.com"]}, "not allowed"),
        ({"to": ["buyer@notexample.test"]}, "not allowed"),
        ({"to": ["buyer@example.test", "leak@elsewhere.com"]}, "not allowed"),
        ({"to": [f"u{i}@example.test" for i in range(11)]}, "give 1 to 10 recipients"),
    ],
)
async def test_send_refuses_before_connecting(
    smtp_calls: list[str], changes: dict[str, Any], message: str
) -> None:
    params = MailSendParams.model_validate(_mail(**changes))
    result = await SmtpBroker().send(_ctx(), params)
    assert not result.ok
    assert result.error is not None
    assert message in result.error
    assert smtp_calls == []


async def test_max_recipients_per_resource(smtp_calls: list[str]) -> None:
    params = MailSendParams.model_validate(_mail(to=["a@example.test", "b@example.test"]))
    result = await SmtpBroker().send(_ctx(max_recipients=1), params)
    assert result.error == "give 1 to 1 recipients"
    assert smtp_calls == []


@pytest.mark.parametrize(
    ("security", "port", "expected"),
    [
        ("none", 1025, ["connect SMTP mail.test:1025", "send buyer@example.test", "quit"]),
        (
            "starttls",
            587,
            [
                "connect SMTP mail.test:587",
                "ehlo",
                "starttls",
                "ehlo",
                "login agent@example.test",
                "send buyer@example.test",
                "quit",
            ],
        ),
        (
            "ssl",
            465,
            [
                "connect SMTP_SSL mail.test:465",
                "login agent@example.test",
                "send buyer@example.test",
                "quit",
            ],
        ),
    ],
)
async def test_security_modes(
    smtp_calls: list[str], security: str, port: int, expected: list[str]
) -> None:
    credential = LOGIN if security != "none" else None
    ctx = _ctx(credential, security=security, port=port)
    result = await SmtpBroker().send(ctx, MailSendParams.model_validate(_mail()))
    assert result.ok, result.error
    assert result.data["sent_to"] == ["buyer@example.test"]
    assert result.data["refused"] == []
    assert result.data["message_id"].endswith("@example.test>")
    assert smtp_calls == expected


async def test_message_headers(smtp_calls: list[str]) -> None:
    params = MailSendParams.model_validate(
        _mail(to=["a@example.test", "b@ops.example.test"], body="Line one.\nLine two.")
    )
    result = await SmtpBroker().send(_ctx(), params)
    assert result.ok
    [message] = _FakeSmtp.messages
    assert message["From"] == "agentgate@example.test"
    assert message["To"] == "a@example.test, b@ops.example.test"
    assert message["Subject"] == "Open POs"
    assert message["Date"]
    assert message["Message-ID"] == result.data["message_id"]
    assert message.get_content_type() == "text/plain"
    assert message.get_content() == "Line one.\nLine two.\n"


async def test_starttls_not_offered_fails_closed(smtp_calls: list[str]) -> None:
    _FakeSmtp.extensions = {"auth"}
    ctx = _ctx(LOGIN, security="starttls", port=587)
    result = await SmtpBroker().send(ctx, MailSendParams.model_validate(_mail()))
    assert not result.ok
    assert result.error == "smtp server does not offer STARTTLS"
    assert smtp_calls == ["connect SMTP mail.test:587", "ehlo", "quit"]


async def test_sign_in_without_encryption_is_refused(smtp_calls: list[str]) -> None:
    result = await SmtpBroker().send(_ctx(LOGIN), MailSendParams.model_validate(_mail()))
    assert result.error == "smtp sign-in needs security starttls or ssl"
    assert smtp_calls == []


@pytest.mark.parametrize(
    "credential",
    [
        SecretPayload(CredentialType.API_TOKEN, PASSWORD),
        SecretPayload(CredentialType.BASIC_AUTH, PASSWORD),
    ],
)
async def test_credential_must_be_basic_auth_with_username(
    smtp_calls: list[str], credential: SecretPayload
) -> None:
    ctx = _ctx(credential, security="ssl", port=465)
    result = await SmtpBroker().send(ctx, MailSendParams.model_validate(_mail()))
    assert result.error == "smtp credential must be basic_auth with a username field"
    assert smtp_calls == []


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (
            smtplib.SMTPAuthenticationError(535, f"bad password {PASSWORD}".encode()),
            "smtp authentication failed",
        ),
        (
            smtplib.SMTPRecipientsRefused({"buyer@example.test": (550, b"no such user")}),
            "smtp server refused every recipient",
        ),
        (
            smtplib.SMTPSenderRefused(553, b"relay denied", "agentgate@example.test"),
            "smtp server refused the sender",
        ),
        (smtplib.SMTPDataError(554, b"spam"), "smtp server refused the message"),
        (smtplib.SMTPNotSupportedError("no AUTH"), "smtp server does not support"),
        (ssl.SSLCertVerificationError("certificate verify failed"), "smtp TLS handshake failed"),
        (TimeoutError("timed out"), "smtp server timed out"),
        (ConnectionRefusedError(f"refused {PASSWORD}"), "smtp connection failed"),
    ],
)
async def test_errors_are_safe(smtp_calls: list[str], error: Exception, message: str) -> None:
    _FakeSmtp.error = error
    ctx = _ctx(LOGIN, security="ssl", port=465)
    result = await SmtpBroker().send(ctx, MailSendParams.model_validate(_mail()))
    assert not result.ok
    assert result.error is not None
    assert result.error.startswith(message)
    assert PASSWORD not in result.model_dump_json()


async def test_partly_refused_is_still_sent(smtp_calls: list[str]) -> None:
    _FakeSmtp.refused = {"b@example.test": (550, b"no such user")}
    params = MailSendParams.model_validate(_mail(to=["a@example.test", "b@example.test"]))
    result = await SmtpBroker().send(_ctx(), params)
    assert result.ok
    assert result.data["sent_to"] == ["a@example.test"]
    assert result.data["refused"] == ["b@example.test"]


async def test_unexpected_error_is_wrapped(caplog: pytest.LogCaptureFixture) -> None:
    class Exploding:
        async def send(
            self, attrs: SmtpServerAttributes, login: Login | None, params: MailSendParams
        ) -> SendOutcome:
            raise RuntimeError(f"internal detail {login.password if login else ''}")

    ctx = _ctx(LOGIN, security="ssl", port=465)
    result = await SmtpBroker(Exploding()).send(ctx, MailSendParams.model_validate(_mail()))
    assert result.error == "mail.send failed"
    assert PASSWORD not in result.model_dump_json()
    assert "internal detail" in caplog.text


async def test_timeout() -> None:
    class Slow:
        async def send(self, *args: Any) -> SendOutcome:
            await asyncio.sleep(5)
            raise AssertionError("unreachable")

    ctx = make_ctx(ResourceType.SMTP_SERVER, smtp_attributes(), timeout_seconds=1)
    params = MailSendParams.model_validate(_mail())
    result = await asyncio.wait_for(SmtpBroker(Slow()).send(ctx, params), timeout=3)
    assert result.error == "mail.send timed out"


async def test_invalid_resource_attributes() -> None:
    ctx = make_ctx(ResourceType.SMTP_SERVER, {"host": "mail.test"})
    result = await SmtpBroker().send(ctx, MailSendParams.model_validate(_mail()))
    assert result.error == "smtp_server resource attributes are invalid"


async def test_wrong_resource_type() -> None:
    ctx = make_ctx(ResourceType.SSH_HOST, smtp_attributes())
    result = await SmtpBroker().send(ctx, MailSendParams.model_validate(_mail()))
    assert result.error == "resource is not an smtp_server"


def test_works_with_fake_registry() -> None:
    registry = FakeActionRegistry()
    SmtpBroker().register(registry)
    params = registry.validate_params("mail.send", _mail(to="buyer@example.test"))
    assert params == MailSendParams(to=("buyer@example.test",), subject="Open POs", body="Two.")
