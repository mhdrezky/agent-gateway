"""Deliver one checked message over SMTP with the stdlib, in a worker thread."""

import asyncio
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Protocol

from agent_gateway.brokers.output import BrokerError
from agent_gateway.brokers.smtp.models import MailSendParams, SmtpServerAttributes, domain_of
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload

USERNAME_FIELD = "username"


@dataclass(frozen=True, slots=True)
class Login:
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class SendOutcome:
    message_id: str
    refused: tuple[str, ...]


class MailSender(Protocol):
    async def send(
        self, attrs: SmtpServerAttributes, login: Login | None, params: MailSendParams
    ) -> SendOutcome:
        """Send one message; raise ``BrokerError`` with a safe message on failure."""
        ...


def login_from(credential: SecretPayload | None, attrs: SmtpServerAttributes) -> Login | None:
    if credential is None:
        return None
    if credential.type is not CredentialType.BASIC_AUTH or (
        USERNAME_FIELD not in credential.field_names()
    ):
        raise BrokerError("smtp credential must be basic_auth with a username field")
    if attrs.security == "none":
        raise BrokerError("smtp sign-in needs security starttls or ssl")
    return Login(credential.field(USERNAME_FIELD), credential.reveal())


def build_message(attrs: SmtpServerAttributes, params: MailSendParams) -> EmailMessage:
    message = EmailMessage()
    message["From"] = attrs.from_address
    message["To"] = ", ".join(params.to)
    message["Subject"] = params.subject
    message["Date"] = formatdate(usegmt=True)
    message["Message-ID"] = make_msgid(domain=domain_of(attrs.from_address))
    message.set_content(params.body)
    return message


class SmtplibSender:
    async def send(
        self, attrs: SmtpServerAttributes, login: Login | None, params: MailSendParams
    ) -> SendOutcome:
        message = build_message(attrs, params)
        try:
            refused = await asyncio.to_thread(_deliver, attrs, login, message)
        except smtplib.SMTPAuthenticationError as exc:
            raise BrokerError("smtp authentication failed") from exc
        except smtplib.SMTPRecipientsRefused as exc:
            raise BrokerError("smtp server refused every recipient") from exc
        except smtplib.SMTPSenderRefused as exc:
            raise BrokerError("smtp server refused the sender") from exc
        except smtplib.SMTPNotSupportedError as exc:
            raise BrokerError("smtp server does not support a required extension") from exc
        except smtplib.SMTPException as exc:
            raise BrokerError("smtp server refused the message") from exc
        except ssl.SSLError as exc:
            raise BrokerError("smtp TLS handshake failed") from exc
        except TimeoutError as exc:
            raise BrokerError("smtp server timed out") from exc
        except OSError as exc:
            raise BrokerError("smtp connection failed") from exc
        return SendOutcome(str(message["Message-ID"]), tuple(sorted(refused)))


def _deliver(
    attrs: SmtpServerAttributes, login: Login | None, message: EmailMessage
) -> dict[str, tuple[int, bytes]]:
    context = ssl.create_default_context()
    smtp = (
        smtplib.SMTP_SSL(attrs.host, attrs.port, timeout=attrs.timeout_seconds, context=context)
        if attrs.security == "ssl"
        else smtplib.SMTP(attrs.host, attrs.port, timeout=attrs.timeout_seconds)
    )
    with smtp:
        if attrs.security == "starttls":
            smtp.ehlo()
            # Fail closed: never fall back to plain text when STARTTLS was configured.
            if not smtp.has_extn("starttls"):
                raise BrokerError("smtp server does not offer STARTTLS")
            smtp.starttls(context=context)
            smtp.ehlo()
        if login is not None:
            smtp.login(login.username, login.password)
        return smtp.send_message(message)
