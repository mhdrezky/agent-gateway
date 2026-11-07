"""SMTP resource attributes and ``mail.send`` params (SPEC §11.4).

Every value that becomes a mail header is constrained here, so a model cannot inject
extra headers or recipients through CR/LF, commas, or display names.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

HOST_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$"
DOMAIN_PATTERN = r"^[a-z0-9-]+(\.[a-z0-9-]+)*$"
# A bare local@domain address: no display name, comma, whitespace, or control characters.
ADDRESS_PATTERN = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$"
# One line: no C0 control characters (CR, LF, TAB, NUL, ...) and no DEL.
SUBJECT_PATTERN = r"^[^\x00-\x1f\x7f]+$"

MAX_ADDRESS_LENGTH = 254
MAX_RECIPIENTS_LIMIT = 50
DEFAULT_MAX_RECIPIENTS = 10
MAX_SUBJECT = 200
MAX_BODY = 20_000

Address = Annotated[str, StringConstraints(pattern=ADDRESS_PATTERN, max_length=MAX_ADDRESS_LENGTH)]
Domain = Annotated[str, StringConstraints(pattern=DOMAIN_PATTERN, max_length=MAX_ADDRESS_LENGTH)]
Security = Literal["starttls", "ssl", "none"]


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[1].lower()


class SmtpServerAttributes(BaseModel):
    """Schema of ``Resource.attributes`` for ``smtp_server`` resources (SPEC §8.5)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: Annotated[str, StringConstraints(pattern=HOST_PATTERN)]
    port: int = Field(default=587, ge=1, le=65535)
    # "ssl" is implicit TLS; "none" is only for test servers such as Mailpit.
    security: Security = "starttls"
    from_address: Address
    # A domain also allows its subdomains; nothing outside this list is ever mailed.
    allowed_domains: tuple[Domain, ...] = Field(min_length=1)
    max_recipients: int = Field(
        default=DEFAULT_MAX_RECIPIENTS, ge=1, le=MAX_RECIPIENTS_LIMIT, strict=True
    )
    timeout_seconds: int = Field(default=15, ge=1, le=60, strict=True)

    @field_validator("allowed_domains", mode="before")
    @classmethod
    def _normalize_domains(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(d.strip().lower().lstrip(".") if isinstance(d, str) else d for d in value)
        return value

    def allows(self, address: str) -> bool:
        domain = domain_of(address)
        return any(domain == d or domain.endswith(f".{d}") for d in self.allowed_domains)


class MailSendParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to: tuple[Address, ...] = Field(min_length=1, max_length=MAX_RECIPIENTS_LIMIT)
    subject: Annotated[
        str, StringConstraints(pattern=SUBJECT_PATTERN, min_length=1, max_length=MAX_SUBJECT)
    ]
    body: str = Field(min_length=1, max_length=MAX_BODY)

    @field_validator("to", mode="before")
    @classmethod
    def _recipients(cls, value: object) -> object:
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list | tuple):
            stripped = (r.strip() if isinstance(r, str) else r for r in value)
            return tuple(r for r in stripped if r != "")
        return value

    @field_validator("subject", "body", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value
