"""SMTP broker: send mail to allowed domains only, never read a mailbox."""

from agent_gateway.brokers.smtp.broker import SmtpBroker

__all__ = ["SmtpBroker"]
