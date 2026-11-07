"""SQL broker: one gated, read-only SELECT per call; no writes, no free connection."""

from agent_gateway.brokers.sql.broker import SqlBroker

__all__ = ["SqlBroker"]
