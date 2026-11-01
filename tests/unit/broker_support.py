"""Shared builders for broker tests."""

import logging
from typing import Any

from agent_gateway.brokers.base import ActionContext
from agent_gateway.modules.credentials.models import SecretPayload
from agent_gateway.modules.resources.models import Resource, ResourceType

FINGERPRINT = "SHA256:" + "A" * 43


def ssh_attributes(**overrides: Any) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "host": "192.168.1.10",
        "port": 22,
        "username": "deploy",
        "host_key_fingerprint": FINGERPRINT,
        "allowed_services": ["nginx", "app"],
    }
    attrs.update(overrides)
    return attrs


def make_ctx(
    resource_type: ResourceType,
    attributes: dict[str, Any],
    credential: SecretPayload | None = None,
    *,
    output_limit_bytes: int = 65536,
    timeout_seconds: int = 30,
) -> ActionContext:
    return ActionContext(
        execution_id="exe_test",
        agent_id="agt_test",
        resource=Resource(id="res_test", type=resource_type, name="test", attributes=attributes),
        credential=credential,
        timeout_seconds=timeout_seconds,
        output_limit_bytes=output_limit_bytes,
        logger=logging.getLogger("tests.broker"),
    )
