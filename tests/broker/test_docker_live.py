"""Docker broker against a real Docker engine. See README.md in this folder."""

import os
from typing import Any

import pytest

from agent_gateway.brokers.docker import DockerBroker
from agent_gateway.brokers.docker.models import ContainerParams, LogsParams, NoParams
from agent_gateway.modules.resources.models import ResourceType
from tests.unit.broker_support import make_ctx

pytestmark = pytest.mark.broker

MANAGED = "agw-test-managed"
UNMANAGED = "agw-test-unmanaged"


@pytest.fixture
def broker() -> DockerBroker:
    endpoint = os.environ.get("AGW_TEST_DOCKER_ENDPOINT")
    if not endpoint:
        pytest.skip("missing AGW_TEST_DOCKER_ENDPOINT")
    return DockerBroker(endpoint)


def _ctx() -> Any:
    return make_ctx(ResourceType.DOCKER_HOST, {})


async def test_list_hides_unmanaged(broker: DockerBroker) -> None:
    result = await broker.container_list(_ctx(), NoParams())
    assert result.ok, result.error
    names = {name for c in result.data["containers"] for name in c["names"]}
    assert MANAGED in names
    assert UNMANAGED not in names


async def test_logs_and_restart_managed(broker: DockerBroker) -> None:
    logs = await broker.container_logs(_ctx(), LogsParams(container=MANAGED, tail=5))
    assert logs.ok, logs.error
    assert "agw-test-tick" in logs.data["stdout"]
    restarted = await broker.container_restart(_ctx(), ContainerParams(container=MANAGED))
    assert restarted.ok, restarted.error


async def test_unmanaged_refused(broker: DockerBroker) -> None:
    result = await broker.container_stop(_ctx(), ContainerParams(container=UNMANAGED))
    assert not result.ok
