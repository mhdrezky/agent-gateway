"""Resource registry (SPEC §8.5)."""

import pytest
from pydantic import BaseModel, ConfigDict, Field

from agent_gateway.common.errors import ConflictError, InvalidParamsError, ResourceNotFoundError
from agent_gateway.common.ids import IdPrefix, has_prefix
from agent_gateway.modules.resources.models import Resource, ResourceType
from agent_gateway.modules.resources.ports import ResourceRegistry
from agent_gateway.modules.resources.registry import StoredResourceRegistry
from tests.fakes.storage import InMemoryCollection

CRED_ID = "cred_01JB8ABCDEFGHJKMNPQRSTVWXY"


class SshHostAttributes(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    port: int = Field(default=22, ge=1, le=65535)
    username: str
    allowed_services: list[str] = Field(default_factory=list)


class DockerHostAttributes(BaseModel):
    model_config = ConfigDict(extra="forbid")

    socket: str


SSH = {"host": "192.168.1.10", "username": "deploy"}


@pytest.fixture
def registry() -> StoredResourceRegistry:
    return StoredResourceRegistry(
        InMemoryCollection[Resource](),
        {
            ResourceType.SSH_HOST: SshHostAttributes,
            ResourceType.DOCKER_HOST: DockerHostAttributes,
        },
    )


def test_satisfies_protocol(registry: StoredResourceRegistry) -> None:
    protocol: ResourceRegistry = registry
    assert protocol is not None


async def test_create_validates_and_normalises(registry: StoredResourceRegistry) -> None:
    resource = await registry.create(
        ResourceType.SSH_HOST,
        "homelab-1",
        tags=["env:prod", "site:home", "env:prod"],
        attributes=SSH,
        credential_id=CRED_ID,
    )
    assert has_prefix(resource.id, IdPrefix.RESOURCE)
    assert resource.tags == ("env:prod", "site:home")
    assert resource.attributes == {**SSH, "port": 22, "allowed_services": []}
    assert resource.credential_id == CRED_ID
    assert await registry.get(resource.id) == resource


@pytest.mark.parametrize(
    "attributes",
    [{}, {**SSH, "port": 0}, {**SSH, "command": "rm -rf /"}, {"host": "h", "username": 5}],
)
async def test_invalid_attributes(
    registry: StoredResourceRegistry, attributes: dict[str, object]
) -> None:
    with pytest.raises(InvalidParamsError, match="attributes"):
        await registry.create(ResourceType.SSH_HOST, "h", attributes=attributes)
    assert await registry.list() == []


async def test_error_does_not_echo_values(registry: StoredResourceRegistry) -> None:
    with pytest.raises(InvalidParamsError) as info:
        await registry.create(ResourceType.SSH_HOST, "h", attributes={**SSH, "port": "s3cr3t"})
    assert "s3cr3t" not in info.value.message
    assert "port" in info.value.message


async def test_type_without_schema_is_rejected(registry: StoredResourceRegistry) -> None:
    with pytest.raises(InvalidParamsError, match="github_repo"):
        await registry.create(ResourceType.GITHUB_REPO, "repo", attributes={})


@pytest.mark.parametrize("tags", [["prod"], ["Env:prod"], ["env:"], ["env:a b"], "env:prod"])
async def test_invalid_tags(registry: StoredResourceRegistry, tags: list[str]) -> None:
    with pytest.raises(InvalidParamsError, match="tag"):
        await registry.create(ResourceType.SSH_HOST, "h", tags=tags, attributes=SSH)


async def test_invalid_credential_id(registry: StoredResourceRegistry) -> None:
    with pytest.raises(InvalidParamsError, match="credential_id"):
        await registry.create(ResourceType.SSH_HOST, "h", attributes=SSH, credential_id="res_x")


@pytest.mark.parametrize("name", ["", "x" * 65])
async def test_invalid_name(registry: StoredResourceRegistry, name: str) -> None:
    with pytest.raises(InvalidParamsError, match="name"):
        await registry.create(ResourceType.SSH_HOST, name, attributes=SSH)


async def test_duplicate_name(registry: StoredResourceRegistry) -> None:
    first = await registry.create(ResourceType.SSH_HOST, "h", attributes=SSH)
    with pytest.raises(ConflictError):
        await registry.create(ResourceType.DOCKER_HOST, "h", attributes={"socket": "x"})
    other = await registry.create(ResourceType.SSH_HOST, "other", attributes=SSH)
    with pytest.raises(ConflictError):
        await registry.update(other.id, name="h")
    assert (await registry.update(first.id, name="h")).name == "h"


async def test_list_filters_by_type(registry: StoredResourceRegistry) -> None:
    ssh = await registry.create(ResourceType.SSH_HOST, "a", attributes=SSH)
    docker = await registry.create(ResourceType.DOCKER_HOST, "b", attributes={"socket": "s"})
    assert await registry.list() == sorted([ssh, docker], key=lambda r: r.id)
    assert await registry.list(type=ResourceType.DOCKER_HOST) == [docker]
    assert await registry.list(type=ResourceType.HTTP_ENDPOINT) == []


async def test_update(registry: StoredResourceRegistry) -> None:
    resource = await registry.create(ResourceType.SSH_HOST, "h", tags=["env:dev"], attributes=SSH)
    updated = await registry.update(
        resource.id,
        name="renamed",
        tags=["env:prod"],
        attributes={**SSH, "port": 2222},
        credential_id=CRED_ID,
    )
    assert updated.id == resource.id
    assert updated.type is ResourceType.SSH_HOST
    assert updated.name == "renamed"
    assert updated.tags == ("env:prod",)
    assert updated.attributes["port"] == 2222
    assert updated.credential_id == CRED_ID
    assert await registry.update(resource.id) == updated


async def test_update_revalidates_attributes(registry: StoredResourceRegistry) -> None:
    resource = await registry.create(ResourceType.SSH_HOST, "h", attributes=SSH)
    with pytest.raises(InvalidParamsError, match="attributes"):
        await registry.update(resource.id, attributes={"socket": "x"})
    assert await registry.get(resource.id) == resource


async def test_update_missing(registry: StoredResourceRegistry) -> None:
    with pytest.raises(ResourceNotFoundError):
        await registry.update("res_missing", name="x")


async def test_delete(registry: StoredResourceRegistry) -> None:
    resource = await registry.create(ResourceType.SSH_HOST, "h", attributes=SSH)
    assert await registry.delete(resource.id) is True
    assert await registry.delete(resource.id) is False
    assert await registry.get(resource.id) is None
