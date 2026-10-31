"""Resource model (SPEC §8.5)."""

from collections.abc import Iterable
from enum import StrEnum
from typing import Any

from pydantic import Field

from agent_gateway.common.models import Record

TAG_PATTERN = r"^[a-z0-9][a-z0-9_-]*:[A-Za-z0-9._-]+$"


class ResourceType(StrEnum):
    SSH_HOST = "ssh_host"
    DOCKER_HOST = "docker_host"
    GITHUB_REPO = "github_repo"
    CLOUDFLARE_ZONE = "cloudflare_zone"
    HTTP_ENDPOINT = "http_endpoint"


class Resource(Record):
    """A target of actions. ``attributes`` are validated by the schema its broker registers."""

    type: ResourceType
    name: str = Field(min_length=1, max_length=64)
    tags: tuple[str, ...] = ()
    attributes: dict[str, Any] = Field(default_factory=dict)
    credential_id: str | None = None

    def has_tags(self, required: Iterable[str]) -> bool:
        return set(required) <= set(self.tags)
