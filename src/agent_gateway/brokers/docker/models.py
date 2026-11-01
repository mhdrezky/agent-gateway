"""Docker resource attributes and action params."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

# Container name or id: no "/", no whitespace, no shell or URL metacharacters.
CONTAINER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"
# unix:///path/to.sock, tcp://host:port, http(s)://host:port
ENDPOINT_PATTERN = r"^(unix:///[A-Za-z0-9_./-]+|(tcp|http|https)://[A-Za-z0-9.:\[\]-]+(:\d+)?/?)$"
API_VERSION_PATTERN = r"^v1\.\d{1,3}$"

MANAGED_LABEL = "agw.managed"
MANAGED_VALUE = "true"
MAX_LOG_TAIL = 500
DEFAULT_LOG_TAIL = 100
STOP_TIMEOUT_SECONDS = 10

ContainerName = Annotated[str, StringConstraints(pattern=CONTAINER_PATTERN)]


class DockerHostAttributes(BaseModel):
    """Schema of ``Resource.attributes`` for ``docker_host`` resources."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # None: use the broker's configured socket (``brokers.docker.socket``).
    endpoint: Annotated[str, StringConstraints(pattern=ENDPOINT_PATTERN)] | None = None
    api_version: Annotated[str, StringConstraints(pattern=API_VERSION_PATTERN)] | None = None
    # Container names the agent may touch besides those labelled agw.managed=true.
    allowed_containers: tuple[ContainerName, ...] = ()


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ContainerParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    container: ContainerName


class LogsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    container: ContainerName
    tail: int = Field(default=DEFAULT_LOG_TAIL, ge=1, le=MAX_LOG_TAIL, strict=True)
