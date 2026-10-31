"""On-disk envelope for JSON collections (SPEC §6.2)."""

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from agent_gateway.common.models import Record


class CollectionFile[R: Record](BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(ge=1)
    updated_at: AwareDatetime
    items: dict[str, R] = Field(default_factory=dict)
