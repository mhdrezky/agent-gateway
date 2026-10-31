"""Base classes for every persisted or exchanged model."""

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Immutable model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Record(StrictModel):
    """A model stored in a collection, addressed by ``id``."""

    id: str = Field(min_length=1, max_length=64)
