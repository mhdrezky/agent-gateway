"""SQL resource attributes and action params (SPEC §11.4)."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

HOST_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$"
DBNAME_PATTERN = r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$"
USERNAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_.@-]{0,62}$"
# Unquoted PostgreSQL identifiers fold to lower case; the gate compares in lower case too.
IDENTIFIER_PATTERN = r"^[a-z_][a-z0-9_$]{0,62}$"

MAX_SQL_LENGTH = 20000
DEFAULT_ROW_CAP = 200
MAX_ROW_CAP = 10000
# Kept below the 60 s action timeout so the database gives up before the gateway does.
MAX_STATEMENT_TIMEOUT_MS = 50000

Identifier = Annotated[str, StringConstraints(pattern=IDENTIFIER_PATTERN)]
SslMode = Literal["disable", "allow", "prefer", "require", "verify-ca", "verify-full"]


class SqlDatabaseAttributes(BaseModel):
    """Schema of ``Resource.attributes`` for ``sql_database`` resources (SPEC §11.4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # T-SQL comes later, with its own gate dialect and driver.
    engine: Literal["postgres"] = "postgres"
    host: Annotated[str, StringConstraints(pattern=HOST_PATTERN)]
    port: int = Field(default=5432, ge=1, le=65535)
    dbname: Annotated[str, StringConstraints(pattern=DBNAME_PATTERN)]
    username: Annotated[str, StringConstraints(pattern=USERNAME_PATTERN)]
    # Every table in a query is pinned to this schema.
    schema_name: Identifier = "public"
    # The tables an agent may query. May start empty: an admin picks them from the
    # resource's catalog (`agw sync`, SPEC §11.6) and an empty set refuses every query.
    allowed_tables: tuple[Identifier, ...] = ()
    row_cap: int = Field(default=DEFAULT_ROW_CAP, ge=1, le=MAX_ROW_CAP)
    statement_timeout_ms: int = Field(default=15000, ge=100, le=MAX_STATEMENT_TIMEOUT_MS)
    connect_timeout_seconds: int = Field(default=5, ge=1, le=10)
    sslmode: SslMode = "prefer"


class QueryParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sql: str = Field(min_length=1, max_length=MAX_SQL_LENGTH)
