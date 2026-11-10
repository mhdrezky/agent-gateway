"""``mcp_server`` resource attributes and the params model of a tool (SPEC §11.6)."""

import copy
from typing import Any, ClassVar, Literal

from jsonschema import Draft202012Validator, SchemaError
from jsonschema.validators import validator_for
from pydantic import BaseModel, ConfigDict, Field, model_serializer, model_validator

# Plain http(s) URL of the server's Streamable HTTP endpoint, no credentials in it.
URL_PATTERN = r"^https?://[A-Za-z0-9.\-\[\]:]+(:\d{1,5})?(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?$"
MAX_TOOL_ERRORS = 5


class McpServerAttributes(BaseModel):
    """Schema of ``Resource.attributes`` for ``mcp_server`` resources.

    A credential is optional: an ``api_token`` credential is sent as
    ``Authorization: Bearer <token>`` on every request to the server.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(pattern=URL_PATTERN, max_length=2048)
    transport: Literal["streamable_http"] = "streamable_http"
    # Per request to the server (listing tools, one tool call). The action timeout of
    # 60 s still bounds a whole call.
    timeout_seconds: int = Field(default=30, ge=1, le=55)


def schema_problems(schema: dict[str, Any], arguments: dict[str, Any]) -> list[str]:
    """Where ``arguments`` break the tool's input schema, without echoing any value."""
    try:
        cls = validator_for(schema, default=Draft202012Validator)
        cls.check_schema(schema)
        validator = cls(schema)
        errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.path))
    except SchemaError:
        return ["the tool's input schema is invalid"]
    problems: list[str] = []
    for error in errors[:MAX_TOOL_ERRORS]:
        where = ".".join(str(p) for p in error.path) or "params"
        if error.validator == "required":
            # Names a property from the schema, not from the input.
            problems.append(f"{where}: {error.message}")
        else:
            problems.append(f"{where}: does not satisfy '{error.validator}'")
    return problems


class McpToolParams(BaseModel):
    """Params of one MCP tool: the tool's arguments, checked against its own JSON schema.

    The JSON schema shown to agents is the server's, unchanged. ``model_dump`` gives the
    arguments back as they came, so a stored execution validates again the same way.
    """

    model_config = ConfigDict(extra="forbid")

    tool_schema: ClassVar[dict[str, Any]] = {"type": "object"}
    arguments: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _check(cls, data: Any) -> Any:
        if isinstance(data, McpToolParams):
            return data
        if not isinstance(data, dict):
            raise ValueError("params must be an object")
        arguments: dict[str, Any] = {str(k): v for k, v in data.items()}
        problems = schema_problems(cls.tool_schema, arguments)
        if problems:
            raise ValueError("; ".join(problems))
        return {"arguments": arguments}

    @model_serializer
    def _arguments(self) -> dict[str, Any]:
        return dict(self.arguments)

    @classmethod
    def model_json_schema(cls, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return copy.deepcopy(cls.tool_schema)


def params_model(action_id: str, schema: dict[str, Any]) -> type[McpToolParams]:
    """A params class for one tool, carrying its input schema."""
    name = "Params_" + action_id.replace(".", "_")
    tool_schema = copy.deepcopy(schema) or {"type": "object"}
    return type(name, (McpToolParams,), {"tool_schema": tool_schema, "__module__": __name__})
