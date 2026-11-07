"""What counts as a correlation id (SPEC §12)."""

import pytest

from agent_gateway.apps.api_server.correlation import parse_correlation, resolve_correlation
from agent_gateway.common.errors import InvalidParamsError


def test_absent_and_present() -> None:
    assert parse_correlation(None) is None
    assert parse_correlation("conv-1:2") == "conv-1:2"


@pytest.mark.parametrize("value", ["", "  conv", "conv  ", "bad\nid", "x" * 201, 5])
def test_rejected(value: object) -> None:
    with pytest.raises(InvalidParamsError):
        parse_correlation(value)


def test_meta_and_header_must_agree() -> None:
    assert resolve_correlation("conv-1:2", {"agentgate/correlation_id": "conv-1:2"}) == "conv-1:2"
    assert resolve_correlation(None, {"agentgate/correlation_id": "conv-1:2"}) == "conv-1:2"
    assert resolve_correlation("conv-1:2", None) == "conv-1:2"
    with pytest.raises(InvalidParamsError):
        resolve_correlation("one", {"agentgate/correlation_id": "two"})
