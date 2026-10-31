from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agent_gateway.common.canonical import canonical_json, sha256_digest
from agent_gateway.common.clock import to_rfc3339
from agent_gateway.common.ids import IdPrefix, has_prefix, new_id
from agent_gateway.common.models import Record


def test_new_id_has_prefix_and_is_unique() -> None:
    ids = {new_id(IdPrefix.AGENT) for _ in range(100)}
    assert len(ids) == 100
    assert all(has_prefix(i, IdPrefix.AGENT) for i in ids)
    assert not has_prefix(new_id(IdPrefix.AGENT), IdPrefix.TOKEN)
    assert not has_prefix("agt_short", IdPrefix.AGENT)


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": [1, "é"]}) == canonical_json({"a": [1, "é"], "b": 1})
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_json_rejects_nan() -> None:
    with pytest.raises(ValueError, match="JSON compliant"):
        canonical_json({"x": float("nan")})


def test_sha256_digest_format() -> None:
    digest = sha256_digest({"service": "nginx"})
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64


def test_to_rfc3339() -> None:
    value = datetime(2026, 10, 31, 10, 0, 0, 123456, tzinfo=UTC)
    assert to_rfc3339(value) == "2026-10-31T10:00:00.123Z"
    plus7 = value.astimezone(timezone(timedelta(hours=7)))
    assert to_rfc3339(plus7) == "2026-10-31T10:00:00.123Z"
    with pytest.raises(ValueError, match="naive"):
        to_rfc3339(datetime(2026, 1, 1))  # noqa: DTZ001


def test_records_are_strict_and_frozen() -> None:
    with pytest.raises(ValidationError):
        Record(id="x", unknown=1)  # type: ignore[call-arg]
    record = Record(id="x")
    with pytest.raises(ValidationError):
        record.id = "y"  # type: ignore[misc]
