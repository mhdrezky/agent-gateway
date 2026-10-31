"""Canonical JSON encoding, used for digests and the audit hash chain."""

import hashlib
import json
from typing import Any

from pydantic import BaseModel


def canonical_json(value: Any) -> bytes:
    """Encode with sorted keys, no whitespace, UTF-8. Models are dumped in JSON mode first."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sha256_digest(value: Any) -> str:
    """Digest in the ``sha256:<hex>`` form used for ``params_digest``."""
    return f"sha256:{sha256_hex(value)}"
