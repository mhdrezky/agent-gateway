"""Prefixed ULID identifiers, e.g. ``agt_01JB8XYZ...``."""

from enum import StrEnum

from ulid import ULID

ULID_LENGTH = 26


class IdPrefix(StrEnum):
    AGENT = "agt"
    TOKEN = "tok"
    RESOURCE = "res"
    CREDENTIAL = "cred"
    POLICY = "pol"
    EXECUTION = "exe"
    APPROVAL = "apr"
    ELEVATION = "elv"


def new_id(prefix: IdPrefix) -> str:
    return f"{prefix}_{ULID()}"


def has_prefix(value: str, prefix: IdPrefix) -> bool:
    head, sep, tail = value.partition("_")
    return sep == "_" and head == prefix and len(tail) == ULID_LENGTH
