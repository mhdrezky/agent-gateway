"""Token string format and hashing (SPEC §9.1, §9.2).

A token is ``agw_<token_id>_<secret>`` with ``token_id = tok_<ULID>`` and ``secret`` 32
random bytes in unpadded base64url (which may itself contain ``_``).
"""

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field

from agent_gateway.common.ids import IdPrefix, has_prefix
from agent_gateway.modules.identity.models import TOKEN_SCHEME

SECRET_BYTES = 32
# 32 bytes of unpadded base64url is always 43 characters.
SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
# Characters of the plaintext kept as the display ``prefix``, e.g. ``agw_tok_01JB8``.
DISPLAY_PREFIX_LENGTH = 13
# Upper bound on what is parsed at all; real tokens are 79 characters.
MAX_TOKEN_LENGTH = 128


@dataclass(frozen=True)
class ParsedToken:
    token_id: str
    secret: str = field(repr=False)


def new_secret() -> str:
    return secrets.token_urlsafe(SECRET_BYTES)


def format_token(token_id: str, secret: str) -> str:
    return f"{TOKEN_SCHEME}_{token_id}_{secret}"


def display_prefix(token_id: str) -> str:
    return f"{TOKEN_SCHEME}_{token_id}"[:DISPLAY_PREFIX_LENGTH]


def parse_token(raw: str) -> ParsedToken | None:
    """Split a raw token into id and secret, or ``None`` if it is malformed in any way."""
    if len(raw) > MAX_TOKEN_LENGTH:
        return None
    parts = raw.split("_", 3)
    if len(parts) != 4:
        return None
    scheme, prefix, ulid, secret = parts
    token_id = f"{prefix}_{ulid}"
    if scheme != TOKEN_SCHEME or not has_prefix(token_id, IdPrefix.TOKEN):
        return None
    if SECRET_PATTERN.fullmatch(secret) is None:
        return None
    return ParsedToken(token_id=token_id, secret=secret)


def hash_secret(key: bytes, secret: str) -> str:
    """``hex(HMAC-SHA256(k_token, secret))`` as stored in ``Token.hash``."""
    return hmac.new(key, secret.encode("ascii"), hashlib.sha256).hexdigest()


def secret_matches(key: bytes, secret: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(key, secret), stored_hash)
