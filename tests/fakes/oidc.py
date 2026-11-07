"""A fake OIDC provider: an RSA signing key, its JWKS, and access tokens it signs."""

import json
import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_gateway.config import OidcSettings

ISSUER = "http://idp.test/realms/dev"
AUDIENCE = "agentgate"


def oidc_settings(**overrides: Any) -> OidcSettings:
    values: dict[str, Any] = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "jwks_url": "http://idp.internal/certs",
    }
    return OidcSettings(**{**values, **overrides})


class FakeIdp:
    """Signs tokens with ``kid``; serves its JWKS through ``fetch`` (a ``JwksSource``)."""

    def __init__(self, kid: str = "key-1") -> None:
        self.fetches = 0
        self._keys: dict[str, rsa.RSAPrivateKey] = {}
        self.kid = kid
        self.rotate(kid)

    def rotate(self, kid: str) -> None:
        self._keys[kid] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = kid

    async def fetch(self) -> dict[str, Any]:
        self.fetches += 1
        keys = []
        for kid, private in self._keys.items():
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
            keys.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": keys}

    def token(
        self,
        subject: str = "user-1",
        groups: list[str] | None = None,
        *,
        kid: str | None = None,
        algorithm: str = "RS256",
        key: Any = None,
        **claims: Any,
    ) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": subject,
            "iat": now,
            "exp": now + 300,
            "groups": groups or [],
            **claims,
        }
        payload = {k: v for k, v in payload.items() if v is not None}
        signing = key if key is not None else self._keys[kid or self.kid]
        return jwt.encode(payload, signing, algorithm=algorithm, headers={"kid": kid or self.kid})
