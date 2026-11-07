"""``X-User-Token`` verification and ``users.json`` matching (SPEC §8.9, §9.4)."""

import time
from datetime import timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from agent_gateway.common.errors import ActionNotAllowedError, AuthenticationError
from agent_gateway.modules.identity.models import (
    Principal,
    TokenKind,
    User,
    UserMatch,
)
from agent_gateway.modules.identity.users import (
    USER_AUTH_FAILED_MESSAGE,
    UserDirectory,
    build_user_directory,
)
from tests.fakes.clock import FixedClock
from tests.fakes.oidc import FakeIdp, oidc_settings
from tests.fakes.storage import InMemoryCollection

AGENT = Principal(kind=TokenKind.AGENT, token_id="tok_x", agent_id="agt_x", roles=("app",))


class Env:
    def __init__(self, **settings: Any) -> None:
        self.idp = FakeIdp()
        self.clock = FixedClock()
        self.users = InMemoryCollection[User]()
        self.directory = build_user_directory(
            self.users, oidc_settings(**settings), source=self.idp, clock=self.clock
        )

    async def add(self, user_id: str, roles: tuple[str, ...], **match: str) -> None:
        await self.users.put(User(id=user_id, match=UserMatch(**match), roles=roles))


@pytest.fixture
def env() -> Env:
    return Env()


async def assert_refused(directory: UserDirectory, raw: str) -> None:
    with pytest.raises(AuthenticationError) as info:
        await directory.resolve(raw)
    assert info.value.message == USER_AUTH_FAILED_MESSAGE
    assert info.value.__cause__ is None


async def test_roles_are_the_union_of_every_match(env: Env) -> None:
    await env.add("usr_a", ("staff",), group="staff")
    await env.add("usr_b", ("author", "staff"), subject="user-1")
    await env.add("usr_c", ("ops",), group="ops")
    user = await env.directory.resolve(env.idp.token("user-1", ["staff"]))
    assert user.subject == "user-1"
    assert user.user_ids == ("usr_a", "usr_b")
    assert user.roles == ("staff", "author")


async def test_an_unknown_user_has_no_roles(env: Env) -> None:
    await env.add("usr_a", ("staff",), group="staff")
    user = await env.directory.resolve(env.idp.token("nobody", ["visitors"]))
    assert user.user_ids == ()
    assert user.roles == ()


async def test_on_behalf_of_keeps_the_agent(env: Env) -> None:
    await env.add("usr_a", ("staff",), group="staff")
    principal = await env.directory.on_behalf_of(AGENT, env.idp.token("user-1", ["staff"]))
    assert principal.agent_id == AGENT.agent_id
    assert principal.roles == AGENT.roles
    assert principal.user is not None
    assert principal.user.roles == ("staff",)


async def test_admin_tokens_cannot_carry_a_user(env: Env) -> None:
    admin = Principal(kind=TokenKind.ADMIN, token_id="tok_admin")
    with pytest.raises(ActionNotAllowedError):
        await env.directory.on_behalf_of(admin, env.idp.token())


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "http://evil.test/realms/dev"},
        {"aud": "someone-else"},
        {"exp": int(time.time()) - 600},
        {"exp": None},
        {"sub": None},
        {"sub": ""},
        {"iss": None},
    ],
    ids=["issuer", "audience", "expired", "no-exp", "no-sub", "empty-sub", "no-iss"],
)
async def test_bad_claims_are_refused(env: Env, claims: dict[str, Any]) -> None:
    await assert_refused(env.directory, env.idp.token(**claims))


async def test_expiry_allows_the_configured_leeway(env: Env) -> None:
    await env.directory.resolve(env.idp.token(exp=int(time.time()) - 10))


async def test_a_token_signed_by_another_key_is_refused(env: Env) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    await assert_refused(env.directory, env.idp.token(key=other))


async def test_unsigned_and_hmac_tokens_are_refused(env: Env) -> None:
    payload = jwt.decode(env.idp.token(), options={"verify_signature": False})
    unsigned = jwt.encode(payload, key="", algorithm="none", headers={"kid": env.idp.kid})
    await assert_refused(env.directory, unsigned)
    public_jwk = (await env.idp.fetch())["keys"][0]
    hmac = jwt.encode(payload, public_jwk["n"], algorithm="HS256", headers={"kid": env.idp.kid})
    await assert_refused(env.directory, hmac)


@pytest.mark.parametrize("raw", ["", "not-a-jwt", "a.b.c"])
async def test_garbage_is_refused(env: Env, raw: str) -> None:
    await assert_refused(env.directory, raw)


async def test_without_oidc_settings_every_user_token_is_refused() -> None:
    idp = FakeIdp()
    directory = build_user_directory(InMemoryCollection[User](), None)
    await assert_refused(directory, idp.token())


async def test_jwks_is_cached(env: Env) -> None:
    for _ in range(3):
        await env.directory.resolve(env.idp.token())
    assert env.idp.fetches == 1
    env.clock.advance(timedelta(seconds=301))
    await env.directory.resolve(env.idp.token())
    assert env.idp.fetches == 2


async def test_a_rotated_key_is_fetched_once_per_interval(env: Env) -> None:
    await env.directory.resolve(env.idp.token())
    env.idp.rotate("key-2")
    # Within 30 s of the last fetch an unknown kid is refused without hitting the IdP.
    await assert_refused(env.directory, env.idp.token())
    assert env.idp.fetches == 1
    env.clock.advance(timedelta(seconds=31))
    await env.directory.resolve(env.idp.token())
    assert env.idp.fetches == 2


async def test_an_idp_outage_keeps_the_cached_keys(env: Env) -> None:
    await env.directory.resolve(env.idp.token())

    async def down() -> dict[str, Any]:
        raise OSError("connection refused")

    env.idp.fetch = down  # type: ignore[method-assign]
    env.clock.advance(timedelta(seconds=301))
    await env.directory.resolve(env.idp.token())


async def test_an_unreachable_idp_refuses_without_leaking() -> None:
    class Down:
        async def fetch(self) -> dict[str, Any]:
            raise OSError("connection refused to http://idp.internal")

    idp = FakeIdp()
    directory = build_user_directory(
        InMemoryCollection[User](), oidc_settings(), source=Down(), clock=FixedClock()
    )
    await assert_refused(directory, idp.token())


def test_user_match_needs_exactly_one_field() -> None:
    with pytest.raises(ValidationError):
        UserMatch()
    with pytest.raises(ValidationError):
        UserMatch(subject="a", group="b")


def test_only_asymmetric_algorithms_are_configurable() -> None:
    with pytest.raises(ValidationError):
        oidc_settings(algorithms=["HS256"])
    with pytest.raises(ValidationError):
        oidc_settings(algorithms=["none"])
