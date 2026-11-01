"""Agents, tokens, and authentication (SPEC §8.1, §8.2, §9)."""

import hashlib
import hmac
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agent_gateway.common.errors import (
    AgentNotFoundError,
    AuthenticationError,
    ConflictError,
    InvalidParamsError,
    NotFoundError,
)
from agent_gateway.common.ids import IdPrefix, has_prefix
from agent_gateway.modules.crypto.keyring import MasterKeyRing
from agent_gateway.modules.crypto.ports import SubkeyPurpose
from agent_gateway.modules.identity.authenticator import AUTH_FAILED_MESSAGE, TokenAuthenticator
from agent_gateway.modules.identity.models import (
    Agent,
    AgentStatus,
    IssuedToken,
    Token,
    TokenKind,
)
from agent_gateway.modules.identity.ports import Authenticator, IdentityService
from agent_gateway.modules.identity.service import IdentityManager
from agent_gateway.modules.identity.tokens import display_prefix, parse_token
from agent_gateway.modules.storage.json_collection import JsonCollection
from agent_gateway.modules.storage.locking import FileLocker
from tests.fakes.clock import FixedClock
from tests.fakes.storage import InMemoryCollection

MASTER_KEY = bytes(range(32))


class CountingCollection[R: Agent | Token](InMemoryCollection[R]):
    def __init__(self) -> None:
        super().__init__()
        self.updates = 0

    async def update(self, item_id: str, fn: Callable[[R], R]) -> R:
        self.updates += 1
        return await super().update(item_id, fn)


class Env:
    def __init__(self) -> None:
        self.clock = FixedClock()
        self.keyring = MasterKeyRing(MASTER_KEY)
        self.agents = InMemoryCollection[Agent]()
        self.tokens = CountingCollection[Token]()
        self.identity = IdentityManager(self.agents, self.tokens, self.keyring, clock=self.clock)
        self.auth = TokenAuthenticator(self.agents, self.tokens, self.keyring, clock=self.clock)

    async def agent_token(self, *, expires_at: datetime | None = None) -> tuple[Agent, IssuedToken]:
        agent = await self.identity.create_agent("bot", roles=["operator"])
        issued = await self.identity.issue_token(
            TokenKind.AGENT, agent_id=agent.id, expires_at=expires_at
        )
        return agent, issued


@pytest.fixture
def env() -> Env:
    return Env()


async def assert_rejected(auth: Authenticator, raw: str) -> None:
    with pytest.raises(AuthenticationError) as info:
        await auth.authenticate(raw)
    assert info.value.message == AUTH_FAILED_MESSAGE
    assert str(info.value) == AUTH_FAILED_MESSAGE
    assert info.value.__cause__ is None


def test_implementations_satisfy_protocols(env: Env) -> None:
    service: IdentityService = env.identity
    authenticator: Authenticator = env.auth
    assert service is not None
    assert authenticator is not None


class TestAgents:
    async def test_create_and_get(self, env: Env) -> None:
        agent = await env.identity.create_agent(
            "claude-devops", description="ops", roles=["operator", "viewer", "operator"]
        )
        assert has_prefix(agent.id, IdPrefix.AGENT)
        assert agent.roles == ("operator", "viewer")
        assert agent.status is AgentStatus.ACTIVE
        assert agent.created_at == env.clock.now()
        assert await env.identity.get_agent(agent.id) == agent
        assert await env.identity.get_agent("agt_missing") is None

    async def test_duplicate_name_conflicts(self, env: Env) -> None:
        await env.identity.create_agent("bot")
        with pytest.raises(ConflictError):
            await env.identity.create_agent("bot")

    @pytest.mark.parametrize("name", ["", "Bad Name", "-x", "a" * 65])
    async def test_invalid_name(self, env: Env, name: str) -> None:
        with pytest.raises(InvalidParamsError, match="name"):
            await env.identity.create_agent(name)
        assert await env.identity.list_agents() == []

    async def test_roles_string_rejected(self, env: Env) -> None:
        with pytest.raises(InvalidParamsError, match="roles"):
            await env.identity.create_agent("bot", roles="operator")

    async def test_list_sorted_by_id(self, env: Env) -> None:
        created = [await env.identity.create_agent(name) for name in ("c", "a", "b")]
        assert await env.identity.list_agents() == sorted(created, key=lambda a: a.id)

    async def test_update(self, env: Env) -> None:
        agent = await env.identity.create_agent("bot", description="old", roles=["a"])
        updated = await env.identity.update_agent(
            agent.id, description="new", roles=["b"], status=AgentStatus.DISABLED
        )
        assert (updated.description, updated.roles, updated.status) == (
            "new",
            ("b",),
            AgentStatus.DISABLED,
        )
        assert updated.name == agent.name
        assert updated.created_at == agent.created_at
        unchanged = await env.identity.update_agent(agent.id)
        assert unchanged == updated

    async def test_update_validates(self, env: Env) -> None:
        agent = await env.identity.create_agent("bot")
        with pytest.raises(InvalidParamsError, match="description"):
            await env.identity.update_agent(agent.id, description="x" * 501)
        assert await env.identity.get_agent(agent.id) == agent

    async def test_update_missing(self, env: Env) -> None:
        with pytest.raises(AgentNotFoundError):
            await env.identity.update_agent("agt_missing", description="x")


class TestTokens:
    async def test_issue_agent_token(self, env: Env) -> None:
        agent, issued = await env.agent_token()
        token = issued.token
        plaintext = issued.plaintext.get_secret_value()

        assert has_prefix(token.id, IdPrefix.TOKEN)
        assert token.kind is TokenKind.AGENT
        assert token.agent_id == agent.id
        assert token.created_at == env.clock.now()
        assert plaintext.startswith(f"agw_{token.id}_")
        assert token.prefix == display_prefix(token.id) == plaintext[:13]
        assert len(plaintext) == len("agw_") + len(token.id) + 1 + 43
        assert plaintext not in repr(issued)
        assert await env.tokens.get(token.id) == token

    async def test_stored_hash_is_hmac_of_secret(self, env: Env) -> None:
        _, issued = await env.agent_token()
        parsed = parse_token(issued.plaintext.get_secret_value())
        assert parsed is not None
        key = env.keyring.subkey(SubkeyPurpose.TOKEN_HMAC)
        expected = hmac.new(key, parsed.secret.encode(), hashlib.sha256).hexdigest()
        assert issued.token.hash == expected
        assert parsed.secret not in issued.token.model_dump_json()

    async def test_secrets_are_unique(self, env: Env) -> None:
        agent = await env.identity.create_agent("bot")
        issued = [
            await env.identity.issue_token(TokenKind.AGENT, agent_id=agent.id) for _ in range(20)
        ]
        assert len({i.plaintext.get_secret_value() for i in issued}) == 20
        assert len({i.token.hash for i in issued}) == 20

    async def test_issue_admin_token(self, env: Env) -> None:
        issued = await env.identity.issue_token(TokenKind.ADMIN)
        assert issued.token.kind is TokenKind.ADMIN
        assert issued.token.agent_id is None

    async def test_issue_validation(self, env: Env) -> None:
        agent = await env.identity.create_agent("bot")
        with pytest.raises(InvalidParamsError):
            await env.identity.issue_token(TokenKind.AGENT)
        with pytest.raises(AgentNotFoundError):
            await env.identity.issue_token(TokenKind.AGENT, agent_id="agt_missing")
        with pytest.raises(InvalidParamsError):
            await env.identity.issue_token(TokenKind.ADMIN, agent_id=agent.id)
        with pytest.raises(InvalidParamsError, match="timezone"):
            await env.identity.issue_token(TokenKind.ADMIN, expires_at=datetime(2030, 1, 1))  # noqa: DTZ001
        with pytest.raises(InvalidParamsError, match="future"):
            await env.identity.issue_token(TokenKind.ADMIN, expires_at=env.clock.now())
        assert await env.identity.list_tokens() == []

    async def test_revoke(self, env: Env) -> None:
        _, issued = await env.agent_token()
        revoked = await env.identity.revoke_token(issued.token.id)
        assert revoked.revoked_at == env.clock.now()
        env.clock.advance(timedelta(hours=1))
        again = await env.identity.revoke_token(issued.token.id)
        assert again.revoked_at == revoked.revoked_at
        with pytest.raises(NotFoundError):
            await env.identity.revoke_token("tok_missing")

    async def test_list_tokens_filters_by_agent(self, env: Env) -> None:
        agent, issued = await env.agent_token()
        other = await env.identity.create_agent("other")
        await env.identity.issue_token(TokenKind.AGENT, agent_id=other.id)
        admin = await env.identity.issue_token(TokenKind.ADMIN)
        assert await env.identity.list_tokens(agent_id=agent.id) == [issued.token]
        assert len(await env.identity.list_tokens()) == 3
        assert admin.token in await env.identity.list_tokens()


class TestAuthenticate:
    async def test_agent_token(self, env: Env) -> None:
        agent, issued = await env.agent_token()
        principal = await env.auth.authenticate(issued.plaintext.get_secret_value())
        assert principal.kind is TokenKind.AGENT
        assert principal.token_id == issued.token.id
        assert principal.agent_id == agent.id
        assert principal.roles == ("operator",)
        assert not principal.is_admin

    async def test_admin_token(self, env: Env) -> None:
        issued = await env.identity.issue_token(TokenKind.ADMIN)
        principal = await env.auth.authenticate(issued.plaintext.get_secret_value())
        assert principal.is_admin
        assert principal.agent_id is None
        assert principal.roles == ()

    async def test_roles_are_read_at_auth_time(self, env: Env) -> None:
        agent, issued = await env.agent_token()
        await env.identity.update_agent(agent.id, roles=["viewer"])
        principal = await env.auth.authenticate(issued.plaintext.get_secret_value())
        assert principal.roles == ("viewer",)

    async def test_wrong_secret(self, env: Env) -> None:
        _, issued = await env.agent_token()
        plaintext = issued.plaintext.get_secret_value()
        last = plaintext[-1]
        await assert_rejected(env.auth, plaintext[:-1] + ("A" if last != "A" else "B"))

    async def test_secret_of_another_token(self, env: Env) -> None:
        _, first = await env.agent_token()
        second = await env.identity.issue_token(TokenKind.ADMIN)
        first_parsed = parse_token(first.plaintext.get_secret_value())
        second_parsed = parse_token(second.plaintext.get_secret_value())
        assert first_parsed is not None
        assert second_parsed is not None
        await assert_rejected(env.auth, f"agw_{first_parsed.token_id}_{second_parsed.secret}")

    async def test_unknown_token_id(self, env: Env) -> None:
        _, issued = await env.agent_token()
        parsed = parse_token(issued.plaintext.get_secret_value())
        assert parsed is not None
        await assert_rejected(env.auth, f"agw_tok_01JB8ABCDEFGHJKMNPQRSTVWXY_{parsed.secret}")

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "agw",
            "Bearer agw_tok_01JB8ABCDEFGHJKMNPQRSTVWXY_" + "a" * 43,
            "xyz_tok_01JB8ABCDEFGHJKMNPQRSTVWXY_" + "a" * 43,
            "agw_agt_01JB8ABCDEFGHJKMNPQRSTVWXY_" + "a" * 43,
            "agw_tok_SHORT_" + "a" * 43,
            "agw_tok_01JB8ABCDEFGHJKMNPQRSTVWXY_" + "a" * 42,
            "agw_tok_01JB8ABCDEFGHJKMNPQRSTVWXY_" + "a" * 44,
            "agw_tok_01JB8ABCDEFGHJKMNPQRSTVWXY_" + "a" * 42 + "=",
            "agw_tok_01JB8ABCDEFGHJKMNPQRSTVWXY_" + "a" * 42 + "é",
            "agw_tok_01JB8ABCDEFGHJKMNPQRSTVWXY",
            "x" * 10_000,
        ],
    )
    async def test_malformed(self, env: Env, raw: str) -> None:
        await assert_rejected(env.auth, raw)

    async def test_secret_may_contain_underscores(self) -> None:
        secret = "ab_cd" + "x" * 38
        parsed = parse_token(f"agw_tok_01JB8ABCDEFGHJKMNPQRSTVWXY_{secret}")
        assert parsed is not None
        assert parsed.token_id == "tok_01JB8ABCDEFGHJKMNPQRSTVWXY"
        assert parsed.secret == secret
        assert secret not in repr(parsed)

    async def test_revoked(self, env: Env) -> None:
        _, issued = await env.agent_token()
        await env.identity.revoke_token(issued.token.id)
        await assert_rejected(env.auth, issued.plaintext.get_secret_value())

    async def test_expired(self, env: Env) -> None:
        expires_at = env.clock.now() + timedelta(hours=1)
        _, issued = await env.agent_token(expires_at=expires_at)
        raw = issued.plaintext.get_secret_value()
        env.clock.advance(timedelta(minutes=59))
        await env.auth.authenticate(raw)
        env.clock.advance(timedelta(minutes=1))
        await assert_rejected(env.auth, raw)

    async def test_disabled_agent(self, env: Env) -> None:
        agent, issued = await env.agent_token()
        raw = issued.plaintext.get_secret_value()
        await env.identity.update_agent(agent.id, status=AgentStatus.DISABLED)
        await assert_rejected(env.auth, raw)
        await env.identity.update_agent(agent.id, status=AgentStatus.ACTIVE)
        await env.auth.authenticate(raw)

    async def test_deleted_agent(self, env: Env) -> None:
        agent, issued = await env.agent_token()
        await env.agents.delete(agent.id)
        await assert_rejected(env.auth, issued.plaintext.get_secret_value())

    async def test_token_deleted_while_marking_used(self, env: Env) -> None:
        _, issued = await env.agent_token()
        original_update = env.tokens.update

        async def delete_then_update(item_id: str, fn: Callable[[Token], Token]) -> Token:
            await env.tokens.delete(item_id)
            return await original_update(item_id, fn)

        env.tokens.update = delete_then_update  # type: ignore[method-assign]
        await assert_rejected(env.auth, issued.plaintext.get_secret_value())

    async def test_token_revoked_while_marking_used(self, env: Env) -> None:
        _, issued = await env.agent_token()
        original_update = env.tokens.update

        async def revoke_then_update(item_id: str, fn: Callable[[Token], Token]) -> Token:
            await original_update(
                item_id, lambda t: t.model_copy(update={"revoked_at": env.clock.now()})
            )
            return await original_update(item_id, fn)

        env.tokens.update = revoke_then_update  # type: ignore[method-assign]
        await assert_rejected(env.auth, issued.plaintext.get_secret_value())

    async def test_last_used_is_throttled(self, env: Env) -> None:
        _, issued = await env.agent_token()
        raw = issued.plaintext.get_secret_value()
        start = env.clock.now()

        await env.auth.authenticate(raw)
        assert env.tokens.updates == 1
        stored = await env.tokens.get(issued.token.id)
        assert stored is not None
        assert stored.last_used_at == start

        env.clock.advance(timedelta(seconds=59))
        await env.auth.authenticate(raw)
        assert env.tokens.updates == 1

        env.clock.advance(timedelta(seconds=1))
        await env.auth.authenticate(raw)
        assert env.tokens.updates == 2
        stored = await env.tokens.get(issued.token.id)
        assert stored is not None
        assert stored.last_used_at == start + timedelta(minutes=1)

    async def test_failed_auth_does_not_write(self, env: Env) -> None:
        _, issued = await env.agent_token()
        await env.identity.revoke_token(issued.token.id)
        updates = env.tokens.updates
        await assert_rejected(env.auth, issued.plaintext.get_secret_value())
        assert env.tokens.updates == updates

    async def test_other_master_key_rejects(self, env: Env) -> None:
        _, issued = await env.agent_token()
        other = TokenAuthenticator(
            env.agents, env.tokens, MasterKeyRing(bytes(32)), clock=env.clock
        )
        await assert_rejected(other, issued.plaintext.get_secret_value())


async def test_end_to_end_with_json_collections(tmp_path: Path) -> None:
    locker = FileLocker(tmp_path / ".locks")
    clock = FixedClock(datetime(2026, 10, 31, tzinfo=UTC))
    agents = JsonCollection(tmp_path / "agents.json", Agent, locker=locker, clock=clock)
    tokens = JsonCollection(tmp_path / "tokens.json", Token, locker=locker, clock=clock)
    keyring = MasterKeyRing(MASTER_KEY)
    identity = IdentityManager(agents, tokens, keyring, clock=clock)
    agent = await identity.create_agent("claude-devops", roles=["operator"])
    issued = await identity.issue_token(TokenKind.AGENT, agent_id=agent.id)
    raw = issued.plaintext.get_secret_value()

    principal = await TokenAuthenticator(agents, tokens, keyring, clock=clock).authenticate(raw)
    assert principal.agent_id == agent.id
    parsed = parse_token(raw)
    assert parsed is not None
    assert parsed.secret not in (tmp_path / "tokens.json").read_text(encoding="utf-8")
