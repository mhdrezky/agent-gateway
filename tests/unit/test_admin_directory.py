"""The IdP directory client and the ``admin`` settings (SPEC §23)."""

from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_gateway.common.errors import DirectoryUnavailableError
from agent_gateway.config import DirectorySettings, Settings, load_settings
from agent_gateway.modules.administration.directory import KeycloakDirectory
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from tests.fakes.clock import FixedClock
from tests.fakes.credentials import FakeCredentialStore
from tests.fakes.keycloak import BASE_URL, CLIENT_ID, CLIENT_SECRET, REALM, FakeKeycloak, FakeUser


def settings(**overrides: object) -> DirectorySettings:
    values: dict[str, object] = {
        "base_url": f"{BASE_URL}/",
        "realm": REALM,
        "client_id": CLIENT_ID,
        "credential": "idp",
    }
    return DirectorySettings.model_validate({**values, **overrides})


async def directory(
    idp: FakeKeycloak, clock: FixedClock, *, secret: str | None = CLIENT_SECRET, **overrides: object
) -> KeycloakDirectory:
    store = FakeCredentialStore()
    if secret is not None:
        await store.create("idp", SecretPayload(CredentialType.API_TOKEN, secret))
    return KeycloakDirectory(settings(**overrides), store, clock, transport=idp.transport())


@pytest.fixture
def idp() -> FakeKeycloak:
    return FakeKeycloak(
        users=[FakeUser("u-1", "ann", "Ann", "", None, ["staff", "ops"])], groups=["staff", "ops"]
    )


async def test_the_service_token_is_reused_until_it_nearly_expires(idp: FakeKeycloak) -> None:
    clock = FixedClock()
    found = await directory(idp, clock)
    await found.users("", 10)
    await found.groups("")
    assert idp.token_requests == 1
    clock.advance(timedelta(seconds=280))  # 300 s token, refreshed 30 s early
    await found.users("", 10)
    assert idp.token_requests == 2


async def test_a_refused_token_is_renewed_once(idp: FakeKeycloak) -> None:
    found = await directory(idp, FixedClock())
    await found.users("", 10)
    idp.issued = "rotated-by-the-idp"
    assert [u.username for u in await found.users("", 10)] == ["ann"]
    assert idp.token_requests == 2


async def test_groups_can_be_named_by_full_path(idp: FakeKeycloak) -> None:
    found = await directory(idp, FixedClock(), groups_full_path=True)
    user = await found.user("u-1")
    assert user is not None
    assert user.groups == ["/ops", "/staff"]
    assert [g.name for g in await found.groups("")] == ["/ops", "/staff"]


async def test_an_unknown_user_is_none(idp: FakeKeycloak) -> None:
    assert await (await directory(idp, FixedClock())).user("nobody") is None


@pytest.mark.parametrize("secret", [None, "wrong"])
async def test_a_missing_or_wrong_secret_is_unavailable(
    idp: FakeKeycloak, secret: str | None
) -> None:
    found = await directory(idp, FixedClock(), secret=secret)
    with pytest.raises(DirectoryUnavailableError):
        await found.users("", 10)


async def test_an_idp_that_is_down_is_unavailable(idp: FakeKeycloak) -> None:
    idp.down = True
    with pytest.raises(DirectoryUnavailableError):
        await (await directory(idp, FixedClock())).groups("")


def test_admin_settings_load_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "gw.yaml"
    path.write_text(
        "admin:\n"
        "  user_roles: [platform-admin]\n"
        "  apply_requires_second_admin: true\n"
        "  directory:\n"
        "    base_url: http://keycloak:8080\n"
        "    realm: agentgate-dev\n"
        "    client_id: agentgate-directory\n"
        "    credential: keycloak-directory\n",
        encoding="utf-8",
    )
    loaded = load_settings(path)
    assert loaded.admin.user_roles == ["platform-admin"]
    assert loaded.admin.apply_requires_second_admin is True
    assert loaded.admin.directory is not None
    assert loaded.admin.directory.provider == "keycloak"


def test_admin_defaults_make_nobody_an_access_admin() -> None:
    assert Settings().admin.user_roles == []
    assert Settings().admin.directory is None
    with pytest.raises(ValidationError):
        settings(base_url="not a url")
