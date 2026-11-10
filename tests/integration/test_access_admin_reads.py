"""Reads, directory, and effective access for an access admin (SPEC §23, contract §4 to §6)."""

from collections.abc import AsyncIterator
from typing import Any

import pytest

from agent_gateway.config import Settings
from tests.access_world import ALICE, CAROL, AccessWorld, build_access_world
from tests.fakes.keycloak import CLIENT_SECRET


@pytest.fixture
async def aw(settings: Settings) -> AsyncIterator[AccessWorld]:
    world = await build_access_world(settings)
    yield world
    await world.w.api.aclose()
    await world.w.gateway.stop()


async def get(aw: AccessWorld, path: str, **params: Any) -> Any:
    response = await aw.w.api.get(path, params=params, headers=aw.as_user(CAROL))
    assert response.status_code == 200, response.text
    return response.json()


# ---- reads (contract §4) -----------------------------------------------------------------


async def test_users_are_the_whole_user_store(aw: AccessWorld) -> None:
    users = await get(aw, "/v1/admin/users")
    assert sorted((u["match"].get("group"), u["roles"]) for u in users) == [
        ("platform-admin", ["platform-admin"]),
        ("staff", ["staff"]),
    ]
    assert all(u["id"].startswith("usr_") for u in users)


async def test_policies_are_user_side_with_resource_names(aw: AccessWorld) -> None:
    policies = await get(aw, "/v1/admin/policies", side="user")
    assert policies == [
        {
            "name": "staff-echo",
            "subject": {"user_role": "staff"},
            "actions": ["fake.*"],
            "resources": {"names": ["echo-endpoint"], "tags": []},
            "effect": "allow",
            "approval": "never",
            "expires_at": None,
        }
    ]
    # Without ``side`` an access admin gets the same user side.
    assert await get(aw, "/v1/admin/policies") == policies


async def test_resources_never_carry_secrets_or_credential_ids(aw: AccessWorld) -> None:
    resources = {r["name"]: r for r in await get(aw, "/v1/admin/resources")}
    echo = resources["echo-endpoint"]
    assert echo == {
        "id": aw.w.resource_id,
        "name": "echo-endpoint",
        "type": "http_endpoint",
        "tags": ["env:test"],
        "has_credential": True,
        "allowed_tables": None,
        "catalog": {"synced_at": None, "snapshot_id": None, "pending_review": False},
    }
    sample = resources["sample"]
    assert sample["allowed_tables"] == ["customer"]
    assert sample["catalog"]["snapshot_id"].startswith("snap_")
    assert sample["catalog"]["synced_at"].endswith("Z")
    assert sample["has_credential"] is False
    text = str(await get(aw, "/v1/admin/resources"))
    assert "cred_" not in text
    assert "attributes" not in text
    assert "db.internal" not in text
    only_sql = await get(aw, "/v1/admin/resources", type="sql_database")
    assert [r["name"] for r in only_sql] == ["sample"]


async def test_actions_leave_out_privileged_ones_for_an_access_admin(aw: AccessWorld) -> None:
    actions = {a["id"]: a for a in await get(aw, "/v1/admin/actions")}
    assert "priv.sudo" not in actions
    assert actions["fake.echo"] == {
        "id": "fake.echo",
        "resource_type": "http_endpoint",
        "resource": None,
        "description": "Return the message unchanged.",
        "risk": "low",
        "read_only": True,
        "source": "builtin",
        "state": "active",
    }
    assert "model.chat" in actions
    assert "sql.query" in actions
    static = await aw.w.api.get("/v1/admin/actions", headers=aw.w.admin())
    assert "priv.sudo" in {a["id"] for a in static.json()}


# ---- directory (contract §5) -------------------------------------------------------------


async def test_directory_users_come_from_the_idp(aw: AccessWorld) -> None:
    users = await get(aw, "/v1/admin/directory/users", q="ali", limit=5)
    assert users == [
        {
            "subject": "u-alice",
            "username": "alice",
            "display_name": "Alice A",
            "email": "alice@example.com",
            "groups": ["staff"],
            "enabled": True,
        }
    ]
    everyone = await get(aw, "/v1/admin/directory/users")
    assert [u["username"] for u in everyone] == ["alice", "bob", "carol"]
    # The service account signed in once, with the secret from the credential store.
    assert aw.idp_admin.token_requests == 1


async def test_directory_limit_is_1_to_100(aw: AccessWorld) -> None:
    for limit in (0, 101):
        response = await aw.w.api.get(
            "/v1/admin/directory/users", params={"limit": limit}, headers=aw.as_user(CAROL)
        )
        assert response.status_code == 422


async def test_directory_groups_count_members(aw: AccessWorld) -> None:
    groups = await get(aw, "/v1/admin/directory/groups")
    assert groups == [
        {"name": "platform-admin", "path": "/platform-admin", "member_count": 2},
        {"name": "staff", "path": "/staff", "member_count": 2},
    ]
    assert [g["name"] for g in await get(aw, "/v1/admin/directory/groups", q="sta")] == ["staff"]


async def test_an_unreachable_idp_is_503(aw: AccessWorld) -> None:
    aw.idp_admin.down = True
    for path in ("/v1/admin/directory/users", "/v1/admin/directory/groups"):
        response = await aw.w.api.get(path, headers=aw.as_user(CAROL))
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "directory_unavailable"
    response = await aw.w.api.get(
        "/v1/admin/access", params={"subject": "u-alice"}, headers=aw.as_user(CAROL)
    )
    assert response.status_code == 503


async def test_a_wrong_directory_secret_is_503_without_leaking_it(aw: AccessWorld) -> None:
    aw.idp_admin.issued = "other"  # the IdP refuses the token the gateway holds
    aw.idp_admin.users[0].groups = []
    response = await aw.w.api.get("/v1/admin/directory/users", headers=aw.as_user(CAROL))
    assert response.status_code == 200  # one retry signs in again
    meta = await aw.w.gateway.admin.list_credentials(_cli())
    directory = next(m for m in meta if m.name == "idp-directory")
    from agent_gateway.modules.credentials.models import CredentialType, SecretPayload

    await aw.w.gateway.admin.rotate_credential(
        _cli(), directory.id, SecretPayload(CredentialType.API_TOKEN, "wrong-secret")
    )
    aw.idp_admin.issued = "rotated"
    response = await aw.w.api.get("/v1/admin/directory/users", headers=aw.as_user(CAROL))
    assert response.status_code == 503
    assert CLIENT_SECRET not in response.text
    assert "wrong-secret" not in response.text


async def test_without_directory_settings_the_directory_is_503(settings: Settings) -> None:
    world = await build_access_world(settings)
    try:
        world.w.gateway.access.directory = _unconfigured()
        response = await world.w.api.get("/v1/admin/directory/users", headers=world.as_user(CAROL))
        assert response.status_code == 503
    finally:
        await world.w.api.aclose()
        await world.w.gateway.stop()


# ---- effective access (contract §6) ------------------------------------------------------


async def test_access_shows_roles_with_their_source_grants_and_denials(aw: AccessWorld) -> None:
    view = await get(aw, "/v1/admin/access", subject="u-alice")
    staff_item = next(
        u["id"] for u in await get(aw, "/v1/admin/users") if u["match"].get("group") == "staff"
    )
    assert view["subject"] == "u-alice"
    assert view["groups"] == ["staff"]
    assert view["roles"] == [
        {"role": "staff", "via": [{"kind": "group", "value": "staff", "user_record": staff_item}]}
    ]
    assert view["grants"] == [
        {
            "action": "fake.echo",
            "resource": "echo-endpoint",
            "decision": "allow",
            "policy": "staff-echo",
            "reason": "allowed by policy",
        }
    ]
    assert view["denied"] == [
        {"action": "test.leak", "reason": "no matching allow policy for user"}
    ]


async def test_access_is_user_and_calling_agent(aw: AccessWorld) -> None:
    # Taking fake.* away from the agents' role takes it away from every user through them.
    from agent_gateway.modules.authorization.models import Role

    await aw.w.gateway.admin.put_role(_cli(), Role(id="operator", actions=("test.*", "priv.sudo")))
    view = await get(aw, "/v1/admin/access", subject="u-alice")
    assert view["grants"] == []
    assert {d["action"]: d["reason"] for d in view["denied"]}["fake.echo"] == (
        "action not in agent roles"
    )


async def test_access_of_an_unknown_subject_is_404(aw: AccessWorld) -> None:
    response = await aw.w.api.get(
        "/v1/admin/access", params={"subject": "nobody"}, headers=aw.as_user(CAROL)
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "user_not_found"


async def test_access_with_the_static_token_names_the_agent(aw: AccessWorld) -> None:
    missing = await aw.w.api.get(
        "/v1/admin/access", params={"subject": "u-alice"}, headers=aw.w.admin()
    )
    assert missing.status_code == 422
    response = await aw.w.api.get(
        "/v1/admin/access",
        params={"subject": "u-alice", "agent": "claude-ops"},
        headers=aw.w.admin(),
    )
    assert response.status_code == 200
    assert [g["action"] for g in response.json()["grants"]] == ["fake.echo"]


async def test_a_user_reads_nothing_here(aw: AccessWorld) -> None:
    for path in ("/v1/admin/users", "/v1/admin/actions", "/v1/admin/directory/users"):
        response = await aw.w.api.get(path, headers=aw.as_user(ALICE))
        assert response.json()["error"]["code"] == "not_admin"


def _cli() -> Any:
    from agent_gateway.modules.administration.service import CLI_PRINCIPAL

    return CLI_PRINCIPAL


def _unconfigured() -> Any:
    from agent_gateway.modules.administration.directory import UnconfiguredDirectory

    return UnconfiguredDirectory()
