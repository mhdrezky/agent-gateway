"""End-to-end flows through the REST API (SPEC §12, §13, §15)."""

from agent_gateway.modules.audit.models import AuditEventType
from tests.world import World


async def _submit(world: World, headers: dict[str, str], **body: object) -> tuple[int, dict]:  # type: ignore[type-arg]
    payload: dict[str, object] = {
        "action": "fake.echo",
        "resource_id": world.resource_id,
        "params": {"message": "hi"},
    }
    payload.update(body)
    response = await world.api.post("/v1/executions", json=payload, headers=headers)
    return response.status_code, response.json()


async def test_health_needs_no_token(world: World) -> None:
    response = await world.api.get("/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_missing_or_bad_token_is_401_and_audited(world: World) -> None:
    for headers in ({}, {"Authorization": "Bearer agw_tok_nope_x"}, {"Authorization": "Basic x"}):
        response = await world.api.get("/v1/whoami", headers=headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthenticated"
    failures = await world.gateway.audit.query(event=AuditEventType.AUTH_FAILED)
    assert len(failures) == 3


async def test_auth_failures_are_rate_limited(world: World) -> None:
    codes = [
        (await world.api.get("/v1/whoami", headers={"Authorization": "Bearer bad"})).status_code
        for _ in range(7)
    ]
    assert codes[:5] == [401] * 5
    assert codes[5:] == [429, 429]


async def test_whoami(world: World) -> None:
    body = (await world.api.get("/v1/whoami", headers=world.agent())).json()
    assert body["agent_id"] == world.agent_id
    assert body["roles"] == ["operator"]


async def test_agent_sees_actions_and_resources_without_attributes(world: World) -> None:
    actions = (await world.api.get("/v1/actions", headers=world.agent())).json()
    assert [a["id"] for a in actions] == ["fake.echo", "test.leak", "test.sleep"]
    assert actions[0]["params_schema"]["properties"]["message"]["type"] == "string"
    resources = (await world.api.get("/v1/resources", headers=world.agent())).json()
    assert resources == [
        {
            "id": world.resource_id,
            "type": "http_endpoint",
            "name": "echo-endpoint",
            "tags": ["env:test"],
        }
    ]


async def test_execute_succeeds(world: World) -> None:
    status, body = await _submit(world, world.agent())
    assert status == 200
    assert body["status"] == "succeeded"
    assert body["result"]["data"] == {"message": "hi"}
    ctx, _ = world.fake.calls[0]
    assert ctx.agent_id == world.agent_id
    assert ctx.credential is not None  # the broker got the credential, the agent did not

    fetched = await world.api.get(f"/v1/executions/{body['id']}", headers=world.agent())
    assert fetched.json()["id"] == body["id"]
    page = (await world.api.get("/v1/executions", headers=world.agent())).json()
    assert [e["id"] for e in page["items"]] == [body["id"]]


async def test_agents_cannot_see_each_others_executions(world: World) -> None:
    _, body = await _submit(world, world.agent())
    response = await world.api.get(f"/v1/executions/{body['id']}", headers=world.other())
    assert response.status_code == 404
    assert (await world.api.get("/v1/executions", headers=world.other())).json()["items"] == []
    admin_view = await world.api.get(f"/v1/executions/{body['id']}", headers=world.admin())
    assert admin_view.status_code == 200


async def test_idempotency_key_returns_the_same_execution(world: World) -> None:
    _, first = await _submit(world, world.agent(), idempotency_key="k1")
    _, second = await _submit(world, world.agent(), idempotency_key="k1")
    assert first["id"] == second["id"]
    assert len(world.fake.calls) == 1


async def test_pagination(world: World) -> None:
    ids = [(await _submit(world, world.agent()))[1]["id"] for _ in range(3)]
    first = (await world.api.get("/v1/executions?limit=2", headers=world.agent())).json()
    assert [e["id"] for e in first["items"]] == ids[::-1][:2]
    rest = (
        await world.api.get(
            f"/v1/executions?limit=2&cursor={first['next_cursor']}", headers=world.agent()
        )
    ).json()
    assert [e["id"] for e in rest["items"]] == [ids[0]]
    assert rest["next_cursor"] is None


async def test_no_matching_policy_is_denied(world: World) -> None:
    resource = await world.api.post(
        "/v1/admin/resources",
        json={"type": "http_endpoint", "name": "unlisted", "attributes": {"host": "x"}},
        headers=world.admin(),
    )
    status, body = await _submit(world, world.agent(), resource_id=resource.json()["id"])
    assert status == 403
    assert body["error"]["code"] == "action_not_allowed"
    denied = await world.api.get(
        f"/v1/executions/{body['error']['execution_id']}", headers=world.agent()
    )
    assert denied.json()["status"] == "denied"
    assert world.fake.calls == []


async def test_invalid_params_are_422(world: World) -> None:
    status, body = await _submit(world, world.agent(), params={"message": 1, "x": 2})
    assert status == 422
    assert body["error"]["code"] == "invalid_params"


async def test_broker_timeout_fails_the_execution(world: World) -> None:
    status, body = await _submit(world, world.agent(), action="test.sleep", params={"seconds": 5})
    assert status == 200
    assert body["status"] == "failed"
    assert body["error"] == "the action timed out"


async def test_admin_crud_round_trip(world: World) -> None:
    created = await world.api.post(
        "/v1/admin/agents", json={"name": "new-agent", "roles": ["operator"]}, headers=world.admin()
    )
    assert created.status_code == 201
    agent_id = created.json()["id"]
    token = await world.api.post(
        f"/v1/admin/agents/{agent_id}/tokens", json={}, headers=world.admin()
    )
    assert token.status_code == 201
    plaintext = token.json()["plaintext"]
    assert plaintext.startswith("agw_tok_")

    me = await world.api.get("/v1/whoami", headers={"Authorization": f"Bearer {plaintext}"})
    assert me.json()["agent_id"] == agent_id

    await world.api.delete(f"/v1/admin/tokens/{token.json()['token']['id']}", headers=world.admin())
    revoked = await world.api.get("/v1/whoami", headers={"Authorization": f"Bearer {plaintext}"})
    assert revoked.status_code == 401

    disabled = await world.api.patch(
        f"/v1/admin/agents/{world.agent_id}", json={"status": "disabled"}, headers=world.admin()
    )
    assert disabled.json()["status"] == "disabled"
    assert (await world.api.get("/v1/whoami", headers=world.agent())).status_code == 401


async def test_unknown_route_is_json_404(world: World) -> None:
    response = await world.api.get("/v1/nope", headers=world.agent())
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


async def test_audit_chain_is_intact_after_a_session(world: World) -> None:
    await _submit(world, world.agent())
    await _submit(world, world.agent(), action="fake.missing")
    verify = (await world.api.get("/v1/admin/audit/verify", headers=world.admin())).json()
    assert verify["ok"] is True
    events = [
        e["event"] for e in (await world.api.get("/v1/admin/audit", headers=world.admin())).json()
    ]
    for expected in (
        "execution.requested",
        "execution.started",
        "execution.succeeded",
        "execution.rejected",
        "token.created",
    ):
        assert expected in events
