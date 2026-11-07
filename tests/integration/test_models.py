"""Model resources, ``/v1/models``, chat, and ``/v1/bind`` over REST (SPEC §10.4, §15.4)."""

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from agent_gateway.config import Settings, UserSettings
from agent_gateway.modules.administration.service import CLI_PRINCIPAL
from agent_gateway.modules.authorization.models import (
    ApprovalMode,
    PolicyEffect,
    PolicySubject,
    ResourceSelector,
    Role,
)
from agent_gateway.modules.credentials.models import CredentialType, SecretPayload
from agent_gateway.modules.identity.models import UserMatch
from agent_gateway.modules.resources.models import ResourceType
from tests.fakes.oidc import FakeIdp, oidc_settings
from tests.integration.test_user_identity import as_user, audit_events
from tests.world import World, build_world

MODEL_KEY = "sk-model-key-7f3a9c1e"
DEFAULT_ID = "vllm:qwen3-32b@rev-2f4c1a9"
BIG_ID = "vllm:llama-70b@rev-0b1c2d3"
OPTIONS = {"chat_template_kwargs": {"enable_thinking": False}, "reasoning_effort": "none"}
PROMPT = "the secret plan is pineapple"
REPLY = "noted the plan"


@dataclass
class Upstream:
    """A fake OpenAI-compatible server behind ``httpx.MockTransport``."""

    requests: list[httpx.Request] = field(default_factory=list)
    status: int = 200
    body: Any = None
    fail: Exception | None = None

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail is not None:
            raise self.fail
        body = self.body
        if body is None:
            body = {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": REPLY,
                            "tool_calls": [{"id": "c1", "type": "function"}],
                        }
                    }
                ],
                "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
            }
        return httpx.Response(self.status, json=body)

    def sent(self) -> dict[str, Any]:
        body: dict[str, Any] = json.loads(self.requests[-1].content)
        return body


@dataclass
class ModelWorld:
    world: World
    idp: FakeIdp
    upstream: Upstream
    models: dict[str, str]

    def staff(self) -> dict[str, str]:
        return as_user(self.world, self.idp.token("u-staff", ["staff"]))

    def author(self) -> dict[str, str]:
        return as_user(self.world, self.idp.token("u-author", ["authors"]))

    def nobody(self) -> dict[str, str]:
        return as_user(self.world, self.idp.token("u-nobody", []))


@pytest.fixture
async def mw(settings: Settings, idp: FakeIdp) -> AsyncIterator[ModelWorld]:
    """Agent role ``operator`` may chat with ``default`` and ``big``; ``slow`` needs approval;
    ``hidden`` has no policy. Staff users may chat with ``default`` only; authors may bind.
    """
    upstream = Upstream()
    configured = settings.model_copy(update={"users": UserSettings(oidc=oidc_settings())})
    w = await build_world(
        configured,
        approval=ApprovalMode.NEVER,
        jwks=idp,
        model_transport=httpx.MockTransport(upstream.handle),
    )
    admin = w.gateway.admin
    key = await admin.create_credential(
        CLI_PRINCIPAL, "model key", SecretPayload(CredentialType.API_TOKEN, MODEL_KEY)
    )
    models: dict[str, str] = {}
    for name, model_id, credential in [
        ("default", DEFAULT_ID, key.id),
        ("big", BIG_ID, None),
        ("slow", "vllm:slow@rev-1", None),
        ("hidden", "vllm:hidden@rev-1", None),
    ]:
        resource = await admin.create_resource(
            CLI_PRINCIPAL,
            ResourceType.MODEL,
            name,
            attributes={
                "base_url": f"http://{name}.models.internal/",
                "model_id": model_id,
                "options": OPTIONS if name == "default" else {},
            },
            credential_id=credential,
        )
        models[name] = resource.id
    await admin.put_role(
        CLI_PRINCIPAL, Role(id="operator", actions=("fake.*", "test.*", "model.chat"))
    )
    await admin.put_role(CLI_PRINCIPAL, Role(id="staff", actions=("fake.*", "model.*")))
    await admin.add_user(CLI_PRINCIPAL, UserMatch(group="staff"), ["staff"])
    await admin.add_user(CLI_PRINCIPAL, UserMatch(group="authors"), ["author"])
    for subject, ids, approval in [
        (PolicySubject(role="operator"), (models["default"], models["big"]), ApprovalMode.NEVER),
        (PolicySubject(role="operator"), (models["slow"],), ApprovalMode.ALWAYS),
        (PolicySubject(user_role="staff"), (models["default"], models["slow"]), ApprovalMode.NEVER),
    ]:
        await admin.create_policy(
            CLI_PRINCIPAL,
            subject=subject,
            actions=["model.chat"],
            resources=ResourceSelector(ids=ids),
            effect=PolicyEffect.ALLOW,
            approval=approval,
        )
    yield ModelWorld(world=w, idp=idp, upstream=upstream, models=models)
    await w.api.aclose()
    await w.gateway.stop()


def turn(**extra: Any) -> dict[str, Any]:
    return {"messages": [{"role": "user", "content": PROMPT}], **extra}


async def chat(mw: ModelWorld, name: str, headers: dict[str, str], **extra: Any) -> httpx.Response:
    return await mw.world.api.post(f"/v1/models/{name}/chat", json=turn(**extra), headers=headers)


# ---- GET /v1/models ---------------------------------------------------------------------


async def test_models_are_scoped_to_user_and_agent(mw: ModelWorld) -> None:
    agent = await mw.world.api.get("/v1/models", headers=mw.world.agent())
    assert agent.status_code == 200, agent.text
    assert agent.json() == [
        {"name": "big", "model_id": BIG_ID},
        {"name": "default", "model_id": DEFAULT_ID},
    ]
    staff = await mw.world.api.get("/v1/models", headers=mw.staff())
    assert staff.json() == [{"name": "default", "model_id": DEFAULT_ID}]


async def test_a_user_without_roles_sees_no_models(mw: ModelWorld) -> None:
    response = await mw.world.api.get("/v1/models", headers=mw.nobody())
    assert response.status_code == 200, response.text
    assert response.json() == []


async def test_models_need_valid_tokens(mw: ModelWorld) -> None:
    assert (await mw.world.api.get("/v1/models")).status_code == 401
    forged = as_user(mw.world, "eyJhbGciOiJub25lIn0.e30.")
    response = await mw.world.api.get("/v1/models", headers=forged)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"
    admin = await mw.world.api.get("/v1/models", headers=mw.world.admin())
    assert admin.json() == []


async def test_model_chat_is_not_an_action_or_a_tool(mw: ModelWorld) -> None:
    actions = await mw.world.api.get("/v1/actions", headers=mw.world.agent())
    assert "model.chat" not in [a["id"] for a in actions.json()]
    submit = await mw.world.api.post(
        "/v1/executions",
        json={"action": "model.chat", "resource_id": mw.models["default"], "params": {}},
        headers=mw.world.agent(),
    )
    assert submit.status_code == 404
    assert submit.json()["error"]["code"] == "action_not_found"


# ---- POST /v1/models/{name}/chat ------------------------------------------------------------


async def test_chat_sends_the_exact_model_and_options(mw: ModelWorld) -> None:
    tools = [{"type": "function", "function": {"name": "fake_echo", "parameters": {}}}]
    response = await chat(
        mw, "default", mw.staff(), tools=tools, temperature=0.2, max_tokens=64, correlation_id="c:1"
    )
    assert response.status_code == 200, response.text
    out = response.json()
    assert out["status"] == "ok"
    assert out["model_id"] == DEFAULT_ID
    assert out["message"]["content"] == REPLY
    assert out["usage"]["prompt_tokens"] == 11

    request = mw.upstream.requests[-1]
    assert str(request.url) == "http://default.models.internal/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {MODEL_KEY}"
    assert mw.upstream.sent() == {
        "model": DEFAULT_ID,
        "messages": [{"role": "user", "content": PROMPT}],
        **OPTIONS,
        "tools": tools,
        "tool_choice": "auto",
        "temperature": 0.2,
        "max_tokens": 64,
    }


async def test_chat_without_a_credential_sends_no_authorization(mw: ModelWorld) -> None:
    response = await chat(mw, "big", mw.world.agent())
    assert response.json()["status"] == "ok"
    assert response.json()["model_id"] == BIG_ID
    assert "authorization" not in mw.upstream.requests[-1].headers
    assert mw.upstream.sent() == {"model": BIG_ID, "messages": turn()["messages"]}


@pytest.mark.parametrize(
    ("name", "who"),
    [("big", "staff"), ("hidden", "agent"), ("slow", "agent"), ("slow", "staff"), ("big", "admin")],
)
async def test_chat_that_is_not_allowed_is_denied(mw: ModelWorld, name: str, who: str) -> None:
    headers = {
        "staff": mw.staff(),
        "agent": mw.world.agent(),
        "admin": mw.world.admin(),
    }[who]
    response = await chat(mw, name, headers)
    assert response.status_code == 200, response.text
    out = response.json()
    assert out["status"] == "denied"
    assert out["error"] == f"model '{name}' is not allowed for this caller"
    assert out["message"] is None
    assert mw.upstream.requests == []


async def test_chat_with_an_unknown_model_is_404(mw: ModelWorld) -> None:
    response = await chat(mw, "no-such-model", mw.staff())
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "model_not_found"
    assert mw.upstream.requests == []


@pytest.mark.parametrize(
    ("status", "body", "fail", "error"),
    [
        (500, {"error": f"boom {MODEL_KEY}"}, None, "model call failed: HTTPStatusError"),
        (200, None, httpx.ConnectError("refused"), "model call failed: ConnectError"),
        (200, None, httpx.ReadTimeout("slow"), "model call failed: ReadTimeout"),
        (200, {"choices": []}, None, "model call failed: invalid response"),
    ],
)
async def test_upstream_failures_are_safe_errors(
    mw: ModelWorld, status: int, body: Any, fail: Exception | None, error: str
) -> None:
    mw.upstream.status, mw.upstream.body, mw.upstream.fail = status, body, fail
    response = await chat(mw, "default", mw.staff())
    assert response.status_code == 200, response.text
    assert response.json() == {
        "status": "error",
        "message": None,
        "usage": None,
        "error": error,
        "model_id": None,
    }
    assert MODEL_KEY not in response.text


async def test_a_reply_echoing_the_credential_is_redacted(mw: ModelWorld) -> None:
    mw.upstream.body = {"choices": [{"message": {"role": "assistant", "content": MODEL_KEY}}]}
    response = await chat(mw, "default", mw.staff())
    assert response.json()["message"]["content"] == "***"


async def test_chat_is_audited_without_message_text(mw: ModelWorld) -> None:
    await chat(mw, "default", mw.staff(), correlation_id="conv-1:3")
    await chat(mw, "big", mw.staff())
    await chat(mw, "nope", mw.staff())
    events = await audit_events(mw.world, "model.chat")
    assert [e["details"]["outcome"] for e in events] == ["ok", "denied", "not_found"]
    ok = events[0]
    assert ok["actor"] == {"type": "agent", "id": mw.world.agent_id}
    assert ok["action"] == "model.chat"
    assert ok["resource_id"] == mw.models["default"]
    assert ok["details"] == {
        "model": "default",
        "model_id": DEFAULT_ID,
        "user": "u-staff",
        "correlation_id": "conv-1:3",
        "outcome": "ok",
        "prompt_tokens": 11,
        "completion_tokens": 3,
        "tool_calls": 1,
    }
    var = mw.world.gateway.settings.var_dir
    stored = "".join(p.read_text(encoding="utf-8") for p in var.rglob("*.json*"))
    for text in (PROMPT, REPLY, MODEL_KEY):
        assert text not in stored
    assert not (var / "executions").exists() or not any((var / "executions").rglob("*.json"))


@pytest.mark.parametrize(
    ("attributes", "field"),
    [
        ({"base_url": "http://m", "model_id": "latest"}, "model_id"),
        ({"base_url": "http://m", "model_id": "qwen3:latest"}, "model_id"),
        ({"base_url": "http://m", "model_id": "q", "options": {"model": "x"}}, "options"),
        ({"base_url": "http://m", "model_id": "q", "options": {"stream": True}}, "options"),
        ({"base_url": "file:///etc/passwd", "model_id": "q"}, "base_url"),
    ],
)
async def test_model_attributes_are_validated(
    mw: ModelWorld, attributes: dict[str, Any], field: str
) -> None:
    response = await mw.world.api.post(
        "/v1/admin/resources",
        json={"type": "model", "name": "bad", "attributes": attributes},
        headers=mw.world.admin(),
    )
    assert response.status_code == 422, response.text
    assert field in response.json()["error"]["message"]


# ---- POST /v1/bind ------------------------------------------------------------------------


async def test_bind_resolves_names_for_the_agent(mw: ModelWorld) -> None:
    # The author has no grants of their own: bind checks the agent's names only.
    body = {
        "models": ["default", "big"],
        "tools": ["fake_echo", "test_sleep"],
        "resources": [mw.world.resource_id, mw.models["default"]],
    }
    response = await mw.world.api.post("/v1/bind", json=body, headers=mw.author())
    assert response.status_code == 200, response.text
    assert response.json() == {"models": {"default": DEFAULT_ID, "big": BIG_ID}}
    events = await audit_events(mw.world, "bind.checked")
    assert events[-1]["details"]["outcome"] == "ok"
    assert events[-1]["details"]["user"] == "u-author"
    assert events[-1]["details"]["bound_models"] == {"default": DEFAULT_ID, "big": BIG_ID}


async def test_bind_lists_exactly_what_is_missing(mw: ModelWorld) -> None:
    body = {
        "models": ["default", "no-such-model", "hidden", "slow"],
        "tools": ["fake_echo", "no_such_tool", "model_chat", "fake.echo"],
        "resources": [mw.world.resource_id, "res_none", mw.models["hidden"]],
    }
    response = await mw.world.api.post("/v1/bind", json=body, headers=mw.author())
    assert response.status_code == 409, response.text
    error = response.json()["error"]
    assert error["code"] == "names_missing"
    assert error["message"]
    assert error["missing"] == {
        "models": ["hidden", "no-such-model", "slow"],
        "tools": ["fake.echo", "model_chat", "no_such_tool"],
        "resources": sorted(["res_none", mw.models["hidden"]]),
    }
    events = await audit_events(mw.world, "bind.checked")
    assert events[-1]["details"]["outcome"] == "missing"
    assert events[-1]["details"]["missing"] == error["missing"]


async def test_bind_needs_an_author_or_reviewer(mw: ModelWorld) -> None:
    body = {"models": ["default"]}
    no_user = await mw.world.api.post("/v1/bind", json=body, headers=mw.world.agent())
    assert no_user.status_code == 401
    assert no_user.json()["error"]["code"] == "unauthenticated"
    staff = await mw.world.api.post("/v1/bind", json=body, headers=mw.staff())
    assert staff.status_code == 403
    assert staff.json()["error"]["code"] == "action_not_allowed"
    nobody = await mw.world.api.post("/v1/bind", json=body, headers=mw.nobody())
    assert nobody.status_code == 403
    events = await audit_events(mw.world, "bind.checked")
    assert [e["details"]["outcome"] for e in events] == ["no_user", "forbidden", "forbidden"]


async def test_bind_roles_come_from_settings(settings: Settings, idp: FakeIdp) -> None:
    configured = settings.model_copy(
        update={
            "users": UserSettings(oidc=oidc_settings()),
            "bind": settings.bind.model_copy(update={"roles": ["staff"]}),
        }
    )
    w = await build_world(configured, approval=ApprovalMode.NEVER, jwks=idp)
    try:
        await w.gateway.admin.add_user(CLI_PRINCIPAL, UserMatch(group="staff"), ["staff"])
        response = await w.api.post(
            "/v1/bind", json={}, headers=as_user(w, idp.token("u-1", ["staff"]))
        )
        assert response.status_code == 200, response.text
        assert response.json() == {"models": {}}
    finally:
        await w.api.aclose()
        await w.gateway.stop()
