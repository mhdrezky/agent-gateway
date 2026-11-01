"""End-to-end test against the real Docker image and a real SSH server.

    uv run python tests/e2e/run_e2e.py [--keep]

Builds nothing itself: run ``docker build -f docker/Dockerfile -t agent-gateway:local .``
first (or let compose build it). Everything runs in the ``agw-e2e`` compose project with
its own volume and a throwaway master key and SSH key under ``tests/e2e/.work/``.
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import TextContent

from agent_gateway.modules.crypto.keyring import generate_master_key

HERE = Path(__file__).resolve().parent
WORK = HERE / ".work"
COMPOSE = ["docker", "compose", "-f", str(HERE / "docker-compose.e2e.yml")]
URL = "http://127.0.0.1:18080"
HOST_KEY = "/config/ssh_host_keys/ssh_host_ed25519_key.pub"
TERMINAL = {"succeeded", "failed", "denied", "rejected", "expired"}


class Report:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.bodies: list[str] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {name}" + (f" - {detail}" if detail and not ok else ""))
        if not ok:
            self.failures.append(name)


def sh(*args: str, check: bool = True, capture: bool = True) -> str:
    result = subprocess.run(
        list(args), cwd=HERE, check=False, capture_output=capture, text=True, encoding="utf-8"
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
    return result.stdout or ""


def compose(*args: str, check: bool = True) -> str:
    return sh(*COMPOSE, *args, check=check)


def wait_for(what: str, probe: Callable[[], Any], timeout: float = 60) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = probe()
            if value:
                return value
        except Exception:  # noqa: S110 - keep polling until the deadline
            pass
        time.sleep(1)
    raise TimeoutError(f"timed out waiting for {what}")


def prepare() -> None:
    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "keys").mkdir(parents=True)
    (WORK / "master.key").write_text(generate_master_key() + "\n", encoding="ascii")
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(WORK / "keys" / "id_ed25519"))


def start() -> str:
    compose("down", "-v", "--remove-orphans", check=False)
    compose("up", "-d", "sshd")
    output = compose("run", "--rm", "gateway", "agw", "init")
    token = next(line for line in output.splitlines() if line.startswith("agw_tok_"))
    compose("up", "-d", "gateway")
    wait_for("gateway health", lambda: httpx.get(f"{URL}/v1/health").status_code == 200)
    return token


def host_fingerprint() -> str:
    line = wait_for(
        "sshd host key", lambda: compose("exec", "-T", "sshd", "ssh-keygen", "-lf", HOST_KEY)
    )
    return str(line.split()[1])


def poll(api: httpx.Client, execution_id: str, timeout: float = 30) -> dict[str, Any]:
    def done() -> dict[str, Any] | None:
        body: dict[str, Any] = api.get(f"/v1/executions/{execution_id}").json()
        return body if body["status"] in TERMINAL else None

    result: dict[str, Any] = wait_for(f"execution {execution_id}", done, timeout)
    return result


def _ran(execution: dict[str, Any]) -> bool:
    """The fixed command reached the host (it may still exit non-zero: no systemd there)."""
    result = execution.get("result") or {}
    return execution.get("started_at") is not None and "exit_code" in result.get("data", {})


def configure(admin: httpx.Client, fingerprint: str) -> dict[str, str]:
    private_key = (WORK / "keys" / "id_ed25519").read_text(encoding="utf-8")
    admin.put("/v1/admin/roles/operator", json={"actions": ["ssh.*"]}).raise_for_status()
    agent = admin.post("/v1/admin/agents", json={"name": "e2e-agent", "roles": ["operator"]})
    credential = admin.post(
        "/v1/admin/credentials",
        json={"name": "e2e ssh key", "type": "ssh_private_key", "value": private_key},
    )
    attributes = {
        "host": "sshd",
        "port": 2222,
        "username": "deploy",
        "host_key_fingerprint": fingerprint,
        "allowed_services": ["nginx"],
    }
    resource = admin.post(
        "/v1/admin/resources",
        json={
            "type": "ssh_host",
            "name": "e2e-sshd",
            "tags": ["env:prod"],
            "attributes": attributes,
            "credential_id": credential.json()["id"],
        },
    )
    bad_key = admin.post(
        "/v1/admin/resources",
        json={
            "type": "ssh_host",
            "name": "e2e-wrong-hostkey",
            "tags": ["env:prod"],
            "attributes": attributes | {"host_key_fingerprint": "SHA256:" + "A" * 43},
            "credential_id": credential.json()["id"],
        },
    )
    unlisted = admin.post(
        "/v1/admin/resources",
        json={
            "type": "ssh_host",
            "name": "e2e-unlisted",
            "tags": ["env:staging"],
            "attributes": attributes,
            "credential_id": credential.json()["id"],
        },
    )
    admin.post(
        "/v1/admin/policies",
        json={
            "subject": {"role": "operator"},
            "actions": ["ssh.*"],
            "resources": {"tags": ["env:prod"]},
            "effect": "allow",
            "approval": "by_risk",
        },
    ).raise_for_status()
    token = admin.post(f"/v1/admin/agents/{agent.json()['id']}/tokens", json={})
    return {
        "agent_token": token.json()["plaintext"],
        "resource": resource.json()["id"],
        "bad_key_resource": bad_key.json()["id"],
        "unlisted_resource": unlisted.json()["id"],
        "private_key": private_key,
    }


def rest_checks(report: Report, agent: httpx.Client, ids: dict[str, str]) -> None:
    def submit(action: str, resource: str, params: dict[str, Any]) -> httpx.Response:
        response = agent.post(
            "/v1/executions", json={"action": action, "resource_id": resource, "params": params}
        )
        report.bodies.append(response.text)
        return response

    actions = [a["id"] for a in agent.get("/v1/actions").json()]
    report.check("agent sees ssh actions", "ssh.system.info" in actions, str(actions))

    resources = agent.get("/v1/resources").json()
    report.bodies.append(json.dumps(resources))
    report.check(
        "agent sees only allowed resources, without attributes",
        {r["name"] for r in resources} == {"e2e-sshd", "e2e-wrong-hostkey"}
        and all("attributes" not in r for r in resources),
        json.dumps(resources),
    )

    info = submit("ssh.system.info", ids["resource"], {})
    body = info.json()
    report.check(
        "ssh.system.info runs over real SSH",
        info.status_code == 200
        and body["status"] == "succeeded"
        and "load average" in body["result"]["data"]["uptime"]["stdout"],
        info.text[:300],
    )

    status = submit("ssh.service.status", ids["resource"], {"service": "nginx"})
    report.check(
        "ssh.service.status runs (container has no systemd, so it may report failure)",
        status.status_code == 200 and _ran(status.json()),
        status.text[:300],
    )

    not_allowed = submit("ssh.service.status", ids["resource"], {"service": "sshd"})
    report.check(
        "service outside allowed_services is refused",
        not_allowed.status_code == 200 and not_allowed.json()["status"] == "failed",
        not_allowed.text[:300],
    )

    injection = submit("ssh.service.status", ids["resource"], {"service": "nginx; id"})
    report.check("shell metacharacters rejected as invalid params", injection.status_code == 422)

    wrong_key = submit("ssh.system.info", ids["bad_key_resource"], {})
    report.check(
        "wrong host key fingerprint is refused",
        wrong_key.json()["status"] == "failed" and "host key" in (wrong_key.json()["error"] or ""),
        wrong_key.text[:300],
    )

    denied = submit("ssh.system.info", ids["unlisted_resource"], {})
    report.check(
        "resource without a policy is denied",
        denied.status_code == 403 and denied.json()["error"]["code"] == "action_not_allowed",
        denied.text[:300],
    )

    unknown = submit("ssh.shell.exec", ids["resource"], {})
    report.check("unregistered action is 404", unknown.status_code == 404)

    restart = submit("ssh.service.restart", ids["resource"], {"service": "nginx"})
    pending = restart.json()
    report.check(
        "medium-risk action on env:prod waits for approval",
        restart.status_code == 202 and pending["status"] == "pending_approval",
        restart.text[:300],
    )
    if restart.status_code == 202:
        compose("exec", "-T", "gateway", "agw", "approvals", "approve", pending["approval_id"])
        finished = poll(agent, pending["id"])
        report.bodies.append(json.dumps(finished))
        report.check(
            "CLI approval in another process is picked up and executed",
            _ran(finished),
            json.dumps(finished)[:300],
        )


async def mcp_checks(report: Report, token: str, resource_id: str) -> None:
    params = StdioServerParameters(
        command="uv",
        args=["run", "--project", str(HERE.parents[1]), "agw-mcp"],
        env={**os.environ, "AGW_URL": URL, "AGW_TOKEN": token},
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = {t.name for t in (await session.list_tools()).tools}
        report.check(
            "MCP server lists the four tools",
            tools == {"list_actions", "list_resources", "execute_action", "get_execution"},
            str(tools),
        )
        result = await session.call_tool(
            "execute_action",
            {"action": "ssh.system.info", "resource_id": resource_id, "params": {}},
        )
        item = result.content[0]
        text = item.text if isinstance(item, TextContent) else ""
        report.bodies.append(text)
        body = json.loads(text) if text else {}
        report.check(
            "MCP execute_action runs over real SSH through the REST engine",
            body.get("status") == "succeeded",
            text[:300],
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="leave the stack running")
    args = parser.parse_args()

    report = Report()
    prepare()
    try:
        admin_token = start()
        report.check("gateway container healthy and initialised", True)
        fingerprint = host_fingerprint()
        admin = httpx.Client(
            base_url=URL, headers={"Authorization": f"Bearer {admin_token}"}, timeout=60
        )
        ids = configure(admin, fingerprint)
        agent = httpx.Client(
            base_url=URL, headers={"Authorization": f"Bearer {ids['agent_token']}"}, timeout=60
        )
        rest_checks(report, agent, ids)
        asyncio.run(mcp_checks(report, ids["agent_token"], ids["resource"]))

        verify = json.loads(compose("exec", "-T", "gateway", "agw", "audit", "verify"))
        report.check("audit chain verifies", verify["ok"] is True, json.dumps(verify))

        master_key = (WORK / "master.key").read_text(encoding="ascii").strip()
        key_body = "".join(ids["private_key"].splitlines()[1:-1])
        leaks = [b for b in report.bodies if master_key in b or (key_body and key_body[:40] in b)]
        report.check("no master key or private key in any agent response", not leaks)
    finally:
        if args.keep:
            print(f"Stack left running at {URL} (compose project agw-e2e).")
        else:
            compose("down", "-v", "--remove-orphans", check=False)
            shutil.rmtree(WORK, ignore_errors=True)

    print(f"\n{'FAILED' if report.failures else 'ALL PASSED'}: {len(report.failures)} failure(s)")
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main())
