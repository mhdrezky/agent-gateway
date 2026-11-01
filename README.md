# Agent Gateway

**Unified Access & Action Management for AI agents and automation systems.**

Agent Gateway is a self-hosted gateway that sits between AI agents (LLM agents, MCP clients, scripts, CI jobs) and your infrastructure (servers, containers, GitHub, Cloudflare, cloud APIs). Agents never hold credentials and never run arbitrary commands. They ask the gateway to perform **registered actions**. The gateway authenticates the agent, authorizes the request against policy, optionally waits for human approval, runs the action through a broker, and records everything in a tamper-evident audit log.

> Status: **v0.1, phases 0–2 implemented** (core, SSH and Docker brokers, REST API, MCP server, CLI). Not yet battle-tested on production resources. See [devnote/SPEC.md](devnote/SPEC.md) for the technical specification.

---

## Why

Giving an AI agent an SSH key, a GitHub token, or a Cloudflare API key directly means:

- the secret ends up in prompts, logs, and model context;
- the agent can do *anything* that credential allows;
- there is no central record of what happened, and no way to stop a risky action before it runs.

Agent Gateway fixes this by making the gateway the only component that holds secrets and the only component that executes actions.

```
┌──────────────┐    token     ┌─────────────────────────────────────────────┐
│  AI Agent    │ ───────────▶ │               Agent Gateway                 │
│ (REST / MCP) │              │                                             │
└──────────────┘              │  Identity → Authorization → Approval        │
                              │        → Action Registry → Broker           │
                              │                 │                           │
                              │        Credentials (AES-256-GCM)            │
                              │        Audit log (JSONL + hash chain)       │
                              └─────────────────┼───────────────────────────┘
                                                ▼
                          SSH · Docker · GitHub · Cloudflare · HTTP APIs
```

---

## Core principles

These are non-negotiable. Any change that violates one of them is a bug.

1. **Agents never read the master key.**
2. **Agents never receive private credentials.** Secrets are decrypted only inside a broker, only for the duration of an action.
3. **No arbitrary shell execution**, except through explicitly **privileged** actions (today only `ssh.sudo`), which wildcards never grant and which every layer (role, policy, host flag, server sudoers) can revoke on its own.
4. **Every action must be registered** in the Action Registry with a typed input schema.
5. **Authorization happens on the server**, never delegated to or trusted from the LLM.
6. **REST and MCP share the same execution engine.** No interface has its own code path to a broker.
7. **Storage supports atomic writes and file locking.**

---

## Architecture

| Component      | Decision                                   |
| -------------- | ------------------------------------------ |
| Backend        | Python + FastAPI                           |
| Storage        | JSON files + encrypted binary blobs        |
| Database       | None (no SQL)                              |
| Secret store   | Built-in (no external Vault)               |
| Encryption     | AES-256-GCM                                |
| Authentication | Per-agent API token                        |
| Authorization  | RBAC + per-resource policy                 |
| Execution      | Action Broker only                         |
| Interfaces     | REST API + MCP Server                      |
| Approval       | Human-in-the-loop approval                 |
| Audit          | Append-only JSONL with hash chain          |
| Deployment     | Docker Desktop (docker compose)            |

### Request lifecycle

1. **Authenticate** – the agent presents its API token; the gateway resolves it to an agent identity.
2. **Resolve action** – the requested action is looked up in the Action Registry and its input is validated against the schema.
3. **Authorize** – RBAC role checks plus resource policy (which agent may run which action on which resource).
4. **Approve** – if policy requires it, the request is parked as *pending* until a human approves or rejects it.
5. **Execute** – the matching broker loads the needed credential, performs the action, and returns a sanitized result.
6. **Audit** – every step (allowed, denied, pending, approved, executed, failed) is appended to the hash-chained audit log.

---

## Project structure

```
agent-gateway/
├── src/agent_gateway/
│   ├── apps/
│   │   ├── api_server/      # FastAPI REST interface
│   │   └── mcp_server/      # MCP interface (thin client of the REST API)
│   ├── modules/
│   │   ├── storage/         # atomic JSON writes, file locking
│   │   ├── crypto/          # master key, HKDF, AES-256-GCM envelopes
│   │   ├── identity/        # agents, API tokens, authentication
│   │   ├── authorization/   # RBAC roles + resource policy engine
│   │   ├── resources/       # registry of servers, repos, zones, endpoints
│   │   ├── credentials/     # encrypted credential store
│   │   ├── action_registry/ # registered actions + input schemas
│   │   ├── approvals/       # human approval workflow
│   │   ├── audit/           # JSONL audit log with hash chain
│   │   └── execution/       # the single execution engine (REST + MCP)
│   ├── brokers/
│   │   ├── base.py          # broker contract
│   │   ├── ssh/             # predefined SSH operations (no raw shell)
│   │   ├── docker/          # container lifecycle actions
│   │   ├── github/          # repo / PR / workflow actions
│   │   ├── cloudflare/      # DNS, tunnels, cache actions
│   │   └── http/            # allow-listed HTTP API calls
│   ├── config.py
│   └── cli.py               # admin CLI (`agw`)
├── config/                  # gateway configuration
├── var/                     # runtime data (gitignored, named volume in Docker)
├── devnote/                 # developer notes and SPEC (Indonesian)
├── docker/
├── scripts/
├── tests/
├── docker-compose.yml
├── pyproject.toml
└── README.md
```

---

## Roadmap

| Phase | Name        | Scope                                                                     |
| ----- | ----------- | ------------------------------------------------------------------------- |
| 0     | Contracts   | Project scaffold, data models, module interfaces, test fakes              |
| 1A    | Persistence | Storage engine, encryption, identity, credentials, resources              |
| 1B    | Policy      | Policy engine, action registry, SSH and Docker brokers                    |
| 1C    | Governance  | Audit log with hash chain, approval workflow                              |
| 2     | Integration | Execution engine, REST API, MCP server, CLI, Docker deployment            |
| 3     | Expansion   | GitHub, Cloudflare, RunPod, HTTP brokers, approval notifications          |

Tracks 1A, 1B, and 1C run in parallel on top of the Phase 0 contracts.

---

## Getting started

Requirements: [uv](https://docs.astral.sh/uv/) and, for deployment, Docker Desktop.

### Run with Docker

```bash
uv sync
uv run agw keygen --out secrets/master.key       # back this file up separately
cp config/gateway.example.yaml config/gateway.yaml
docker compose run --rm -v "${PWD}:/host" gateway agw init --env-file /host/.env
docker compose up -d
curl http://127.0.0.1:8080/v1/health
```

### Run locally

```bash
uv sync
uv run agw keygen --out secrets/master.key
uv run agw init                                   # saves the admin token to .env
uv run agw serve
```

`agw init` saves the first admin token to `.env` as `AGW_ADMIN_TOKEN` and says where; `agw token create --admin` does the same for a new one. `.env` is gitignored (see `.env.example` for its format) and created owner-only: anyone who can read it is a gateway admin. Use `--no-save-env` to print the token instead.

Without a `config/gateway.yaml`, the gateway uses `var/` for data, `secrets/master.key` for the key, and listens on `127.0.0.1:8080`.

### Admin web UI

Open `http://127.0.0.1:8080/admin` and log in with an admin token (the one in `.env`). The token is exchanged for an HttpOnly, SameSite=Strict session cookie (8 hours) and is never stored in the browser; revoking that admin token ends the session at once.

| Page | What you can do |
| ---- | --------------- |
| Dashboard | Pending approvals, counts, recent executions |
| Approvals | Review each request with its agent, resource, and full params (root commands highlighted); approve or reject with a reason; optional auto-refresh |
| Executions | Filter by agent, open any execution for its params, stdout/stderr, and decision |
| Agents / Tokens | Create agents, set roles, disable/enable, issue tokens (shown once with a ready `.mcp.json`), revoke tokens, new admin token |
| Resources | Toggle `ssh.sudo`, edit allowed services and tags, delete |
| Roles / Policies | Edit role actions, create and delete policies; registered actions listed with risk and privileged flag |
| Credentials | Store, rotate, delete secrets (write-only, never displayed) |
| Audit | Browse and filter entries, verify the hash chain |

The UI is plain server-rendered HTML: no JavaScript, no third-party assets, a strict Content-Security-Policy, CSRF tokens on every form, and every change goes through the same audited admin service as the CLI. Like the API, it listens on `127.0.0.1` only; put it behind HTTPS before exposing it.

### Scripts

| Command | What it does |
| ------- | ------------ |
| `agw` | Admin CLI on the gateway's data directory (`keygen`, `init`, `serve`, `agent`, `token`, `resource`, `credential`, `role`, `policy`, `approvals`, `audit`) |
| `agw-onboard-ssh` | Interactive onboarding of an SSH host over the admin API: SSH key, host key check, authorized_keys check, names, registration, and a test run |
| `agw-mcp` | Optional stdio MCP bridge for clients that cannot use HTTP MCP; needs `AGW_URL` and `AGW_TOKEN`. Most agents should use the built-in `/mcp` endpoint instead |

### Onboard an SSH host (recommended)

```bash
uv run agw-onboard-ssh
```

It asks for the admin token, the host, port, and SSH user, reuses `secrets/vps-deploy` (or creates it), shows the host key fingerprint for you to confirm, prints the commands to create a dedicated SSH user (default `agent-gateway`, no password, optional `systemd-journal`/`docker` groups) or to install the key for an existing user, waits while you run them, logs in to verify, then creates `<name>-server`, `<name>-key`, `<name>-operator`, and `<name>-agent`, runs `ssh.system.info` as the new agent, and prints the agent token once with a ready `.mcp.json`. It reads the admin token from `--admin-token`, `AGW_ADMIN_TOKEN`, or `.env`; if it has to ask, it offers to save the token to `.env` for next time.

### Give an agent access (manual)

```bash
uv run agw role set operator -a ssh.service.status -a ssh.service.restart
uv run agw agent create claude-ops -r operator
uv run agw credential add homelab-key ssh_private_key --value-file ~/.ssh/deploy_key
uv run agw resource add ssh_host homelab-1 --tag env:prod --credential <cred_id> \
  --attributes '{"host": "192.168.1.10", "username": "deploy", "host_key_fingerprint": "SHA256:...", "allowed_services": ["nginx"]}'
uv run agw policy add -a "ssh.service.*" --role operator --tag env:prod
uv run agw token create --agent <agent_id>         # prints the agent token once
```

### Privileged access: `ssh.sudo`

`ssh.sudo` runs any command as root on an SSH host (`sudo -n -- bash -lc <command>`), for agents that install and configure servers (Docker, Caddy, packages). It is off by default and needs all of these, each revocable on its own:

| Layer | Grant | Revoke (takes effect immediately) |
| ----- | ----- | --------------------------------- |
| Role | `agw role set web01-operator -a "ssh.*" -a ssh.sudo` | `agw role set web01-operator -a "ssh.*"` |
| Policy | `agw policy add -a ssh.sudo --role web01-operator --resource <res_id>` | `agw policy delete <pol_id>` |
| Host flag | `agw resource sudo <res_id> --enable` | `agw resource sudo <res_id> --disable` |
| Server | `/etc/sudoers.d/agent-gateway` with `NOPASSWD:ALL` (onboarding prints the commands) | `sudo rm -f /etc/sudoers.d/agent-gateway` |

`ssh.*` never includes `ssh.sudo`: it must be named exactly. It is high risk, so with the default `by_risk` policy the first command waits for approval.

**Sudo windows.** Approving an `ssh.sudo` command opens a 15-minute window (`approvals.elevation_minutes`, 0 turns it off) in which the same agent may run any `ssh.sudo` command on the same resource without asking again. After 15 minutes the next command needs approval again, which opens a new window. A window never overrides the other layers: role, policy, host flag, and sudoers still apply. Close one early in the UI (Approvals or the resource page, "End now") or with `agw elevation revoke <elv_id>`; open one by hand with `agw elevation grant --agent <agt_id> --resource <res_id> --minutes 15`. Openings and closings are audited (`elevation.granted`, `elevation.revoked`).

### Connect an agent over MCP

The gateway serves MCP (Streamable HTTP) at `/mcp`. An agent needs only the URL and its own agent token, no copy of this repo. Put the token in the `AGW_TOKEN` environment variable and add this to the agent project's `.mcp.json`:

```json
{
  "mcpServers": {
    "agent-gateway": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp",
      "headers": { "Authorization": "Bearer ${AGW_TOKEN}" }
    }
  }
}
```

Every `/mcp` request is authenticated with that header; requests without a valid agent token get `401`, admin tokens get `403`, and each tool call runs as the agent that sent it, through the same engine as the REST API. `/mcp` accepts only `localhost` Host headers unless you list public names in `server.public_hosts`; expose it beyond this machine only behind HTTPS.

Clients that only speak stdio can use the bridge instead: `"command": "uv", "args": ["--directory", "/path/to/agent-gateway", "run", "agw-mcp"]` with `AGW_URL` and `AGW_TOKEN` in `env`.

Actions that need approval return `pending_approval`. Review them with:

```bash
uv run agw approvals list
uv run agw approvals approve <approval_id>
```

### Development

```bash
uv run ruff format --check . && uv run ruff check . && uv run mypy && uv run pytest
```

End-to-end test against the Docker image and a real OpenSSH server (needs Docker running):

```bash
docker build -f docker/Dockerfile -t agent-gateway:local .
uv run python tests/e2e/run_e2e.py          # add --keep to leave the stack up
```

SSH resources pin one host key: `host_key_fingerprint` is its SHA-256 fingerprint and `host_key_algorithm` (default `ssh-ed25519`) is its type. Get both with `ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -`.

---

## Security model (summary)

- **Master key** is provided to the gateway at startup (environment/secret file) and is never written to `storage/` or exposed through any interface.
- **Credentials** are stored encrypted with AES-256-GCM, each with its own nonce, and are decrypted only inside a broker.
- **API tokens** are stored hashed; the plaintext token is shown once at creation.
- **Audit log** entries include the hash of the previous entry, so any edit or deletion breaks the chain and is detectable.
- **Broker outputs** are sanitized before being returned to the agent.

---

## Documentation

- [devnote/SPEC.md](devnote/SPEC.md) – technical specification: module responsibilities, data schemas, encryption spec, auth model, broker interface, REST contract, MCP tool definitions, approval workflow, audit format, deployment, and testing strategy.

## Conventions

- All code, comments, docstrings, commit messages, and user-facing docs are in **English**.
- Everything under `devnote/` (internal developer notes, including the SPEC) is written in **Indonesian**.

## License

TBD.
