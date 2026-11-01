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
3. **No arbitrary shell execution.** There is no "run this command" action.
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
docker compose run --rm gateway agw init         # prints the first admin token once
docker compose up -d
curl http://127.0.0.1:8080/v1/health
```

### Run locally

```bash
uv sync
uv run agw keygen --out secrets/master.key
uv run agw init
uv run agw serve
```

Without a `config/gateway.yaml`, the gateway uses `var/` for data, `secrets/master.key` for the key, and listens on `127.0.0.1:8080`.

### Give an agent access

```bash
uv run agw role set operator -a ssh.service.status -a ssh.service.restart
uv run agw agent create claude-ops -r operator
uv run agw credential add homelab-key ssh_private_key --value-file ~/.ssh/deploy_key
uv run agw resource add ssh_host homelab-1 --tag env:prod --credential <cred_id> \
  --attributes '{"host": "192.168.1.10", "username": "deploy", "host_key_fingerprint": "SHA256:...", "allowed_services": ["nginx"]}'
uv run agw policy add -a "ssh.service.*" --role operator --tag env:prod
uv run agw token create --agent <agent_id>         # prints the agent token once
```

Then point the agent at the REST API, or add the MCP server to its client config:

```json
{
  "mcpServers": {
    "agent-gateway": {
      "command": "uv",
      "args": ["--directory", "/path/to/agent-gateway", "run", "agw-mcp"],
      "env": { "AGW_URL": "http://127.0.0.1:8080", "AGW_TOKEN": "agw_tok_..." }
    }
  }
}
```

Actions that need approval return `pending_approval`. Review them with:

```bash
uv run agw approvals list
uv run agw approvals approve <approval_id>
```

### Development

```bash
uv run ruff format --check . && uv run ruff check . && uv run mypy && uv run pytest
```

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
