# Agent Gateway — Technical Specification

> Versi: 0.1 (draft) · Tanggal: 2026-10-31 · Status: disetujui untuk implementasi Fase 0
>
> Dokumen ini adalah sumber kebenaran arsitektur. Coding agent (Codex, Claude Code, dll.) wajib mengikuti spesifikasi ini. Jika implementasi perlu menyimpang, ubah SPEC terlebih dahulu.

## Daftar isi

1. [Ringkasan](#1-ringkasan)
2. [Konvensi project](#2-konvensi-project)
3. [Arsitektur sistem](#3-arsitektur-sistem)
4. [Struktur project](#4-struktur-project)
5. [Tanggung jawab module](#5-tanggung-jawab-module)
6. [Storage engine](#6-storage-engine)
7. [Spesifikasi enkripsi](#7-spesifikasi-enkripsi)
8. [Data schema](#8-data-schema)
9. [Authentication](#9-authentication)
10. [Authorization](#10-authorization)
11. [Action Registry & Broker interface](#11-action-registry--broker-interface)
12. [Execution engine](#12-execution-engine)
13. [Approval workflow](#13-approval-workflow)
14. [Audit log](#14-audit-log)
15. [REST API contract](#15-rest-api-contract)
16. [MCP server](#16-mcp-server)
17. [Konfigurasi](#17-konfigurasi)
18. [Deployment Docker](#18-deployment-docker)
19. [Strategi testing](#19-strategi-testing)
20. [Rencana implementasi bertahap](#20-rencana-implementasi-bertahap)
21. [Pertanyaan terbuka](#21-pertanyaan-terbuka)
22. [Kontrak `agentgate-gateway/1`](#22-kontrak-agentgate-gateway1)
23. [Kontrak `agentgate-gateway-admin/1`](#23-kontrak-agentgate-gateway-admin1-draf-10-nov-2026)

---

## 1. Ringkasan

Agent Gateway adalah gateway self-hosted yang menjadi satu-satunya jalur bagi AI agent untuk melakukan aksi ke infrastruktur (server via SSH, Docker, GitHub, Cloudflare, API HTTP lain). Agent tidak pernah memegang credential dan tidak pernah menjalankan perintah bebas. Agent hanya meminta gateway menjalankan **action yang terdaftar** pada **resource yang terdaftar**.

### Prinsip yang tidak boleh dilanggar

| # | Prinsip | Cara ditegakkan |
| - | ------- | --------------- |
| P1 | Agent tidak pernah membaca master key. | Master key hanya ada di memori proses gateway; tidak ada endpoint/tool yang mengembalikannya. |
| P2 | Agent tidak pernah menerima private credential. | Credential hanya didekripsi di dalam broker; output broker disanitasi. Endpoint credential bersifat write-only. |
| P3 | Tidak ada arbitrary shell execution, kecuali lewat action **privileged** yang dibuka secara sadar. | Action biasa hanya menjalankan template perintah tetap dengan parameter tervalidasi. Pengecualian (revisi 2026-11-01): `ssh.sudo` (`privileged=True`, risk minimal `high`). Action privileged tidak pernah tercakup wildcard (`ssh.*`); role dan policy harus menyebut id-nya persis, resource harus `allow_sudo: true`, dan server harus memberi sudo ke user gateway. Setiap lapisan bisa dicabut kapan saja secara terpisah. |
| P4 | Semua action harus terdaftar. | Execution engine menolak action id yang tidak ada di registry. |
| P5 | Authorization dilakukan di server. | Keputusan dibuat oleh policy engine; input dari LLM hanya dianggap sebagai permintaan. |
| P6 | MCP dan REST memakai execution engine yang sama. | MCP server adalah thin client ke REST API; tidak punya jalur sendiri ke broker. |
| P7 | Storage mendukung atomic write dan file locking. | Semua tulis melalui `modules/storage`; tidak ada module lain yang menulis file langsung. |

Setiap prinsip harus punya minimal satu test yang membuktikannya (lihat §19).

## 2. Konvensi project

- **Bahasa:** semua kode, nama identifier, comment, docstring, commit message, log message, README, dan pesan error API memakai **bahasa Inggris**. Semua file di folder `devnote/` memakai **bahasa Indonesia**.
- **Python:** 3.12+. Type hints wajib. Format dengan `ruff format`, lint dengan `ruff`, type check dengan `mypy --strict` untuk `src/`.
- **Packaging:** `pyproject.toml` dengan src layout (`src/agent_gateway`). Dependency manager: `uv`.
- **Model data:** Pydantic v2 untuk semua schema (storage, API, action input).
- **Waktu:** semua timestamp UTC, format RFC 3339 dengan sufiks `Z`.
- **ID:** prefix + ULID, contoh `agt_01JB...` (agent), `res_...` (resource), `cred_...`, `exe_...` (execution), `apr_...` (approval).
- **Default deny:** apa pun yang tidak diizinkan secara eksplisit ditolak.

## 3. Arsitektur sistem

```
             ┌───────────────────────┐
 AI agent ──▶│ MCP server (stdio/HTTP)│── HTTP + agent token ──┐
             └───────────────────────┘                         │
 AI agent / script ── HTTP + agent token ─────────────────────▶│
                                                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│ API server (FastAPI)                                                 │
│                                                                      │
│   identity ──▶ execution engine ──▶ authorization ──▶ approvals      │
│                      │                                    │          │
│                      ▼                                    ▼          │
│               action_registry ──▶ broker ◀── credentials (decrypt)   │
│                      │                                               │
│                      └──────────────▶ audit                          │
│                                                                      │
│   storage (atomic write + lock)  ◀── semua module persisten          │
└──────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
            SSH · Docker · GitHub · Cloudflare · HTTP API
```

Keputusan arsitektur utama:

| Komponen | Keputusan |
| -------- | --------- |
| Backend | Python + FastAPI, satu proses (uvicorn, 1 worker) |
| Storage | File JSON + blob terenkripsi, tanpa SQL |
| Secret store | Bawaan, tanpa Vault eksternal |
| Enkripsi | AES-256-GCM, subkey via HKDF-SHA256 |
| Authentication | API token per agent (hash HMAC tersimpan) |
| Authorization | RBAC + policy per resource |
| Execution | Hanya melalui Action Broker |
| Interface | REST API (utama) + MCP server (thin client) |
| Approval | Human-in-the-loop via admin API / CLI |
| Audit | JSONL append-only + hash chain |
| Deployment | Docker Desktop, docker compose, named volume |

**Kenapa satu worker:** storage berbasis file. Satu proses membuat locking dan urutan hash chain audit sederhana dan deterministik. Beban yang diharapkan (personal infrastructure) jauh di bawah batas satu proses async.

## 4. Struktur project

```
agent-gateway/
├── src/agent_gateway/
│   ├── apps/
│   │   ├── api_server/          # FastAPI app, routers, dependencies
│   │   └── mcp_server/          # MCP server, memanggil REST API
│   ├── modules/
│   │   ├── storage/             # atomic write, file lock, repository dasar
│   │   ├── crypto/              # master key, HKDF, AES-GCM envelope
│   │   ├── identity/            # agent, token, authentication
│   │   ├── authorization/       # role, policy, policy decision
│   │   ├── resources/           # registry resource
│   │   ├── credentials/         # credential store terenkripsi
│   │   ├── action_registry/     # definisi & lookup action
│   │   ├── approvals/           # state machine approval
│   │   ├── audit/               # writer & verifier hash chain
│   │   ├── execution/           # orkestrasi pipeline eksekusi, store, dispatcher approval
│   │   ├── administration/      # operasi admin ber-audit (REST admin + CLI)
│   │   ├── catalog/             # snapshot katalog per resource, diff, review (§11.6)
│   │   └── model_endpoints/     # resource model: daftar & chat OpenAI-compatible (fase 4)
│   ├── brokers/
│   │   ├── base.py              # Broker protocol & ActionContext
│   │   ├── ssh/
│   │   ├── docker/
│   │   ├── github/
│   │   ├── cloudflare/
│   │   ├── http/
│   │   ├── sql/                 # sql.query + baca katalog tabel (§11.4, §11.6)
│   │   ├── smtp/                # mail.send (fase 4, §11.5)
│   │   └── mcp/                 # tool server MCP luar sebagai action (§11.6)
│   ├── common/                  # utilitas bersama: ids, clock, canonical JSON, errors, base model
│   ├── config.py                # loader konfigurasi
│   ├── runtime.py               # composition root: merangkai semua implementasi
│   └── cli.py                   # CLI admin (`agw`)
├── config/
│   └── gateway.example.yaml
├── var/                         # data runtime (gitignored, named volume di Docker)
├── devnote/                     # catatan developer (bahasa Indonesia)
├── docker/
│   └── Dockerfile
├── scripts/
├── tests/
│   ├── fakes/                   # implementasi in-memory dari kontrak
│   ├── contracts/               # test kontrak yang bisa dipakai ulang oleh implementasi nyata
│   ├── unit/
│   ├── integration/
│   └── security/
├── docker-compose.yml
├── pyproject.toml
└── README.md
```

Perubahan dari draft awal:

- `storage/` di root diganti `var/` agar tidak bentrok dengan `modules/storage/`.
- Nama folder memakai underscore agar bisa di-import Python.
- Ditambah `modules/execution/` sebagai satu-satunya execution engine (P6).
- Ditambah `modules/crypto/` agar enkripsi terisolasi dan mudah diaudit.
- `brokers/base.py` mendefinisikan kontrak broker.

### Aturan dependency antar module

```
apps ──▶ execution ──▶ {identity, authorization, approvals, action_registry, audit}
action_registry ──▶ brokers ──▶ {credentials, resources}
credentials ──▶ crypto
semua module persisten ──▶ storage
```

- `brokers` tidak boleh meng-import `apps`, `cli`, `execution`, `authorization`, atau `crypto`.
- `apps` tidak boleh memanggil broker secara langsung.
- `apps/mcp_server` tidak boleh meng-import `modules`, `brokers`, `runtime`, `cli`, atau `apps.api_server`; ia hanya bicara HTTP ke REST API.
- `modules` tidak boleh meng-import `apps`, `cli`, atau `runtime`. Hanya `runtime.py` (composition root), `cli.py`, dan `apps` yang merangkai implementasi konkret.
- Hanya `credentials` yang boleh memanggil fungsi dekripsi dari `crypto`. `identity` (HMAC token) dan `audit` (anchor) hanya boleh memakai `KeyRing.subkey`. `authorization`, `action_registry`, `approvals`, `resources`, `execution` tidak boleh meng-import `crypto`.
- `model_endpoints` tidak boleh meng-import `crypto` atau `brokers`; credential hanya lewat `CredentialStore.open` (§7.5).
- `catalog` tidak boleh meng-import `crypto`, `brokers`, atau `execution`; sumber katalog (broker) dirangkai oleh `runtime`.
- `common` tidak boleh meng-import module lain mana pun.
- Tidak ada relative import.

Aturan di atas ditegakkan oleh `tests/security/test_import_boundaries.py`.

### Konvensi file di dalam module

| File | Isi |
| ---- | --- |
| `models.py` | Model Pydantic / dataclass milik module. Boleh di-import module lain. |
| `ports.py` | `Protocol` yang menjadi kontrak publik module. Module lain bergantung pada ini, bukan pada implementasi. |
| file lain | Implementasi (mis. `service.py`, `json_collection.py`). Hanya di-import oleh composition root (`apps`, `cli`) dan test. |

Semua model turunan `common.models.StrictModel` (immutable, `extra="forbid"`); model yang disimpan di collection turunan `Record` (punya `id`). Timestamp memakai `AwareDatetime`, sehingga datetime tanpa timezone ditolak.

## 5. Tanggung jawab module

| Module | Tanggung jawab | Tidak boleh |
| ------ | -------------- | ----------- |
| `storage` | Baca/tulis JSON & blob secara atomic, file lock, versi schema | Tahu isi domain |
| `crypto` | Load master key, derivasi subkey, encrypt/decrypt envelope | Menyimpan key ke disk |
| `identity` | CRUD agent, issue/revoke token, authenticate request | Membuat keputusan izin |
| `authorization` | Role, policy binding, mengembalikan `Decision` | Mengeksekusi action |
| `resources` | CRUD resource (host, repo, zone, endpoint) dan atributnya | Menyimpan secret |
| `credentials` | Simpan credential terenkripsi, dekripsi untuk broker | Mengembalikan plaintext ke API |
| `action_registry` | Registrasi action, validasi input, lookup broker | Mengecek izin |
| `approvals` | Membuat, menyetujui, menolak, meng-expire approval | Mengeksekusi action |
| `audit` | Menulis event berantai hash, verifikasi chain | Mencatat secret |
| `execution` | Menjalankan pipeline lengkap (§12) | Logika spesifik broker |
| `brokers/*` | Menjalankan operasi nyata ke sistem eksternal | Menerima perintah bebas |
| `catalog` | Snapshot katalog per resource (tabel SQL, tool MCP), diff tiap sync, review tool, guard panggilan, mendaftarkan action katalog (§11.6) | Memberi izin |
| `model_endpoints` | Resource `model`: memutuskan izin `model.chat`, meneruskan satu giliran chat ke server OpenAI-compatible, audit tanpa teks pesan (§15.4) | Menyimpan isi pesan, menunggu approval |

## 6. Storage engine

### 6.1 Layout direktori `var/`

```
var/
├── agents.json
├── tokens.json
├── roles.json
├── policies.json
├── resources.json
├── credentials.json            # metadata saja, tanpa secret
├── credentials/
│   └── cred_<id>.bin           # envelope terenkripsi
├── approvals.json
├── users.json                  # user OIDC → role (fase 4, §8.9)
├── executions/
│   └── 2026-10/exe_<id>.json   # satu file per eksekusi
├── audit/
│   ├── 2026-10-31.jsonl
│   └── head.json               # seq & hash terakhir
└── .locks/
```

### 6.2 Format file JSON

Setiap file koleksi:

```json
{
  "schema_version": 1,
  "updated_at": "2026-10-31T10:00:00Z",
  "items": { "<id>": { ... } }
}
```

Saat load, `schema_version` yang lebih baru dari yang dikenal → gateway menolak start. Versi lebih lama → dijalankan migrasi berurutan dari `modules/storage/migrations/`.

### 6.3 Atomic write

1. Ambil lock untuk file tujuan.
2. Tulis ke `<file>.tmp-<random>` di direktori yang sama.
3. `flush()` + `os.fsync(fd)`.
4. `os.replace(tmp, target)`.
5. `fsync` direktori induk (jika OS mendukung).
6. Lepas lock.

Jika proses mati di tengah, file lama tetap utuh. File `*.tmp-*` sisa dibersihkan saat startup.

### 6.4 Locking

- Dalam proses: `asyncio.Lock` per file.
- Antar proses (API server vs CLI `agw`): file lock di `var/.locks/<name>.lock` memakai library `filelock`.
- Urutan pengambilan lock lebih dari satu file selalu alfabetis untuk mencegah deadlock.
- `var/` **harus** berada di Docker named volume, bukan bind mount ke drive Windows, karena semantik lock dan `fsync` pada bind mount Windows tidak andal.

### 6.5 Interface

Kontrak lengkap ada di `modules/storage/ports.py`:

```python
class Collection[R: Record](Protocol):
    async def get(self, item_id: str) -> R | None: ...
    async def all(self) -> list[R]: ...
    async def put(self, item: R) -> None: ...
    async def delete(self, item_id: str) -> bool: ...
    async def update(self, item_id: str, fn: Callable[[R], R]) -> R: ...  # read-modify-write dalam satu lock

class BlobStore(Protocol): ...   # read / write / delete bytes secara atomic
class Locker(Protocol): ...      # lock(name) -> async context manager, berlaku lintas proses
```

Implementasi `Collection` wajib lulus `tests/contracts/collection.py::CollectionContract`.

## 7. Spesifikasi enkripsi

### 7.1 Master key

- 32 byte acak dari `secrets.token_bytes(32)`, dibuat oleh `agw init`.
- Disimpan sebagai file base64 di luar `var/`, diberikan ke container sebagai Docker secret (`/run/secrets/agw_master_key`).
- Path dikonfigurasi lewat env `AGW_MASTER_KEY_FILE`.
- Tidak pernah di-log, tidak pernah dikembalikan oleh API/MCP, tidak pernah ditulis ke `var/`.
- Gateway gagal start jika key tidak ada atau panjangnya bukan 32 byte.

### 7.2 Derivasi subkey

HKDF-SHA256 dari master key, salt kosong, `info` berbeda per kegunaan:

| Subkey | `info` | Kegunaan |
| ------ | ------ | -------- |
| `k_cred` | `agw/credentials/v1` | Enkripsi credential |
| `k_token` | `agw/token-hmac/v1` | HMAC token agent |
| `k_audit` | `agw/audit-anchor/v1` | HMAC anchor audit (opsional) |

### 7.3 Format envelope credential (`cred_<id>.bin`)

```
offset  ukuran  isi
0       4       magic "AGWC"
4       1       format version (0x01)
5       1       key version (0x01)
6       12      nonce acak (96-bit)
18      n       ciphertext + GCM tag (16 byte)
```

- Algoritma: AES-256-GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).
- AAD: `b"agw-cred|" + credential_id + b"|" + str(credential_version)`. Ini mencegah file credential ditukar ke id lain.
- Nonce baru setiap kali enkripsi; tidak pernah dipakai ulang dengan key yang sama.
- Plaintext adalah JSON (`{"type": "ssh_private_key", "value": "...", ...}`).

### 7.4 Rotasi key

`agw rotate-master-key --new-key-file <path>`: dekripsi semua credential dengan key lama, enkripsi ulang dengan key baru (key version +1), tulis secara atomic per file. Karena hash token memakai `k_token` yang diturunkan dari master key dan plaintext token tidak disimpan, hash lama tidak bisa dihitung ulang: rotasi master key **mencabut semua token** dan semua token harus di-reissue. Ini perilaku yang disengaja.

### 7.5 Penanganan plaintext di memori

- Plaintext credential hanya hidup di dalam `ActionContext` selama eksekusi broker. Pengecualian fase 4: `modules/model_endpoints` membuka credential resource `model` (`CredentialStore.open`) hanya selama satu panggilan upstream, lalu `wipe()`; nilainya ikut diredaksi dari jawaban model.
- Disimpan sebagai `bytearray` / `SecretStr` dan dihapus referensinya setelah broker selesai.
- `__repr__` dari objek secret selalu `"***"`.

## 8. Data schema

Contoh berikut menunjukkan isi satu item di dalam `items`.

### 8.1 Agent (`agents.json`)

```json
{
  "id": "agt_01JB8...",
  "name": "claude-devops",
  "description": "Claude Code agent for homelab ops",
  "roles": ["operator"],
  "status": "active",
  "created_at": "2026-10-31T10:00:00Z"
}
```

`status`: `active` | `disabled`.

### 8.2 Token (`tokens.json`)

```json
{
  "id": "tok_01JB8...",
  "agent_id": "agt_01JB8...",
  "kind": "agent",
  "hash": "hex(HMAC-SHA256(k_token, secret))",
  "prefix": "agw_tok_01JB8",
  "created_at": "2026-10-31T10:00:00Z",
  "expires_at": null,
  "last_used_at": null,
  "revoked_at": null
}
```

`kind`: `agent` | `admin`. Token admin dipakai manusia untuk endpoint `/v1/admin/*` dan approval.

### 8.3 Role (`roles.json`)

```json
{
  "id": "operator",
  "description": "Can operate services, cannot change infrastructure",
  "actions": ["ssh.service.status", "ssh.service.restart", "docker.container.*"]
}
```

Pola action mendukung wildcard `*` hanya di segmen terakhir.

### 8.4 Policy (`policies.json`)

```json
{
  "id": "pol_01JB8...",
  "name": null,
  "subject": { "agent_id": "agt_01JB8..." },
  "actions": ["ssh.service.restart"],
  "resources": { "ids": ["res_homelab1"], "tags": ["env:staging"] },
  "effect": "allow",
  "approval": "by_risk",
  "expires_at": null
}
```

- `subject`: tepat satu dari `agent_id`, `role` (role agent), `user` (klaim `sub` user, fase 4), atau `user_role` (role user dari `users.json`, fase 4). Subjek `user` dan `user_role` hanya berlaku untuk panggilan dengan `X-User-Token` (§10.3); policy lama tidak berubah artinya.
- `effect`: `allow` | `deny`.
- `approval`: `never` | `always` | `by_risk` (default: ikut `risk` action) | `requester` (fase 4, diputuskan oleh user peminta, §13b).
- Resource cocok jika id ada di `ids` **atau** semua tag di `tags` dimiliki resource.
- `name` (opsional, fase 4, slice 9): kunci idempoten `agw apply` (§20.6). `null` untuk policy yang dibuat CLI atau REST. Policy fase 2 tanpa field ini tetap terbaca.

### 8.5 Resource (`resources.json`)

```json
{
  "id": "res_homelab1",
  "type": "ssh_host",
  "name": "homelab-1",
  "tags": ["env:prod", "site:home"],
  "attributes": {
    "host": "192.168.1.10",
    "port": 22,
    "username": "deploy",
    "host_key_fingerprint": "SHA256:...",
    "host_key_algorithm": "ssh-ed25519",
    "allowed_services": ["nginx", "app"]
  },
  "credential_id": "cred_01JB8..."
}
```

`type` yang dikenal: `ssh_host`, `docker_host`, `github_repo`, `cloudflare_zone`, `http_endpoint`, serta untuk fase 4 `sql_database` (broker `sql`, slice 6), `smtp_server` (broker `smtp`, slice 7), dan `model` (endpoint model, slice 10). `attributes` divalidasi oleh schema per type yang didaftarkan broker.

#### Resource `model` (fase 4, slice 10)

Satu resource `model` = **satu model persis**. `name` resource adalah nama model yang dipakai aplikasi (mis. `default`). Schema atributnya didaftarkan oleh `runtime.py` dari `modules/model_endpoints/models.py` (bukan broker):

```json
{
  "id": "res_01JB8...",
  "type": "model",
  "name": "default",
  "tags": ["env:practice"],
  "attributes": {
    "base_url": "http://vllm:8000",
    "model_id": "vllm:qwen3-32b@rev-2f4c1a9",
    "options": { "chat_template_kwargs": { "enable_thinking": false }, "reasoning_effort": "none" },
    "timeout_seconds": 60
  },
  "credential_id": "cred_01JB8..."
}
```

- `base_url`: root server OpenAI-compatible (`http`/`https`, tanpa `/` di akhir); gateway memanggil `<base_url>/v1/chat/completions`.
- `model_id`: model upstream persis, dikirim sebagai field `model`. Alias `latest` (atau tag `:latest`) ditolak saat validasi (K1).
- `options` (opsional): field body tambahan yang digabung ke setiap request. Key `model`, `messages`, `tools`, `tool_choice`, dan `stream` ditolak agar opsi tidak bisa mengganti model atau mengaktifkan streaming.
- `timeout_seconds` (default 60, 1–600): timeout panggilan upstream.
- `credential_id` (opsional): credential `api_token`; nilainya dikirim sebagai `Authorization: Bearer <value>` dan tidak pernah keluar dari gateway.

### 8.6 Credential metadata (`credentials.json`)

```json
{
  "id": "cred_01JB8...",
  "type": "ssh_private_key",
  "name": "homelab deploy key",
  "version": 1,
  "key_version": 1,
  "created_at": "2026-10-31T10:00:00Z",
  "rotated_at": null
}
```

`type`: `ssh_private_key`, `api_token`, `basic_auth`, `docker_tls`.

### 8.7 Execution (`executions/<yyyy-mm>/exe_<id>.json`)

```json
{
  "id": "exe_01JB8...",
  "agent_id": "agt_01JB8...",
  "action": "ssh.service.restart",
  "resource_id": "res_homelab1",
  "params": { "service": "nginx" },
  "params_digest": "sha256:...",
  "idempotency_key": "optional-client-key",
  "status": "succeeded",
  "decision": { "effect": "allow", "approval_required": true, "policy_id": "pol_..." },
  "approval_id": "apr_01JB8...",
  "result": { "exit_code": 0, "stdout": "...", "stderr": "" },
  "error": null,
  "created_at": "...",
  "started_at": "...",
  "finished_at": "...",
  "correlation_id": null
}
```

`status`: `pending_approval` → `approved` → `running` → `succeeded` | `failed`; atau `denied` | `rejected` | `expired`.

Fase 4: `user_subject` (opsional, default `null`) berisi `sub` user bila execution diminta atas nama user (§9.4). `correlation_id` (opsional, default `null`) adalah id yang dikirim pemanggil (§12). Keduanya opsional, jadi execution fase 2 tetap terbaca tanpa migrasi.

### 8.8 Approval (`approvals.json`)

```json
{
  "id": "apr_01JB8...",
  "execution_id": "exe_01JB8...",
  "params_digest": "sha256:...",
  "status": "pending",
  "requested_at": "...",
  "expires_at": "...",
  "decided_by": null,
  "decided_at": null,
  "reason": null,
  "mode": "admin",
  "requester": null
}
```

Fase 4: `mode` (`admin` | `requester`, default `admin`) menyatakan siapa yang memutuskan; `requester` berisi `sub` user peminta bila `mode=requester` (§13b). Keduanya opsional, jadi approval fase 2 tetap terbaca sebagai approval admin. Execution menyimpan pilihan yang sama di `decision.approver`.

### 8.9 User (`users.json`, fase 4)

Catatan gateway tentang siapa boleh apa untuk user aplikasi (kontrak `agentgate-gateway/1` §8). Gateway tidak menyimpan nama user atau password; ia hanya mencocokkan klaim token OIDC yang sudah diverifikasi.

```json
{
  "id": "usr_01JB8...",
  "match": { "group": "staff" },
  "roles": ["staff"]
}
```

- `match` berisi tepat satu dari `subject` (klaim `sub` sama persis) atau `group` (ada di klaim grup token).
- Role user = gabungan role semua item yang cocok. Tidak ada yang cocok → role kosong (bukan error).
- File baru; `var/` fase 2 tanpa `users.json` tetap terbaca (koleksi kosong).
- Dikelola admin: `agw user add --group staff --role staff`, `agw user add --subject <sub> --role author`, `agw user list`, `agw user delete <usr_id>`, dan `agw apply` (§20.6). Setiap perubahan diaudit `user.updated`.

## 9. Authentication

### 9.1 Format token

```
agw_<token_id>_<secret>        dengan token_id = tok_<ULID>
```

- `secret`: 32 byte acak, base64url tanpa padding (bisa mengandung `_`).
- Parse dengan `split("_", 3)` → `["agw", "tok", "<ULID>", "<secret>"]`.
- Contoh: `agw_tok_01JB8XYZ..._q2V...`.
- Jenis token (`agent` / `admin`) tidak tercantum di string token; jenisnya dibaca dari `tokens.json`.
- Plaintext hanya ditampilkan sekali saat dibuat.

### 9.2 Verifikasi

1. Ambil header `Authorization: Bearer <token>`.
2. Parse `token_id`; lookup di `tokens.json`.
3. Hitung `HMAC-SHA256(k_token, secret)`; bandingkan dengan `hmac.compare_digest`.
4. Tolak jika `revoked_at`, `expires_at` lewat, atau agent `disabled`.
5. Update `last_used_at` (maksimal sekali per menit per token untuk mengurangi tulis).
6. Semua kegagalan mengembalikan `401` dengan pesan generik yang sama.

### 9.3 Rate limiting

In-memory token bucket per token dan per IP untuk kegagalan autentikasi (default 10 gagal/menit per IP → `429`).

### 9.4 Identitas user (`X-User-Token`, fase 4)

Aplikasi yang memanggil gateway untuk seorang user (agentgate) mengirim access token OIDC user itu apa adanya di header `X-User-Token`, di samping token agent di `Authorization` (`modules/identity/users.py`).

1. Header hanya diterima bersama token **agent** yang valid. Bersama token admin → `403`.
2. Verifikasi JWT: signature dengan kunci dari JWKS (`users.oidc.jwks_url`), algoritma dari daftar yang diizinkan (default `RS256`, `ES256`; `none` dan HMAC selalu ditolak), `iss` = `users.oidc.issuer`, `aud` memuat `users.oidc.audience`, `exp` wajib dan belum lewat (leeway `users.oidc.leeway_seconds`), `sub` wajib.
3. JWKS di-cache (`users.oidc.jwks_cache_seconds`); `kid` yang tidak dikenal memicu satu kali refresh, paling sering sekali per 30 detik.
4. Gagal verifikasi, atau header ada padahal `users.oidc` tidak dikonfigurasi → `401 unauthenticated` dengan pesan generik, dihitung rate limit dan diaudit `auth.failed` seperti token agent.
5. Subject dan grup (klaim `users.oidc.groups_claim`, default `groups`) dicocokkan ke `users.json` (§8.9). Hasilnya principal **user atas nama agent**: `Principal.user = {subject, user_ids, roles}` di samping identitas agent.
6. Tanpa header, principal persis seperti fase 2 (D14).

Di slice 2 identitas user baru dibawa dan dicatat (`GET /v1/whoami`, field `user_subject` pada execution, detail audit `execution.requested`); pembatasan scope user ∩ agent ada di slice 3 (§10).

## 10. Authorization

### 10.1 Input & output

```python
@dataclass(frozen=True)
class Decision:
    effect: Literal["allow", "deny"]
    approval_required: bool
    policy_id: str | None
    reason: str
```

`authorize(agent, action_def, resource) -> Decision`

### 10.2 Algoritma

1. Jika agent tidak punya role yang mencakup action → `deny` (`"action not in agent roles"`).
2. Kumpulkan policy yang cocok dengan subject (agent id atau salah satu role), action, dan resource, serta belum expired.
3. Jika ada policy `deny` yang cocok → `deny`. Deny selalu menang.
4. Jika tidak ada policy `allow` yang cocok → `deny` (default deny).
5. Jika ada `allow`, tentukan approval dari policy yang paling ketat:
   - `always` → wajib approval.
   - `by_risk` → wajib jika `risk` action adalah `high`, atau `medium` dan resource bertag `env:prod`.
   - `never` → tidak perlu approval, **kecuali** action ber-risk `critical` yang selalu wajib approval.
6. `resource.type` harus cocok dengan `action_def.resource_type`, jika tidak → `deny`.

Keputusan bersifat murni (tanpa I/O) agar mudah di-test.

### 10.3 Delegasi: agent atas nama user (fase 4)

Bila principal membawa user (§9.4), scope = **user ∩ agent**. Langkah 1–6 di atas dijalankan untuk sisi agent dengan policy bersubjek `agent_id`/`role` saja, lalu sisi user ikut dinilai:

1. Role user (dari `users.json`) harus mencakup action → bila tidak, `deny` (`"action not in user roles"`). User tanpa role berarti semua action ditolak.
2. Policy sisi user = policy bersubjek `user` (sama dengan `sub`) atau `user_role` (salah satu role user), belum expired, cocok action dan resource.
3. `deny` di sisi mana pun → `deny`. Deny selalu menang.
4. Sisi user tanpa `allow` yang cocok → `deny` (`"no matching allow policy for user"`).
5. Approval = yang paling ketat dari semua `allow` yang cocok di kedua sisi.

Tanpa user, policy bersubjek `user`/`user_role` tidak pernah cocok, sehingga keputusan sama persis dengan fase 2 (D14).

Visibilitas mengikuti scope yang sama: `GET /v1/actions` dan `tools/list` di `/mcp/actions` hanya memuat action yang tercakup role agent dan role user; `GET /v1/resources` hanya resource yang dipilih `allow` di kedua sisi. Execution yang diminta atas nama user hanya terlihat oleh user itu (`get`/`list` dengan `X-User-Token` difilter `user_subject`); panggilan agent saja tetap melihat semua execution agent itu.

### 10.4 Izin model (`model.chat`, fase 4)

Izin memakai model tidak punya mekanisme sendiri; ia memakai role dan policy biasa lewat satu `ActionDefinition` tetap `model.chat` (broker `model`, risk `low`, `resource_type` `model`) di `modules/model_endpoints/models.py`.

- `model.chat` **tidak didaftarkan** di action registry, sehingga tidak muncul di `GET /v1/actions`, tidak menjadi tool MCP, dan tidak bisa di-submit lewat `POST /v1/executions` (P4 tetap berlaku untuk action biasa).
- Role dan policy memberi `model.chat` pada resource `model` seperti action lain (`agw role set app -a model.chat`, policy `actions: ["model.chat"]` dengan `resources.ids`/`tags`). Wildcard `model.*` juga mencakupnya.
- Keputusan dibuat oleh `DefaultPolicyEngine` dengan principal pemanggil, jadi scope user ∩ agent (§10.3) berlaku persis sama.
- Keputusan `allow` yang mewajibkan approval diperlakukan sebagai **deny**: satu giliran chat tidak bisa menunggu approval. Admin memakai `approval: never` (atau `by_risk`, karena risk `low` tidak pernah butuh approval) untuk policy model.

## 11. Action Registry & Broker interface

### 11.1 Definisi action

```python
class ActionDefinition(BaseModel):
    id: str  # "ssh.service.restart"
    broker: str  # "ssh"
    resource_type: str  # "ssh_host"
    description: str  # dipakai sebagai deskripsi tool MCP
    risk: Literal["low", "medium", "high", "critical"]
    input_model: type[BaseModel]  # schema parameter, extra="forbid"
    timeout_seconds: int = 60
    read_only: bool = False  # True hanya bila action tidak pernah mengubah apa pun
```

Action didaftarkan dari kode broker:

```python
@registry.action(
    id="ssh.service.restart",
    resource_type="ssh_host",
    risk="medium",
    description="Restart a systemd service listed in the host's allowed_services.",
)
async def restart_service(ctx: ActionContext, params: ServiceParams) -> ActionResult: ...
```

Action yang tidak ingin diaktifkan dapat dimatikan via config (`actions.disabled`), tetapi config **tidak bisa** mendefinisikan action baru.

### 11.2 Kontrak broker

```python
class ActionContext:
    execution_id: str
    agent_id: str
    resource: Resource
    credential: SecretPayload | None  # sudah didekripsi oleh execution engine
    timeout_seconds: int
    logger: BoundLogger  # logger yang otomatis meredaksi secret


class ActionResult(BaseModel):
    ok: bool
    data: dict[str, Any]  # output yang aman untuk agent
    truncated: bool = False
```

Aturan broker:

- Tidak menerima string perintah dari agent. Parameter selalu bertipe dan divalidasi.
- Nilai parameter yang dipakai di perintah harus berasal dari allowlist di `resource.attributes` atau lolos regex ketat, lalu di-quote (`shlex.quote`).
- Output dipotong (default 64 KiB) dan disanitasi: credential yang dipakai di-redact jika muncul di output.
- Exception broker dibungkus menjadi `ActionResult(ok=False)` dengan pesan aman; stack trace hanya ke log server.

### 11.3 Action awal (Fase 1, jalur B)

#### Action privileged dan cara mencabutnya

`ssh.sudo` memberi agent akses root penuh, jadi izinnya berlapis dan setiap lapisan bisa ditarik sendiri:

| Lapisan | Memberi | Mencabut (berlaku seketika) |
| ------- | ------- | --------------------------- |
| Role | `agw role set <role> -a "ssh.*" -a ssh.sudo` | `agw role set <role> -a "ssh.*"` |
| Policy | `agw policy add -a ssh.sudo --role <role> --resource <res_id>` | `agw policy delete <pol_id>` |
| Resource | `agw resource sudo <res_id> --enable` | `agw resource sudo <res_id> --disable` |
| Agent | – | `agw agent disable <agt_id>` atau `agw token revoke <tok_id>` |
| Server | file `/etc/sudoers.d/<user>` berisi `NOPASSWD:ALL` | `sudo rm -f /etc/sudoers.d/<user>` |

Dengan policy `by_risk` (default), setiap `ssh.sudo` menunggu approval karena risk-nya `high`. Policy `approval: never` menghilangkan approval; itu keputusan admin yang eksplisit. Perintah lengkap tersimpan di execution (bisa dilihat admin); audit log hanya menyimpan digest-nya.

| Action id | Broker | Risk | Keterangan |
| --------- | ------ | ---- | ---------- |
| `ssh.system.info` | ssh | low | uptime, disk, memory |
| `ssh.service.status` | ssh | low | `systemctl status <service>` |
| `ssh.service.restart` | ssh | medium | `systemctl restart <service>` |
| `ssh.logs.tail` | ssh | low | `journalctl -u <service> -n <lines>` (lines ≤ 500) |
| `ssh.sudo` | ssh | high, **privileged** | `sudo -n -- bash -lc <command>`; hanya jika `allow_sudo: true` di resource dan id disebut persis di role + policy; timeout 600 detik |
| `docker.container.list` | docker | low | daftar container |
| `docker.container.logs` | docker | low | log container (tail ≤ 500) |
| `docker.container.restart` | docker | medium | restart container dalam allowlist |
| `docker.container.stop` | docker | high | stop container dalam allowlist |

`read_only` (default `false`, jadi action baru dianggap mengubah sesuatu) menentukan anotasi tool MCP (§16). Action yang tidak mengubah apa pun: `ssh.system.info`, `ssh.service.status`, `ssh.logs.tail`, `docker.container.list`, `docker.container.logs`, `sql.query`. Selain itu adalah tulis, termasuk `ssh.service.restart`, `ssh.sudo`, `docker.container.restart`, `docker.container.stop`, dan `mail.send`. Action privileged tidak boleh `read_only`.

SSH broker memakai `asyncssh`, wajib verifikasi `host_key_fingerprint` (tidak ada auto-accept). Koneksi hanya meminta algoritma `host_key_algorithm` (default `ssh-ed25519`), karena server OpenSSH punya beberapa host key dan tanpa batasan ini asyncssh menegosiasikan RSA sehingga fingerprint ed25519 tidak pernah cocok (ditemukan saat uji e2e). Docker broker memakai Docker Engine API; hanya container dengan label `agw.managed=true` atau di allowlist resource yang boleh disentuh.

### 11.4 Broker `sql` (fase 4, slice 6)

Port SQL gate "doorman" agentgate. Agent mengirim teks SQL bebas, tetapi teks itu tidak pernah sampai ke database sebelum lolos gate (parse dengan `sqlglot`, dialek PostgreSQL). Database-nya adalah resource, bukan parameter. Broker aktif hanya jika `brokers.sql.enabled: true` (§17). Engine saat ini hanya `postgres`; T-SQL (SQL Server) menyusul di langkah berikutnya dengan dialek gate dan driver sendiri.

| Action id | Broker | Risk | Keterangan |
| --------- | ------ | ---- | ---------- |
| `sql.query` | sql | low, read-only | Satu `SELECT` ke tabel di `allowed_tables`, hasil dibatasi `row_cap` baris |

Parameter (`extra="forbid"`):

| Field | Tipe | Aturan |
| ----- | ---- | ------ |
| `sql` | string | 1–20000 karakter; satu statement baca |

Atribut resource `sql_database` (`extra="forbid"`):

| Field | Default | Aturan |
| ----- | ------- | ------ |
| `engine` | `postgres` | hanya `postgres` untuk sekarang |
| `host` | – | hostname atau IP, regex ketat |
| `port` | `5432` | 1–65535 |
| `dbname` | – | `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$` |
| `username` | – | login database, `^[A-Za-z_][A-Za-z0-9_.@-]{0,62}$` |
| `schema_name` | `public` | identifier huruf kecil; semua tabel di-pin ke schema ini |
| `allowed_tables` | `[]` | nama tabel huruf kecil tanpa schema; boleh kosong (semua query ditolak) dan diisi dari katalog (§11.6). Tabel yang hilang dari katalog ditolak walau masih di sini |
| `row_cap` | `200` | 1–10000 baris per panggilan |
| `statement_timeout_ms` | `15000` | 100–50000 (di bawah timeout action 60 detik) |
| `connect_timeout_seconds` | `5` | 1–10 |
| `sslmode` | `prefer` | nilai libpq: `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full` |

```json
{
  "id": "res_salesdb",
  "type": "sql_database",
  "name": "sales-db",
  "attributes": {
    "engine": "postgres",
    "host": "db.internal",
    "port": 5432,
    "dbname": "sales",
    "username": "agw_reader",
    "schema_name": "sample",
    "allowed_tables": ["purchase_order", "purchase_order_line", "product"],
    "row_cap": 200,
    "statement_timeout_ms": 15000
  },
  "credential_id": "cred_..."
}
```

Credential: tipe `basic_auth`, nilainya adalah password login `username` (field credential lain diabaikan). Password diambil dari credential saat panggilan, tidak pernah disimpan di atribut, dan di-redact jika muncul di hasil. Login database sebaiknya juga hanya punya hak `SELECT`; gate adalah dinding pertama, bukan satu-satunya.

Aturan gate (urut, berhenti di pelanggaran pertama):

1. Tepat satu statement, dan statement itu query baca (`SELECT` atau set operation seperti `UNION`).
2. Tidak ada node tulis, DDL, command, atau `SELECT INTO` di mana pun, termasuk subquery dan CTE (`INSERT`, `UPDATE`, `DELETE`, `MERGE`, `DROP`, `CREATE`, `ALTER`, `TRUNCATE`, `COPY`, `SET`, `LOCK`, `GRANT`, transaksi, dll.).
3. Tidak ada fungsi yang membaca file, menjangkau server lain, tidur, atau mengubah state server (`pg_read_file`, `lo_import`, `dblink`, `pg_sleep`, `set_config`, `pg_terminate_backend`, `query_to_xml`, dll.).
4. Setiap tabel nyata (bukan nama CTE) ada di `allowed_tables`, tanpa referensi lintas database, dan schema-nya kosong atau sama dengan `schema_name`. Tabel lalu ditulis ulang menjadi `<schema_name>.<tabel>` agar resolusi tidak bisa dibelokkan lewat `search_path`.
5. Query dibungkus `SELECT * FROM (<query>) AS q LIMIT row_cap + 1`. Baris ekstra hanya menandai bahwa masih ada data; ia dibuang sebelum hasil dikembalikan.

Koneksi: satu sesi pendek per panggilan (psycopg) dengan `default_transaction_read_only=on`, `statement_timeout=<statement_timeout_ms>`, dan `connect_timeout`, transaksi `READ ONLY`. Query berjalan di worker thread; timeout action (60 detik) tetap membungkus semuanya.

Hasil (`ActionResult.data`):

```json
{"columns": ["doc_no", "status"], "rows": [["PO-1", "open"]], "row_count": 1, "limited": false}
```

- `rows` berupa list per baris dengan urutan `columns` (nama kolom boleh kembar, mis. `a.id, b.id`).
- `limited: true` berarti ada lebih dari `row_cap` baris; hasilnya parsial dan agent sebaiknya menyebutnya atau mengagregasi di SQL.
- Nilai dibuat aman untuk JSON: `Decimal` → int bila bulat, selain itu float; tanggal/waktu → ISO 8601; UUID dan interval → string; `bytea` → hex `\x...`; float non-finite → string; `json`/`jsonb` dan array tetap struktur JSON.
- Batas output (`execution.output_limit_bytes`) berlaku: jika JSON hasil melebihi batas, baris dibuang dari akhir, `row_count` mengikuti baris yang tersisa, dan `ActionResult.truncated: true`.

Pesan error (`ActionResult(ok=False, error=...)`, tanpa stack, secret, atau DSN):

| Kondisi | Pesan |
| ------- | ----- |
| SQL tidak bisa di-parse | `could not parse SQL (<jenis error parser>)` |
| SQL kosong | `empty query` |
| Lebih dari satu statement | `only a single statement is allowed` |
| Bukan query baca / ada node terlarang | `only read-only SELECT queries are allowed` |
| Fungsi terlarang | `function '<nama>' is not allowed` |
| Ekspresi tabel tak didukung | `unsupported table expression` |
| Referensi lintas database | `cross-database references are not allowed` |
| Schema lain | `schema '<schema>' is not allowed` |
| Tabel di luar allowlist | `table 'x' not in your allowed set. Tables you can query: ... Use only these — do not query, join, or reference any other table.` (semua tabel terlarang disebut sekaligus, daftar dibatasi 60 nama lalu `(+N more)`) |
| Tidak ada tabel | `query references no allowed tables` |
| Resource salah tipe / atribut invalid | `resource is not a sql_database` / `sql_database resource attributes are invalid` |
| Credential tidak ada atau bukan `basic_auth` | `sql_database resource needs a basic_auth credential` |
| Gagal konek atau login | `could not connect to the database` (detail hanya di log server) |
| `statement_timeout` terlewati | `query canceled: statement timeout of <N> ms exceeded` |
| Error lain dari database | `database error <SQLSTATE>: <pesan utama PostgreSQL>` |
| Timeout action / error tak terduga | `sql.query timed out` / `sql.query failed` |

Untuk tabel di luar allowlist, pesan menyebut daftar tabel yang boleh dipakai: daftar itu adalah scope pemanggil sendiri, jadi tidak membocorkan apa pun; pelanggaran keamanan lain (schema, katalog sistem) tidak menyebutnya.
### 11.5 Broker `smtp` (fase 4, slice 7)

Port konektor mail "doorman" agentgate (`shared/connectors/smtp.py`) ke `brokers/smtp/`. Broker ini hanya mengirim mail; tidak ada action baca kotak masuk. Memakai stdlib (`smtplib`, `email`) yang dijalankan di thread (`asyncio.to_thread`), tanpa dependency baru. Dimatikan secara default (`brokers.smtp.enabled`, §17).

| Action id | Broker | Risk | Keterangan |
| --------- | ------ | ---- | ---------- |
| `mail.send` | smtp | medium, **write** | Kirim satu mail teks ke penerima di domain yang diizinkan resource |

Nama broker `smtp`, tetapi `ActionDefinition.broker` untuk `mail.send` bernilai `mail` karena diturunkan dari segmen pertama id action (§11.1); nilai ini hanya dipakai untuk nama logger.

**Params `mail.send`** (`extra="forbid"`, sama dengan yang didukung doorman; tidak ada `cc`, `bcc`, lampiran, atau HTML):

| Field | Tipe | Aturan |
| ----- | ---- | ------ |
| `to` | list alamat (string tunggal diterima dan dijadikan list) | 1–50 alamat, spasi di tepi dibuang; tiap alamat `local@domain` polos (tanpa nama tampilan, koma, atau CR/LF), maks 254 karakter |
| `subject` | string | 1–200 karakter setelah di-trim, satu baris (tanpa karakter kontrol, termasuk CR/LF) |
| `body` | string | teks polos, 1–20.000 karakter setelah di-trim |

**Atribut resource `smtp_server`:**

| Atribut | Default | Keterangan |
| ------- | ------- | ---------- |
| `host` | – (wajib) | hostname atau IP server SMTP |
| `port` | `587` | |
| `security` | `starttls` | `starttls` (biasanya 587), `ssl` = TLS implisit (biasanya 465), atau `none` (hanya untuk server uji seperti Mailpit) |
| `from_address` | – (wajib) | alamat pengirim, divalidasi dengan pola alamat yang sama dengan `to` |
| `allowed_domains` | – (wajib, min 1) | domain penerima yang diizinkan; subdomain ikut diizinkan (`example.com` mencakup `ops.example.com`, tidak mencakup `example.com.evil.net`); disimpan huruf kecil |
| `max_recipients` | `10` | batas jumlah `to` per mail untuk resource ini (1–50) |
| `timeout_seconds` | `15` | timeout socket per operasi SMTP (1–60); seluruh action tetap dibatasi timeout action (60 detik) |

**Credential (opsional):** tipe `basic_auth`, `value` = password, field `username`. Tanpa credential broker tidak login. Credential dengan `security: none` ditolak (password tidak boleh lewat tanpa enkripsi); tipe lain atau tanpa field `username` juga ditolak.

**Hasil (`ActionResult.data`):**

```json
{ "sent_to": ["buyer@example.com"], "refused": [], "message_id": "<...@example.com>" }
```

`sent_to` = penerima yang diterima server; `refused` = penerima yang ditolak server sementara yang lain diterima (mail tetap terkirim, `ok` tetap `true` agar agent tidak mengirim ulang). Bila semua penerima ditolak → `ok=false`.

**Aturan keamanan:**

- Setiap penerima harus berada di `allowed_domains`; satu saja di luar → seluruh mail ditolak sebelum koneksi dibuka.
- Header injection ditolak: `subject` tanpa karakter kontrol, alamat hanya bentuk `local@domain` polos, `from_address` divalidasi saat resource didaftarkan. `EmailMessage` juga menolak header berisi CR/LF (lapisan kedua).
- Batas ukuran: maks 50 penerima (dan `max_recipients` resource), subject 200 karakter, body 20.000 karakter.
- TLS: sertifikat server selalu diverifikasi (`ssl.create_default_context()`). `security: starttls` **fail closed**: bila server tidak menawarkan STARTTLS, mail tidak dikirim dan login tidak dicoba.
- Error menjadi `ActionResult(ok=false, error=<pesan aman>)` (mis. `smtp authentication failed`, `smtp server does not offer STARTTLS`, `smtp TLS handshake failed`, `smtp connection failed`); teks balasan server, stack trace, dan password tidak pernah dikirim ke agent.

**Approval dan anotasi:** `mail.send` adalah tulis (`read_only` tetap `false`), jadi `destructiveHint` benar (§16). Di instance agentgate, policy-nya memakai `approval: requester` (§13b). Tanpa itu, `by_risk` tetap berlaku: risk `medium` wajib approval admin di resource bertag `env:prod`.

Perbedaan dari doorman: default `security` adalah `starttls` (doorman `none`) agar konfigurasi yang lupa diisi tetap terenkripsi; STARTTLS dicek secara eksplisit lewat `EHLO`; subject juga menolak `\r` dan karakter kontrol lain (doorman hanya `\n`); batas penerima bisa diatur per resource; header `Date` ditambahkan; penolakan sebagian penerima dilaporkan di `refused`.

### 11.6 Katalog, `agw sync`, dan broker `mcp` (kontrak admin §7)

Katalog = snapshot apa yang ditawarkan sebuah resource, dibaca dari resource itu sendiri. **Sync tidak pernah memberi izin**; ia hanya mengisi apa yang bisa dipilih admin. Implementasi: `modules/catalog/` (snapshot, diff, review, guard), sumber katalog di broker (`brokers/sql/introspect.py`, `brokers/mcp/`), REST di `apps/api_server/routes_admin_catalog.py`, CLI `agw sync` dan `agw catalog`.

**Penyimpanan.** Satu snapshot per resource di `var/catalogs.json` (`CatalogSnapshot`, key = id resource), ditulis atomic seperti collection lain. Setiap sync membuat `snapshot_id` baru (`snap_<ULID>`) dan menyimpan diff-nya (`added`, `removed`, `changed`, berdasarkan nama) terhadap snapshot sebelumnya. Sync yang gagal tidak menyentuh snapshot. Semua sync dan acknowledge diaudit (`catalog.synced`, `catalog.sync_failed`, `catalog.acknowledged`).

| Endpoint (token admin statis atau admin akses, §23) | Isi |
| -------- | --- |
| `GET /v1/admin/resources/{id}/catalog` | `Catalog`: `resource` (**nama** resource; URL tetap memakai id), `snapshot_id`, `synced_at`, `tables` atau `tools`. Belum pernah sync → `404 catalog_not_found` |
| `POST /v1/admin/resources/{id}/sync` | `SyncOut` (`added`, `removed`, `changed`, `skipped`). Resource tidak bisa dibaca → `502 sync_failed` (pesan aman), snapshot lama tetap. Tipe tanpa katalog atau broker-nya mati → `422 catalog_not_supported` |
| `POST /v1/admin/resources/{id}/catalog/acknowledge` `{"tools": [...]}` | `Catalog`. Semua atau tidak sama sekali; nama yang tidak ada atau tidak `needs_review` → `409 not_pending_review` |

CLI: `agw sync [resource]` (id atau nama; tanpa argumen = semua resource yang punya katalog; exit 1 bila ada yang gagal), `agw catalog show <resource>`, `agw catalog ack <resource> <tool>...`. Server yang sedang jalan memuat ulang action dari snapshot di setiap tick dispatcher (2 detik), sehingga sync dari CLI (proses lain) langsung berlaku.

**`sql_database`.** Dibaca dengan login resource itu sendiri (credential `basic_auth`), sesi read-only yang sama dengan `sql.query`. PostgreSQL: `pg_catalog` untuk schema `schema_name`: tabel, partitioned table induk, foreign table, view, materialized view (bukan partisi), kolom (`format_type`), nullable, dan komentar tabel/kolom. Hanya relasi yang boleh di-`SELECT` login itu, utuh (`has_table_privilege`) atau sebagian kolomnya lewat grant kolom (`has_any_column_privilege`), dan bernama identifier huruf kecil (yang bisa masuk `allowed_tables`). Kolom yang dicantumkan hanya yang boleh di-`SELECT` login itu (`has_column_privilege`), jadi kolom yang ditahan (mis. `password_hash`) tidak pernah muncul di katalog. Engine dipilih dari `attributes.engine` lewat `INTROSPECTORS`; T-SQL menambah introspector-nya sendiri di sana.

- `allowed_tables` tetap batas atas yang dicek broker dan boleh kosong (artinya semua query ditolak); isinya dipilih dari katalog lewat plan.
- Tabel yang hilang dicatat di `removed_tables` snapshot sampai muncul lagi. Selama masih ada di `allowed_tables`, broker **menolaknya** (dikurangkan dari set yang diizinkan sebelum gate) dan `ResourceView.catalog.pending_review` = `true`. Plan yang menghapusnya dari `allowed_tables` menghilangkan flag itu.

**`mcp_server` (resource type baru).** Broker `mcp` aktif hanya bila `brokers.mcp.enabled: true`.

| Atribut | Default | Aturan |
| ------- | ------- | ------ |
| `url` | – | URL `http`/`https` endpoint Streamable HTTP, tanpa userinfo, maks 2048 |
| `transport` | `streamable_http` | satu-satunya nilai |
| `timeout_seconds` | `30` | 1–55, per request ke server; timeout action 60 detik tetap membungkus satu panggilan |

Credential opsional: tipe `api_token`, dikirim sebagai `Authorization: Bearer <token>`; tipe lain ditolak. Klien = SDK MCP resmi (`streamable_http_client` + `ClientSession`), satu sesi pendek per operasi.

Sync memanggil `tools/list` (dengan paging). Setiap tool menjadi action **`mcp.<resource>.<tool>`** persis menurut kontrak §7.1 setelah amandemen A1: tiap bagian huruf kecil, selain `[a-z0-9_]` → `_`, lalu bagian yang tidak diawali `a-z` diberi awalan `t_` (`2fa-reset` → `t_2fa_reset`, `_private` → `t__private`, `über` → `t__ber`); nama tool model `.` → `_` maks 64. Nama resource yang dipakai adalah nama saat sync. **Ganti nama resource** (infra) mengubah id action-nya pada sync berikutnya; role dan policy yang menyebut id lama tidak cocok lagi, jadi grant-nya harus di-plan ulang.

| Hal | Aturan |
| --- | ------ |
| Risiko | `readOnlyHint: true` → read, risk `low`. Selain itu write: `destructiveHint: false` → `medium`, lainnya (termasuk tanpa anotasi) → `high` |
| Skema params | `inputSchema` server apa adanya; argumen divalidasi dengan JSON Schema (pesan error menyebut lokasi dan kata kunci, tidak pernah nilai input) |
| Terikat resource | Action hanya berjalan di resource asalnya (`ActionDefinition.bound_resource`); resource lain → ditolak `action belongs to another resource`. `/mcp/actions` hanya menawarkan resource itu di `enum` |
| Grant | Seperti action privileged: role dan policy harus menyebut id-nya **persis**. Wildcard (`mcp.*`, `mcp.desk.*`) tidak pernah mencakup action katalog, jadi tool baru tidak ter-grant ke siapa pun |
| Tabrakan | Dua tool yang menjadi id sama → keduanya dilewati: `skipped` `{"tool", "code": "action_collision"}` untuk masing-masing |
| Terlalu panjang | → tool itu dilewati, `code: "action_too_long"` |

Sync tidak pernah gagal karena tool yang buruk (amandemen A1): jawabannya tetap `200 SyncOut`, snapshot disimpan tanpa tool yang dilewati, tool lain berlaku. `action_collision` dan `action_too_long` bukan lagi error HTTP. CLI `agw sync` menampilkan `skipped` dan exit 0.

Hasil panggilan (`ActionResult.data`): `content` (teks, diredaksi dan dipotong ke `output_limit_bytes`), `other_content` (tipe konten non-teks), `structured` (`structuredContent`, hanya bila masih muat utuh). `isError` dari server → `ok=false`, `error = "the tool reported an error: <teks pertama, maks 300>"`. Server tidak terjangkau → `could not reach the MCP server`.

**Review.** Setiap tool menyimpan bentuk yang terakhir diterima admin (`accepted_schema_digest` = SHA-256 JSON kanonik `inputSchema`, `accepted_read_only`), diisi saat tool pertama terlihat.

| State | Kapan | Akibat |
| ----- | ----- | ------ |
| `active` | bentuk sama dengan yang diterima (atau tool baru) | jalan normal lewat engine (policy, approval, audit) |
| `needs_review` | skema input berbeda dari yang diterima, atau yang diterima read dan sekarang write | setiap panggilan ditolak, `reason: "catalog review pending"`; eksekusi yang sudah disetujui tetapi belum jalan juga gagal dengan alasan itu. Kembali ke bentuk yang diterima → `active` lagi |
| `removed` | tidak ada lagi di `tools/list` | bukan action lagi (di-unregister); tetap di snapshot dengan bentuk yang diterima, jadi kalau muncul lagi dengan bentuk lain langsung `needs_review` |

Write → read, atau perubahan deskripsi saja, tercatat di `changed` tetapi tidak perlu review. Acknowledge menerima bentuk saat ini.

**Registrasi action.** Action katalog didaftarkan ke registry sebagai grup per resource (`InMemoryActionRegistry.replace_group`): saat start dari snapshot tersimpan, setelah setiap sync, dan di tick dispatcher. Grup tidak bisa menimpa action kode atau grup lain (id bentrok dilewati dan dicatat di log); `actions.disabled` tetap berlaku. Resource yang dihapus → action-nya hilang di tick berikutnya. Guard engine (`ActionGuard`, diimplementasikan `CatalogService.refusal`) membaca snapshot di setiap panggilan; ia hanya bisa mengubah allow menjadi deny, tidak pernah sebaliknya.

**Antarmuka baca (`CatalogPort`).** Untuk API admin: `snapshot(id)`, `tables(id)` (nama tabel snapshot terakhir, `None` bila belum sync; untuk problem plan `table_not_in_catalog`), `state(resource)` (`CatalogState` untuk `ResourceView.catalog`), `catalog_actions()` (action katalog dengan id dan nama resource, state, risk, read_only; untuk `ActionInfo` `source=mcp`, `resource` = nama). Satu port ini juga dipakai API admin akses (`modules/administration/access.py`); `build_gateway` memasang `CatalogService`.

**Fixture dev.** `tests/fixtures/mcp_fixture.py`: server MCP kecil dengan tool read (`lookup_order`, `list_queues`), write non-destruktif (`create_ticket`), dan tanpa anotasi (`ping_raw`); varian `v2` mengubah skema `lookup_order`, membuat `list_queues` menjadi write, menghapus `ping_raw`, dan menambah `close_ticket`. Jalankan: `uv run python -m tests.fixtures.mcp_fixture --port 8765 [--variant v2] [--token T]`; `POST /variant` mengganti varian server yang sedang jalan.

## 12. Execution engine

`execution.submit(agent, action_id, resource_id, params, idempotency_key) -> Execution`

Pipeline:

1. **Idempotency:** jika `idempotency_key` sudah dipakai agent yang sama dalam 24 jam, kembalikan execution yang ada, beserta `correlation_id` yang tersimpan pada percobaan pertama.
2. **Resolve action:** lookup registry; tidak ada → `404 action_not_found` + audit `execution.rejected`.
3. **Validasi params:** `input_model.model_validate(params)`; gagal → `422`.
4. **Resolve resource:** tidak ada → `404`.
5. **Authorize:** `deny` → simpan execution `denied`, audit, kembalikan `403`.
6. **Approval:** jika wajib, buat approval, status `pending_approval`, audit, kembalikan `202`.
7. **Execute:** status `running` → dekripsi credential → panggil broker dengan timeout → simpan hasil → audit.
8. Kembalikan execution (`200` jika selesai sinkron).

`correlation_id` opsional. REST membacanya dari header `X-Correlation-Id`; `tools/call` (di `/mcp/actions` maupun `/mcp`) dari `_meta["agentgate/correlation_id"]`, dan dari header bila `_meta` tidak membawanya. Chat memakai header yang sama, atau field `correlation_id` di `ChatIn` (§15.4). `POST /v1/bind` menyalin header ke event `bind.checked`. Bila dua sumber ada dan berbeda, permintaan ditolak `422` (`invalid_params`) tanpa execution atau panggilan upstream. Nilainya 1–200 karakter tanpa karakter kontrol. Pada execution ia disimpan di record dan di `details.correlation_id` pada setiap event audit execution itu (termasuk approval-nya). Ia bukan bagian dari `params_digest` dan tidak mengubah idempotensi. Tanpa id, tidak ada field baru di baris audit, sehingga rantai hash fase 2 tetap sah.

Eksekusi yang sudah disetujui dijalankan sebagai background task di proses yang sama. Saat restart, execution berstatus `running` ditandai `failed` dengan error `interrupted` (tidak di-retry otomatis), sedangkan execution `approved` yang belum sempat jalan akan dijalankan.

Batas konkurensi: maksimal 1 eksekusi bersamaan per resource (lock per resource), maksimal 8 global.

Detail implementasi (Fase 2, `modules/execution/engine.py`):

- Hanya token `kind=agent` yang bisa submit; token admin ditolak `403 action_not_allowed`.
- Params yang disimpan dan di-hash adalah hasil normalisasi `input_model` (default ikut terisi), sehingga `params_digest` stabil.
- **Approval dispatcher:** server menjalankan `dispatch_approvals()` tiap 2 detik dan langsung setelah approve/reject via API. Dispatcher membaca `approvals.json`, sehingga approval dari CLI (proses lain) juga diproses. Approval `approved` → execution dijalankan; `rejected` → execution `rejected`; `expired` → execution `expired`.
- Sebelum broker dipanggil, `approval.params_digest` dicocokkan lagi dengan execution.
- Output broker disaring sekali lagi oleh engine (`redact.py`): setiap nilai credential (≥ 4 karakter) diganti `***` (pertahanan berlapis untuk P2).
- Error broker tidak pernah diteruskan ke agent; agent menerima pesan generik, detail hanya di log server.
- Penyimpanan: `FileExecutionStore`, satu file per execution; folder bulan diambil dari timestamp ULID di id.

## 13. Approval workflow

```
         submit
           │
           ▼
   ┌──────────────┐  approve   ┌──────────┐      ┌─────────┐
   │   pending    │──────────▶ │ approved │────▶ │ running │──▶ succeeded / failed
   └──────────────┘            └──────────┘      └─────────┘
      │        │
      │reject  │ TTL habis
      ▼        ▼
  rejected   expired
```

- TTL default 15 menit (`approvals.ttl_minutes`).
- Approval terikat ke `params_digest` (SHA-256 dari JSON kanonik params). Params tidak bisa diubah setelah request dibuat.
- Hanya token `kind=admin` yang bisa approve/reject. Token agent tidak pernah bisa approve, termasuk approval miliknya sendiri.
- Kanal approval di v1: **hanya** admin REST API dan CLI (`agw approvals list|approve|reject`). Keputusan 2026-10-31: tidak ada kanal notifikasi di v1. Kandidat untuk Fase 3: Telegram bot dengan long polling (tanpa port terbuka), allowlist `chat_id`, callback ber-HMAC, dan action `critical` tetap hanya lewat CLI.
- Agent mengetahui hasilnya dengan polling `GET /v1/executions/{id}` (atau tool MCP `get_execution`).
- Expiry diperiksa oleh background task tiap 30 detik dan saat approval diakses.

## 13a. Jendela sudo (elevation)

Ditambahkan 2026-11-01 (`modules/elevation/`). Tujuannya: satu approval untuk satu sesi kerja, bukan satu approval per perintah.

- Saat admin meng-approve action **privileged** (`ssh.sudo`), engine membuka **elevation** untuk pasangan (agent, resource, action) selama `approvals.elevation_minutes` (default 15, `0` = mati, maks 240).
- Selama jendela aktif, keputusan policy `allow` + `approval_required` untuk action privileged itu diubah menjadi tanpa approval; `reason` execution memuat `elevated by elv_... until ...`.
- Jendela **tidak pernah** mengubah deny menjadi allow: role, policy, `allow_sudo` di resource, dan sudoers server tetap berlaku dan tetap bisa mencabut akses seketika.
- Jendela hanya berlaku untuk agent, resource, dan action yang sama persis.
- Admin bisa menutup jendela lebih awal (UI: Approvals/Resource → "End now"; CLI: `agw elevation revoke`) atau membuka jendela manual (`agw elevation grant`, atau form di halaman resource).
- Disimpan di `var/elevations.json` (id `elv_<ULID>`). Pembukaan dan penutupan dicatat di audit (`elevation.granted`, `elevation.revoked`) sebelum disimpan (fail closed).

## 13b. Approval oleh user peminta (`requester`, fase 4)

Untuk tulis yang cukup dikonfirmasi oleh orang yang memintanya sendiri (mis. `mail.send`), policy bisa memakai `approval: requester`. Kanal keputusannya **hanya REST** dengan token user itu sendiri, tidak pernah tool MCP: semua tool MCP terlihat oleh model, dan model tidak boleh mengonfirmasi tulisannya sendiri (kontrak `agentgate-gateway/1` §6).

Siapa yang memutuskan dihitung dari semua `allow` yang cocok (§10.2, §10.3):

1. **Admin** bila ada `allow` yang menuntut approval admin (`always`, `by_risk` yang terpicu), action `critical`, atau action privileged. Admin selalu menang atas `requester`.
2. Selain itu **requester** bila ada `allow` bermode `requester`. Panggilan tanpa `X-User-Token` → `deny` (`"requester approval needs a user"`), karena tidak ada orang yang bisa mengonfirmasi.
3. Selain itu tanpa approval.

Aturan keputusan:

- `GET /v1/approvals/mine?status=` memuat approval `requester` milik `sub` user dari `X-User-Token`, untuk agent token yang sama. `POST /v1/approvals/{id}/decide` `{"decision": "confirm"|"reject"}` memutuskannya. Tanpa `X-User-Token` → `401 unauthenticated`.
- Approval user lain, approval agent lain, atau approval bermode `admin` → `404 approval_not_found` (tidak membocorkan keberadaannya). Sudah diputuskan atau kedaluwarsa → `409 approval_not_pending`.
- Saat `confirm`, policy dinilai ulang dengan role user saat ini. Bila sudah tidak diizinkan, approval ditandai `rejected` dan execution `denied`. Bila masih diizinkan, execution dijalankan sekali dan respons menunggu hasilnya.
- Approval tetap terikat `params_digest` dan TTL yang sama (§13). Admin tetap bisa approve/reject approval `requester` lewat API admin/CLI.
- Audit memakai event `approval.approved`/`approval.rejected` dengan actor `{"type": "user", "id": "<sub>"}`.
- Transisi execution `pending_approval → approved` bersifat atomik (dicek ulang di dalam lock store), sehingga dispatcher dan konfirmasi user tidak pernah menjalankan execution yang sama dua kali.

`ApprovalView` (respons kedua endpoint): `id`, `execution_id`, `tool` (nama tool MCP, §22), `summary`, `params`, `status`, `created_at`, `expires_at`, `decided_at`, `result`, `error`. Pemetaan `status`:

| Approval | Execution | `status` |
| -------- | --------- | -------- |
| `pending` | – | `pending` |
| `approved` | `succeeded`, `approved`, `running` | `confirmed` |
| `approved` | `failed` | `failed` |
| `rejected` | `denied` | `denied` |
| `rejected` | lainnya | `rejected` |
| `expired` | – | `expired` |

## 14. Audit log

### 14.1 Format entry

Satu baris JSON per event di `var/audit/<yyyy-mm-dd>.jsonl`:

```json
{
  "seq": 1042,
  "ts": "2026-10-31T10:00:00.123Z",
  "event": "execution.succeeded",
  "actor": { "type": "agent", "id": "agt_01JB8..." },
  "execution_id": "exe_01JB8...",
  "action": "ssh.service.restart",
  "resource_id": "res_homelab1",
  "params_digest": "sha256:...",
  "details": { "duration_ms": 812 },
  "prev_hash": "9f2c...",
  "hash": "a71b..."
}
```

- `hash = SHA-256(canonical_json(entry tanpa field "hash"))`.
- JSON kanonik: key diurutkan, separator `(",", ":")`, UTF-8, tanpa spasi.
- Entry pertama memakai `prev_hash` = 64 karakter `0`.
- Chain bersambung lintas file harian; `head.json` menyimpan `seq` dan `hash` terakhir.
- `params` mentah **tidak** dicatat; hanya digest. Secret tidak pernah dicatat.
- Event milik sebuah execution menyalin `correlation_id` ke `details` bila pemanggil mengirimkannya (§12). Tidak ada field baru di entry: baris lama tetap terverifikasi.

### 14.2 Event

`auth.failed`, `token.created`, `token.revoked`, `agent.created`, `agent.updated`, `resource.*`, `credential.created`, `credential.rotated`, `policy.*`, `user.updated` (fase 4), `execution.requested`, `execution.denied`, `execution.rejected`, `approval.requested`, `approval.approved`, `approval.rejected`, `approval.expired`, `execution.started`, `execution.succeeded`, `execution.failed`, serta fase 4 `model.chat` dan `bind.checked` (§15.4).

### 14.3 Verifikasi

`agw audit verify` membaca semua file berurutan, memeriksa `seq` kontinu, `prev_hash` cocok, dan `hash` benar. Output: entry pertama yang rusak atau `OK`. Endpoint `GET /v1/admin/audit/verify` menjalankan hal yang sama.

Opsional: setiap hari, gateway menulis anchor `HMAC(k_audit, head_hash)` ke log server agar penghapusan seluruh file juga terdeteksi.

### 14.4 Kegagalan audit

Jika audit tidak bisa ditulis, execution **tidak** dijalankan (fail closed).

## 15. REST API contract

Base path: `/v1`. Semua body JSON. Header `Authorization: Bearer <token>` wajib kecuali `/v1/health`.

### 15.1 Endpoint agent

| Method | Path | Keterangan |
| ------ | ---- | ---------- |
| GET | `/v1/health` | Status gateway (tanpa auth) |
| GET | `/v1/contract` | Versi kontrak yang dilayani, `{"versions": ["agentgate-gateway/1"]}` (tanpa auth, §22) |
| GET | `/v1/whoami` | Identitas agent & role |
| GET | `/v1/actions` | Action yang boleh dipakai agent ini, beserta JSON schema params |
| GET | `/v1/resources` | Resource yang bisa dipakai agent ini (tanpa atribut sensitif) |
| POST | `/v1/executions` | Submit eksekusi. Header `X-Correlation-Id` opsional (§12) |
| GET | `/v1/executions/{id}` | Status & hasil (hanya milik agent sendiri) |
| GET | `/v1/executions` | Daftar eksekusi agent sendiri (paginasi `?cursor=&limit=`) |
| GET | `/v1/approvals/mine` | Approval `requester` milik user (`?status=`), wajib `X-User-Token` (§13b) |
| POST | `/v1/approvals/{id}/decide` | `{"decision": "confirm"\|"reject"}`, wajib `X-User-Token` (§13b) |
| GET | `/v1/models` | Model yang boleh dipakai pemanggil, `[{name, model_id}]` (fase 4, §15.4) |
| POST | `/v1/models/{name}/chat` | Satu giliran chat non-streaming, `ChatIn` → `ChatOut` (fase 4, §15.4) |
| POST | `/v1/bind` | Cek nama model, tool, dan resource untuk agent ini; wajib `X-User-Token` (fase 4, §15.4) |

Request `POST /v1/executions`:

```json
{
  "action": "ssh.service.restart",
  "resource_id": "res_homelab1",
  "params": { "service": "nginx" },
  "idempotency_key": "optional"
}
```

Response: objek Execution (§8.7) dengan status HTTP `200` (selesai), `202` (menunggu approval), `403` (ditolak).

### 15.2 Endpoint admin (token `kind=admin`)

| Method | Path |
| ------ | ---- |
| GET/POST | `/v1/admin/agents` |
| PATCH | `/v1/admin/agents/{id}` (deskripsi, role, status `active`/`disabled`) |
| POST | `/v1/admin/agents/{id}/tokens` (token agent, plaintext sekali) |
| GET | `/v1/admin/tokens?agent_id=` |
| POST | `/v1/admin/tokens` (token admin, plaintext sekali) |
| DELETE | `/v1/admin/tokens/{id}` (revoke) |
| GET/POST | `/v1/admin/resources`, PATCH/DELETE `/v1/admin/resources/{id}` |
| GET | `/v1/admin/credentials` (metadata saja) |
| POST | `/v1/admin/credentials` (write-only) |
| PUT/DELETE | `/v1/admin/credentials/{id}` (PUT = rotasi, write-only) |
| GET | `/v1/admin/roles`, PUT/DELETE `/v1/admin/roles/{id}` |
| GET/POST | `/v1/admin/policies`, PUT/DELETE `/v1/admin/policies/{id}` |
| GET | `/v1/admin/approvals?status=pending` |
| POST | `/v1/admin/approvals/{id}/approve`, `/v1/admin/approvals/{id}/reject` |
| GET | `/v1/admin/audit?since=&until=&event=` |
| GET | `/v1/admin/audit/verify` |

Endpoint di atas tetap hanya untuk token admin statis. Admin akses yang login lewat OIDC (console agentgate) memakai subset baca dan endpoint plan/apply di §23; selain itu ia mendapat `403 infra_only`.

Tidak ada endpoint yang mengembalikan plaintext credential atau master key. Agent tidak bisa menghapus agent; nonaktifkan dengan `status: disabled`. Semua perubahan admin dicatat di audit oleh `modules/administration` (dipakai bersama oleh REST dan CLI).

Endpoint `/v1/resources` untuk agent hanya mengembalikan `id`, `type`, `name`, `tags` dari resource yang dipilih oleh minimal satu policy `allow` untuk agent tersebut; `attributes` dan `credential_id` tidak pernah dikirim ke agent.

### 15.3 Format error

```json
{
  "error": {
    "code": "action_not_allowed",
    "message": "Agent is not allowed to run this action on this resource.",
    "execution_id": "exe_01JB8..."
  }
}
```

| HTTP | `code` |
| ---- | ------ |
| 401 | `unauthenticated` |
| 403 | `action_not_allowed`, `admin_required` |
| 404 | `action_not_found`, `resource_not_found`, `execution_not_found`, `agent_not_found`, `credential_not_found`, `approval_not_found`, `model_not_found` |
| 409 | `approval_not_pending`, `conflict`, `names_missing` |
| 422 | `invalid_params` |
| 429 | `rate_limited` |
| 503 | `audit_unavailable` |

Error `names_missing` membawa field tambahan `missing` (`{"models": [...], "tools": [...], "resources": [...]}`) di dalam objek `error`; error lain tidak berubah bentuk.

### 15.4 Endpoint model dan cek nama (fase 4, slice 10)

Router `apps/api_server/routes_models.py`, logika model di `modules/model_endpoints/service.py`. Kontrak: `agentgate-gateway/1` §5 dan §7.

**`GET /v1/models`** → `[{"name": "default", "model_id": "vllm:qwen3-32b@rev-2f4c1a9"}]`, diurutkan menurut `name`: setiap resource `model` yang boleh di-chat pemanggil (§10.4, tanpa approval). User valid tanpa role → `[]` (`200`).

**`POST /v1/models/{name}/chat`** dengan `ChatIn` (`messages`, `tools?`, `temperature?`, `max_tokens?`, `correlation_id?`) → `ChatOut` (`status`, `message`, `usage`, `error`, `model_id`):

1. Tidak ada resource `model` bernama `name` → `404 model_not_found`.
2. Token admin, atau keputusan `deny` / butuh approval → `200` dengan `status: "denied"` dan satu baris aman (`model '<name>' is not allowed for this caller`).
3. Body upstream: `{"model": model_id, "messages": ..., **options}`, lalu `tools` (+ `tool_choice: "auto"`), `temperature`, `max_tokens` dari `ChatIn` bila ada. Credential (bila ada) dikirim sebagai Bearer.
4. Upstream gagal (koneksi, timeout, status non-2xx, JSON tidak sesuai) → `200` dengan `status: "error"` dan pesan aman (`model call failed: <jenis error>`); detail hanya di log server.
5. Berhasil → `status: "ok"`, `message` = `choices[0].message`, `usage`, dan `model_id` selalu terisi.

Isi pesan **tidak pernah disimpan**: tidak ada execution record, tidak ada teks di audit. Setiap panggilan (termasuk `404` dan `denied`) dicatat sebagai satu event `model.chat` setelah selesai, dengan `resource_id` dan `details` `{model, model_id, user, correlation_id, outcome, reason?, prompt_tokens, completion_tokens, tool_calls}` (`outcome`: `ok`, `denied`, `error`, `not_found`). Bila audit gagal ditulis, jawaban tidak dikembalikan (`503 audit_unavailable`).

**`POST /v1/bind`** dengan `BindIn {models, tools, resources}` (nama gateway) memeriksa bahwa nama-nama itu ada **untuk agent ini** (bukan untuk grant user):

- `models`: nama resource `model` yang boleh di-chat sisi agent (principal tanpa user);
- `tools`: nama tool (`.` → `_`) dari action yang tercakup role agent;
- `resources`: id resource yang terlihat oleh agent (sama dengan `GET /v1/resources` tanpa user).

Hasil: `200 {"models": {name: model_id}}`, atau `409` `{"error": {"code": "names_missing", "message": ..., "missing": {"models": [...], "tools": [...], "resources": [...]}}}` dengan daftar terurut tanpa duplikat. Syarat: token agent dan `X-User-Token` (tanpa itu `401 unauthenticated`), dan user memegang salah satu role di `bind.roles` (default `["author", "reviewer"]`, §17), selain itu `403 action_not_allowed`. Setiap panggilan diaudit sebagai `bind.checked` dengan `details` `{user, models, tools, resources, outcome, correlation_id?, missing?, bound_models?}`. `correlation_id` diisi dari header `X-Correlation-Id` (§12). (`outcome`: `ok`, `missing`, `forbidden`, `no_user`).

OpenAPI di-generate otomatis oleh FastAPI dan diekspor ke `devnote/openapi.json` pada setiap rilis.

## 16. MCP server

- Thin client: setiap tool call diterjemahkan menjadi request HTTP ke REST API memakai token agent.
- Konfigurasi via env: `AGW_URL` (default `http://127.0.0.1:8080`) dan `AGW_TOKEN`.
- Transport: `stdio` (untuk Claude Code / Claude Desktop) dan Streamable HTTP (opsional).
- Library: SDK resmi `mcp` v2 (`mcp.server.mcpserver.MCPServer`; di v2 `FastMCP` sudah diganti nama).
- MCP server tidak membaca `var/`, tidak memuat master key, dan tidak meng-import `modules/*`, `brokers/*`, atau `runtime` sama sekali (ditegakkan oleh test import).
- Hasil berupa list dibungkus objek (`{"actions": [...]}`, `{"resources": [...]}`) karena MCP memecah list menjadi beberapa item konten. Error gateway dikembalikan sebagai data (`{"error": {...}}`) agar agent tahu alasannya.

### Tool

| Tool | Input | Memanggil |
| ---- | ----- | --------- |
| `list_actions` | – | `GET /v1/actions` |
| `list_resources` | `type?` | `GET /v1/resources` |
| `execute_action` | `action`, `resource_id`, `params`, `idempotency_key?` | `POST /v1/executions` |
| `get_execution` | `execution_id` | `GET /v1/executions/{id}` |

Deskripsi `execute_action` menjelaskan bahwa respons dapat berstatus `pending_approval` dan agent harus memanggil `get_execution` untuk mengecek hasil, bukan mengulang submit.

### Endpoint `/mcp` (Streamable HTTP, utama)

Sejak 2026-11-01 gateway melayani MCP langsung di `/mcp` (`apps/api_server/mcp_http.py`), sehingga agent cukup punya URL dan token agent, tanpa repo atau program lokal:

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

- Setiap request HTTP ke `/mcp` diautentikasi (rate limit + audit `auth.failed`, sama seperti REST) sebelum sampai ke lapisan MCP. Tanpa token valid → `401`; token admin → `403`.
- Setiap tool call mengautentikasi ulang token dari header request-nya sendiri, jadi tool selalu berjalan sebagai agent pengirim. Tidak ada token yang disimpan di proses.
- Tool memanggil `ExecutionEngine` dan view yang sama dengan REST (`apps/api_server/views.py`), jadi P6 tetap terjaga.
- Mode stateless + JSON response: tidak ada sesi MCP yang disimpan di memori server.
- Proteksi DNS rebinding: hanya Host `127.0.0.1`, `localhost`, `[::1]`, plus `server.public_hosts` di config.
- Diuji di container nyata ke `tybozen-server`: `ssh.system.info` lewat `/mcp` berhasil.

### Endpoint `/mcp/actions` (tool profile, kontrak `agentgate-gateway/1`)

Untuk aplikasi seperti agentgate yang menyerahkan tool langsung ke model (`apps/api_server/mcp_actions.py`). Transport, autentikasi, mode stateless, dan proteksi DNS rebinding sama dengan `/mcp`; bedanya ada di bentuk tool:

- `tools/list`: satu tool per action yang tercakup role pemanggil (`ExecutionEngine.visible_actions`), nama = id action dengan `.` → `_` (`sql.query` → `sql_query`, pola `^[a-zA-Z0-9_-]{1,64}$`). `inputSchema` = schema params action ditambah `resource_id` wajib dengan `enum` resource yang terlihat oleh pemanggil dan bertipe sama dengan action. Action tanpa resource yang bisa ditarget tidak dicantumkan. Daftar dihitung per request, jadi selalu sesuai role dan policy saat itu.
- `tools/call`: memanggil `ExecutionEngine.submit` (P6). Argumen selain `resource_id` menjadi `params`. `_meta["agentgate/correlation_id"]` (atau header `X-Correlation-Id`) menjadi `correlation_id` execution (§12). `structuredContent` = `ToolOutcome` `{status, execution_id, result, summary, error}`: `succeeded` → `ok` (`result` = `data`), `pending_approval` → `pending` (`summary` menyebut action dan resource yang menunggu), `denied` → `denied`, lainnya → `error`. `isError` benar untuk `denied` dan `error`. Error gateway juga menjadi `ToolOutcome` (`denied` untuk `action_not_allowed`, selain itu `error`), dengan pesan aman tanpa secret.
- Nama tool yang tidak dikenal → `ToolOutcome` `error`, tanpa eksekusi.
- Anotasi: `readOnlyHint` benar bila action `read_only`; `destructiveHint` benar untuk setiap tulis (kontrak §4.1 memperlakukan semua tulis sebagai destruktif). Keduanya sifat action, tidak tergantung policy.
- `_meta["agentgate/write"]` benar bila panggilan action itu oleh pemanggil ini bisa ditahan untuk konfirmasi user (§13b) pada salah satu resource di `enum`-nya: keputusan `allow` dengan `approver=requester`, sesudah jendela elevation diperhitungkan. Tanpa user nilainya `false` (panggilan seperti itu ditolak, bukan ditahan). Approval admin atau tanpa approval juga `false`.
- Meta-tool di `/mcp` dan bridge stdio tidak berubah.

### Bridge stdio (`agw-mcp`, opsional)

Untuk client yang hanya mendukung stdio:

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

## 16a. Admin web UI (`/admin`)

Ditambahkan 2026-11-01 (`apps/admin_ui/`). Halaman HTML yang dirender server oleh FastAPI + Jinja2, di app yang sama dengan REST dan `/mcp`.

- **Login:** token admin ditempel sekali di `/admin/login`, diverifikasi dengan rate limit + audit `auth.failed` yang sama seperti REST, lalu ditukar dengan cookie sesi acak (`HttpOnly`, `SameSite=Strict`, `Path=/admin`, `Secure` di HTTPS, TTL 8 jam). Token agent ditolak. Token tidak pernah disimpan di browser.
- **Sesi:** disimpan di memori proses (satu worker), maksimal 100. Setiap request mengecek ulang bahwa token admin di balik sesi masih aktif; revoke token → sesi langsung berakhir. Restart gateway → login ulang.
- **CSRF:** setiap form POST membawa token CSRF per sesi (`secrets.compare_digest`). Test memastikan setiap form di setiap halaman membawa token yang benar.
- **Tanpa JavaScript dan tanpa aset pihak ketiga:** CSS sendiri di `static/admin.css`. Header: `Content-Security-Policy: default-src 'none'; style-src 'self'; ...` (tidak ada `script-src` sama sekali), `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`.
- **Semua perubahan lewat `AdminService`**, jadi tercatat di audit dengan actor = token admin sesi tersebut, sama seperti CLI dan REST admin.
- **Halaman:** Dashboard, Approvals (detail params + perintah root disorot, approve/reject), Executions (+ detail stdout/stderr), Agents, Tokens (token baru tampil sekali, tidak pernah lewat redirect), Resources (toggle `ssh.sudo`, allowed services, tags, hapus dengan konfirmasi id), Roles, Policies, Credentials (write-only), Audit (+ verify).
- **Belum ada:** membuat resource baru dari UI (pakai `agw-onboard-ssh`), edit policy yang sudah ada (hapus lalu buat ulang).

## 17. Konfigurasi

`config/gateway.yaml`:

```yaml
server:
  host: 0.0.0.0           # di dalam container; default di luar container 127.0.0.1
  port: 8080
var_dir: /app/var
master_key_file: /run/secrets/agw_master_key
approvals:
  ttl_minutes: 15
execution:
  max_concurrent: 8
  output_limit_bytes: 65536
audit:
  daily_anchor: true
rate_limit:
  auth_failures_per_minute: 10
actions:
  disabled: []
brokers:
  docker:
    enabled: false        # mount Docker socket = akses root ke host; aktifkan secara sadar
    socket: unix:///var/run/docker.sock
  sql:
    enabled: false        # broker sql (§11.4): action sql.query ke resource sql_database
  smtp:
    enabled: false        # broker mail.send (§11.5); aktifkan hanya di instance yang mengirim mail
  mcp:
    enabled: false        # resource mcp_server dan tool-nya sebagai action (§11.6)
users:
  oidc:                   # opsional; tanpa ini X-User-Token selalu ditolak (§9.4)
    issuer: https://idp.example.com/realms/company   # nilai klaim iss yang diharapkan
    audience: agentgate
    jwks_url: http://idp:8080/realms/company/protocol/openid-connect/certs
    groups_claim: groups
    algorithms: [RS256, ES256]
    leeway_seconds: 30
    jwks_cache_seconds: 300
bind:
  roles: [author, reviewer]   # role user yang boleh memanggil POST /v1/bind (§15.4)
admin:                        # admin akses lewat app (§23); infra, hanya file ini yang mengatur
  user_roles: [platform-admin]
  apply_requires_second_admin: false   # production: true
  directory:                  # direktori IdP read-only (§23); opsional, tanpa ini 503
    provider: keycloak
    base_url: http://keycloak:8080
    realm: agentgate-dev
    client_id: agentgate-directory
    credential: keycloak-directory     # nama credential (tipe api_token) berisi client secret
    groups_full_path: false
    timeout_seconds: 10
```

Setiap nilai bisa di-override dengan env `AGW_<SECTION>__<KEY>` (contoh `AGW_APPROVALS__TTL_MINUTES=30`). Konfigurasi divalidasi dengan Pydantic Settings saat start.

## 18. Deployment Docker

```yaml
services:
  gateway:
    build: { context: ., dockerfile: docker/Dockerfile }
    ports:
      - "127.0.0.1:8080:8080"     # hanya localhost
    volumes:
      - agw-var:/app/var
      - ./config/gateway.yaml:/app/config/gateway.yaml:ro
      # aktifkan hanya jika docker broker dipakai:
      # - /var/run/docker.sock:/var/run/docker.sock
    secrets:
      - agw_master_key
    environment:
      AGW_MASTER_KEY_FILE: /run/secrets/agw_master_key
    restart: unless-stopped

volumes:
  agw-var:

secrets:
  agw_master_key:
    file: ./secrets/master.key     # gitignored
```

- Image berbasis `python:3.12-slim`, berjalan sebagai user non-root.
- Port hanya di-bind ke `127.0.0.1`. Akses dari luar mesin wajib lewat reverse proxy dengan TLS (di luar scope v1).
- **Peringatan Docker socket:** mount `/var/run/docker.sock` setara akses root ke host. Docker broker wajib membatasi container berdasarkan label/allowlist, dan action `docker.*` ber-risk `medium` ke atas memerlukan approval di env produksi.
- `var/` memakai named volume (lihat §6.4). Backup: `agw backup` membuat arsip tar dari volume; arsip tetap terenkripsi karena credential sudah terenkripsi, tetapi master key harus di-backup terpisah.

## 19. Strategi testing

| Lapisan | Fokus | Tools |
| ------- | ----- | ----- |
| Unit | storage, crypto, policy engine, registry, audit hash | pytest, hypothesis |
| Integration | REST API end-to-end dengan broker palsu | pytest, httpx `ASGITransport` |
| Broker | SSH ke container `openssh-server`, Docker ke Docker lokal, SQL ke Postgres, SMTP ke Mailpit (`agw-broker-smtp`, port 11025/18025, terpisah dari Mailpit dev agentgate di 1025/8025) | pytest marker `@broker` |
| Security | test per prinsip P1–P7 | pytest |

Test wajib:

- **Storage:** atomic write tahan crash (simulasi exception sebelum `os.replace`), tulis konkuren tidak kehilangan update.
- **Crypto:** round-trip, AAD salah → gagal, nonce tidak berulang, tamper 1 byte → gagal.
- **Authorization:** tabel keputusan (deny menang, default deny, approval by_risk, risk critical).
- **Audit:** ubah/hapus/sisipkan satu baris → `verify` gagal di posisi yang tepat.
- **P1/P2:** scan semua response API dan output tool MCP dalam test suite; tidak boleh ada master key atau plaintext credential.
- **P3:** fuzz parameter SSH dengan karakter shell (`;`, `&&`, `` ` ``, `$()`, newline) → ditolak atau ter-quote aman.
- **P4:** action id tidak terdaftar → `404` dan tidak ada broker yang terpanggil.
- **P6:** test import-graph: `apps/mcp_server` tidak meng-import `brokers` atau `modules.execution`.
- **Approval:** token agent tidak bisa approve; params berubah → digest tidak cocok; expire berjalan.

Target coverage: ≥ 90% untuk `modules/crypto`, `modules/authorization`, `modules/audit`, `modules/storage`; ≥ 80% keseluruhan. CI: `ruff`, `mypy`, `pytest` (tanpa marker `broker`).

## 20. Rencana implementasi bertahap

Implementasi dibagi menjadi 4 fase. Fase 0 menetapkan kontrak; Fase 1 dikerjakan dalam tiga jalur paralel di atas kontrak tersebut; Fase 2 menyatukan semuanya. Setiap fase selesai jika semua kriteria terpenuhi dan `ruff`, `mypy`, `pytest` hijau.

```
Fase 0: Kontrak
     │
     ├──▶ Jalur A: Persistence & secret ─┐
     ├──▶ Jalur B: Policy & action ──────┼──▶ Fase 2: Integrasi ──▶ Fase 3: Ekspansi
     └──▶ Jalur C: Governance ───────────┘
```

### 20.1 Fase 0 — Kontrak (berurutan)

Lingkup:

- `git init`, `.gitignore` (`var/`, `secrets/`, `.venv/`), `pyproject.toml`, konfigurasi `ruff`, `mypy`, `pytest`.
- Kerangka folder §4 dengan `__init__.py`.
- `config.py` (§17) dan `config/gateway.example.yaml`.
- Semua model Pydantic §8 (`Agent`, `Token`, `Role`, `Policy`, `Resource`, `CredentialMeta`, `Execution`, `Approval`, `AuditEntry`).
- Interface tanpa implementasi: `JsonCollection` (§6.5), `Decision` (§10.1), `ActionDefinition` (§11.1), `ActionContext`, `ActionResult`, protocol `Broker` (§11.2), `SecretPayload`, serta signature fungsi publik tiap module.
- Fake untuk test: `InMemoryCollection`, `FakeCredentialStore`, `FakeAuditSink`, `FakeBroker` di `tests/fakes/`.
- Utilitas bersama: generator ID (prefix + ULID), `canonical_json()`, `utc_now()`.

Kriteria selesai: semua kontrak di-review dan di-merge; `mypy --strict` lulus; fake lulus test kontraknya sendiri.

**Aturan pembekuan kontrak:** setelah Fase 0 di-merge, file kontrak hanya boleh diubah lewat perubahan kecil tersendiri yang di-merge ke `main` terlebih dahulu, lalu jalur lain melakukan rebase. Jalur tidak boleh mengubah kontrak di branch-nya sendiri.

### 20.2 Fase 1 — Tiga jalur paralel

Setiap jalur dikerjakan di branch/worktree sendiri dan hanya menyentuh folder miliknya.

| Jalur | Branch | Folder yang dimiliki | Lingkup | Kriteria selesai |
| ----- | ------ | -------------------- | ------- | ---------------- |
| A. Persistence & secret | `track/a-persistence` | `modules/storage`, `crypto`, `identity`, `credentials`, `resources` | Atomic write & lock (§6), enkripsi & HKDF (§7), token & autentikasi (§9), credential store, resource registry | Test crash-safety & konkurensi storage lulus; round-trip & tamper test crypto lulus; token bisa dibuat & diverifikasi |
| B. Policy & action | `track/b-policy-action` | `modules/authorization`, `action_registry`, `brokers/` | Policy engine murni (§10), registry & validasi input (§11.1), SSH broker & Docker broker dengan action §11.3 | Tabel keputusan policy lulus; fuzz parameter SSH (P3) lulus; broker test ke container `openssh-server` lulus |
| C. Governance | `track/c-governance` | `modules/audit`, `approvals` | Writer & verifier hash chain (§14), state machine approval & expiry (§13) | Tamper test audit lulus; transisi status approval & TTL lulus |

Aturan:

- Jalur B dan C memakai fake dari Fase 0, bukan implementasi jalur A.
- Tidak ada jalur yang menyentuh `modules/execution`, `apps/`, atau `cli.py`.
- Jalur A paling kritis untuk keamanan; review `crypto` dan `storage` dilakukan paling teliti sebelum merge.
- Urutan merge ke `main`: A → C → B (B paling besar dan paling mungkin perlu rebase).

### 20.3 Fase 2 — Integrasi (berurutan)

Lingkup:

- `modules/execution` (§12) yang menyatukan jalur A, B, C dan mengganti fake dengan implementasi nyata.
- REST API lengkap (§15), MCP server (§16), CLI `agw` (`init`, `agent`, `token`, `resource`, `credential`, `policy`, `approvals`, `audit verify`, `backup`, `rotate-master-key`).
- `docker/Dockerfile`, `docker-compose.yml` (§18).
- Test keamanan P1–P7 (§19) dan test integrasi end-to-end.

Kriteria selesai: Claude Code bisa memanggil `execute_action` via MCP ke gateway yang berjalan di Docker; action ber-risk `medium` di resource `env:prod` menunggu approval dan bisa di-approve via CLI; `agw audit verify` mengembalikan `OK`; semua test P1–P7 lulus.

**Status (2026-11-01):**

| Item | Status |
| ---- | ------ |
| Execution engine, store, dispatcher approval, recovery | selesai |
| `modules/administration` (operasi admin ber-audit, dipakai REST + CLI) | selesai |
| `runtime.py` (composition root) | selesai |
| REST API agent + admin, rate limit gagal-auth, audit `auth.failed` | selesai |
| MCP server: endpoint `/mcp` di gateway (HTTP, utama) dan bridge stdio `agw-mcp` | selesai |
| Admin web UI di `/admin` (§16a) | selesai |
| Action privileged `ssh.sudo` dengan izin berlapis yang bisa dicabut (§1 P3, §11.3) | selesai |
| Jendela sudo 15 menit setelah approval (§13a) | selesai |
| CLI: `keygen`, `init`, `serve`, `agent`, `token`, `resource`, `credential`, `role`, `policy`, `approvals`, `audit verify` | selesai |
| CLI: `backup`, `rotate-master-key` | **belum** |
| Anchor HMAC harian audit (§14.3) | **belum** (TODO di `file_log.py`) |
| Dockerfile + compose | selesai, image ter-build dan berjalan |
| Test P1–P7 + integrasi REST/MCP/CLI | selesai |
| Uji e2e: image Docker + server OpenSSH nyata, via REST, CLI, dan MCP stdio (`tests/e2e/run_e2e.py`, 16 cek) | selesai |
| Uji langsung dari Claude Code ke host milik sendiri | **belum** |
| `agw-onboard-ssh`: onboarding host SSH interaktif lewat admin API (key, cek host key, cek authorized_keys, penamaan `<base>-server/-key/-operator/-agent`, registrasi, uji `ssh.system.info`) | selesai |

Alur setup: `agw keygen --out secrets/master.key` di host → `docker compose run --rm -v "${PWD}:/host" gateway agw init --env-file /host/.env` (token admin disimpan ke `.env` sebagai `AGW_ADMIN_TOKEN`; `--no-save-env` untuk mencetaknya saja) → `docker compose up -d`.

Struktur tambahan Fase 2: `src/agent_gateway/runtime.py` adalah satu-satunya tempat yang merangkai implementasi konkret; `modules/*` tidak boleh meng-import `apps`, `cli`, atau `runtime`. Fixture gateway lengkap untuk test ada di `tests/world.py`.

Gateway **tidak boleh** dipakai pada resource produksi sebelum Fase 2 selesai.

### 20.4 Fase 3 — Ekspansi (paralel per broker)

Broker GitHub, Cloudflare, RunPod, HTTP, dan kanal notifikasi approval (§13). Setiap broker berdiri sendiri di folder `brokers/<nama>/` sehingga bisa dikerjakan paralel, masing-masing di branch `broker/<nama>`.

Kriteria selesai per broker: minimal 3 action terdaftar dengan input schema, test dengan fake/mocked API, dan dokumentasi action di `devnote/`.

### 20.5 Fase 4 — Integrasi agentgate (kontrak `agentgate-gateway/1`)

Gateway menjadi tempat semua aksi dan kredensial untuk aplikasi agentgate (console, assistant, Studio), menggantikan "doorman" milik agentgate. Desain dan keputusannya ada di repo agentgate: `devnotes/design-gateway-split-20261103.md` (K1–K8, D1–D15). Kontraknya dirangkum di §22.

Slice, masing-masing di branch sendiri, dengan SPEC diubah lebih dulu:

| # | Slice | Isi |
| - | ----- | --- |
| 1 | MCP Streamable HTTP | Endpoint `/mcp/actions` dengan bearer token agent, di samping `/mcp` dan stdio: satu tool per action, `resource_id` enum, hasil `ToolOutcome` (§16). Plus `GET /v1/contract` |
| 2 | Identitas user | Verifikasi `X-User-Token` (OIDC: JWKS, `iss`, `aud`, `exp`), `users.json` (subject/grup → role), principal *user atas nama agent*, CLI `agw user` (§8.9, §9.4) |
| 3 | Otorisasi delegasi | Scope = role user ∩ role agent; policy subject `user` dan `user_role`; visibilitas action, resource, dan execution ikut scope (§10.3) |
| 4 | Approval `requester` | Mode approval baru yang diputuskan oleh user peminta; REST `GET /v1/approvals/mine`, `POST /v1/approvals/{id}/decide` (§13b) |
| 5 | Tool profile MCP | Melengkapi `/mcp/actions` dari slice 1: anotasi `readOnlyHint` / `destructiveHint`, `_meta["agentgate/write"]` (§16; daftar tool sudah mengikuti scope user ∩ agent sejak slice 3) |
| 6 | Broker `sql` | Port SQL gate agentgate (satu `SELECT`, tabel yang diizinkan, row cap, `limited`) beserta tesnya. Postgres dulu, T-SQL menyusul |
| 7 | Broker `smtp` | Port konektor mail agentgate (domain yang diizinkan, STARTTLS), action `mail.send` risk `medium` approval `requester`. Mailpit di compose uji |
| 8 | Correlation id | Dari `X-Correlation-Id` / `_meta` ke execution dan audit (§12) |
| 9 | `agw apply <seed.yaml>` | Onboarding deklaratif dan idempoten (agent, role, policy, resource, user, referensi credential) (§20.6) |
| 10 | Endpoint model | Resource `model`, `GET /v1/models`, `POST /v1/models/{name}/chat` (non-streaming), mengembalikan `model_id` persis |

**Tidak boleh terganggu (gate setiap slice):**
- Broker SSH dan Docker tidak disentuh.
- Tanpa `X-User-Token`, keputusan otorisasi sama seperti fase 2.
- Meta-tool MCP dan transport stdio tetap ada.
- Approval admin tetap.
- `var/` fase 2 tetap terbaca (migrasi berurutan bila `schema_version` naik).
- e2e SSH `tests/e2e/run_e2e.py` (16 cek) dan tes P1–P7 lulus.

Instance gateway untuk agentgate terpisah dari instance homelab, dengan master key, `var/`, dan onboarding sendiri, serta `ssh.*` dan `docker.*` dimatikan lewat `actions.disabled`.

Kriteria selesai fase 4: tes kontrak agentgate (`e2e/contract/` di repo agentgate) lulus terhadap image gateway bertag, dan gate di atas lulus.

### 20.6 `agw apply` (fase 4, slice 9)

`agw apply <seed.yaml>` membuat atau memperbarui isi satu instance supaya sama dengan file seed. Menjalankan file yang sama untuk kedua kali tidak mengubah data dan tidak menambah baris audit. Objek yang tidak disebut di seed dibiarkan: perintah ini tidak menghapus. CLI imperatif (`agw agent`, `agw role`, `agw policy`, ...) dan `agw-onboard-ssh` tetap. Perintah ini tidak menerbitkan token; token tetap lewat `agw token create`. `actions.disabled` tetap config instance, bukan isi seed.

Seed adalah YAML. Field yang tidak dikenal ditolak. Secret tidak pernah ditulis di seed. Credential menyebut tepat satu dari `secret_env` (nama variabel environment) atau `secret_file` (path; relatif terhadap file seed bila tidak absolut). Isi file adalah teks secret; satu newline di akhir dibuang. Nilai kosong ditolak. Plaintext secret tidak masuk laporan, audit, atau pesan error. Membandingkan secret yang sudah tersimpan membuka amplop di proses admin (yang memang memegang master key) lalu menghapus plaintext dari memori.

Identitas pencocokan, dan apa yang diperbarui bila objek itu sudah ada:

| Jenis | Identitas | Bila sudah ada |
| ----- | --------- | -------------- |
| role | `id` | `description` dan `actions` |
| agent | `name` | `description`, `roles`, `status` |
| user | `subject` atau `group` | `roles`; `id` user tidak berubah |
| credential | `name` | dibiarkan bila tipe, nilai, dan field sama; bila secret beda, dirotasi (versi naik). Tipe yang beda ditolak |
| resource | `name` | tag, atribut, dan credential. Tipe yang beda ditolak. Credential yang tidak disebut lagi dilepas |
| policy | `name` | subjek, action, resource, effect, approval, `expires_at`. Policy tanpa `name` tidak diikuti |

`name` policy disimpan di `policies.json` (§8.4).

Acuan dicek sebelum ada yang ditulis. Yang harus sudah ada di seed atau di data tersimpan: role yang disebut agent, user, atau subjek policy; nama agent pada subjek policy; nama resource pada policy; nama credential pada resource. Nama yang tidak ketemu ditolak, dan tidak ada yang ditulis. Nama ganda di dalam seed, atau lebih dari satu objek tersimpan dengan identitas yang sama, ditolak.

Urutan tulis: credential, role, user, agent, resource, policy. Atribut resource divalidasi dengan schema yang terdaftar di proses ini. `sql_database` dan `smtp_server` hanya bisa dipakai bila broker-nya enabled, karena schema atributnya didaftarkan broker itu.

Laporan JSON berisi `changes`. Tiap item punya `kind`, `name`, dan `result` (`created`, `updated`, atau `unchanged`). Untuk user, `name` berbentuk `group:<grup>` atau `subject:<sub>`.

Bentuk seed (tanpa secret) ada di `config/seed.example.yaml`. Seed dev agentgate — agent `agentgate-practice` dan `agentgate-production`, role dan policy `sql.*` / `mail.*` / `model.*`, user staff/author/reviewer/lead, resource DB contoh, Mailpit, dan model dev — menyusul di repo agentgate dan memakai perintah yang sama.

## 21. Pertanyaan terbuka

1. **Kanal approval tambahan (Fase 3):** kandidat utama Telegram bot long polling (lihat §13). Diputuskan setelah v1 dipakai.
2. **Multi-admin:** apakah perlu lebih dari satu admin dengan role berbeda (mis. approver vs. pengelola credential)?
3. **Akses remote:** apakah gateway akan diakses dari luar mesin (mis. via Cloudflare Tunnel)? Jika ya, perlu TLS dan mungkin mTLS.
4. **Retensi:** berapa lama file `executions/` dan `audit/` disimpan? Usulan default: execution 90 hari, audit tanpa batas.
5. **Output sensitif:** apakah output log (`ssh.logs.tail`, `docker.container.logs`) perlu filter redaksi pola secret umum (token, password)?

## 22. Kontrak `agentgate-gateway/1`

Sumber kebenaran kontrak ada di repo agentgate: `app/docs/gateway-contract.md` (bahasa Inggris), dengan tipe wire di `packages/contracts/src/agentgate_contracts/gateway.py` dan tes kesesuaian di `e2e/contract/`. Ringkasan untuk implementasi gateway:

| Bagian | Isi |
| ------ | --- |
| Versi | `GET /v1/contract` tanpa auth → `{"versions": ["agentgate-gateway/1"]}` |
| Identitas | `Authorization: Bearer <token agent>` selalu; `X-User-Token: <access token OIDC user>` bila panggilan untuk user; `X-Correlation-Id` opsional, disimpan di execution dan audit (§12). Token user palsu atau kedaluwarsa → `401`; user valid yang tidak ada di `users.json` → scope kosong |
| Role user (§3.1, 12 Nov) | `GET /v1/whoami` dengan header di atas → `user: {subject, roles}` bila ada `X-User-Token`, else `null`. `user.roles` = gabungan semua item `users.json` yang cocok. App memakainya untuk surface console (role bernama sama dengan persona, dibaca dari gateway environment surface itu). Sudah dilayani sejak fase 4; tidak ada perubahan kode |
| Tool (MCP) | `/mcp/actions`, Streamable HTTP. `tools/list`: satu tool per action yang boleh dipakai pemanggil, dengan nama `^[a-zA-Z0-9_-]{1,64}$` (titik → garis bawah) dan `resource_id` enum di `inputSchema`. `tools/call` → `structuredContent` = `ToolOutcome` (`ok`, `pending`, `denied`, `error`), dari status execution: `succeeded` → `ok`, `pending_approval` → `pending`, `denied` → `denied`, lainnya → `error` |
| Model | `GET /v1/models` → `[{name, model_id}]`; `POST /v1/models/{name}/chat` dengan `ChatIn` → `ChatOut` (selalu ada `model_id` bila `ok`). Nama yang tidak boleh dipakai → `status: denied`; nama tak dikenal → `404 model_not_found` |
| Approval user | `GET /v1/approvals/mine?status=` dan `POST /v1/approvals/{id}/decide` `{"decision": "confirm"\|"reject"}`, wajib `X-User-Token` (tanpa itu `401`). Approval orang lain atau mode admin → `404 approval_not_found`; sudah diputuskan → `409 approval_not_pending`. **Tidak pernah tersedia sebagai tool MCP** |
| Cek nama | `POST /v1/bind` `{models, tools, resources}` → `200 {models: {name: model_id}}` atau `409 names_missing` dengan daftar yang hilang; diaudit; butuh user author atau reviewer |
| `users.json` | Item `{id, match: {subject} \| {group}, roles}`; role user = gabungan semua item yang cocok |
| Error | `{"error": {"code", "message"}}` dengan kode §15.3, ditambah `approval_not_found`, `model_not_found`, `names_missing` |

## 23. Kontrak `agentgate-gateway-admin/1` (draf 10 Nov 2026)

Sumber kebenaran: repo agentgate, `app/docs/gateway-admin-contract.md`, tipe wire di `packages/contracts/src/agentgate_contracts/gateway_admin.py`. Desain: `devnotes/design-gateway-admin-20261110.md` di repo itu. Kontrak ini menambah, tidak mengubah §22. Ringkasan untuk implementasi gateway:

| Bagian | Isi |
| ------ | --- |
| Versi | `GET /v1/contract` mencantumkan `agentgate-gateway-admin/1` di samping `agentgate-gateway/1`. `GET /v1/admin/instance` → `{"apply_requires_second_admin", "admin_user_roles"}` (A1) |
| Admin akses | Header §22 (token agent + `X-User-Token`). User adalah admin akses bila salah satu role-nya ada di setting `admin.user_roles` (file config, infra). Token agent tanpa token user → `401` di endpoint admin akses, `403 admin_required` di endpoint infra; bukan admin → `403 not_admin`; endpoint infra → `403 infra_only`. Hak agent tidak berperan. Audit mencatat `actor.kind=user`, `actor.subject`, `actor.via_agent` |
| Sudut pandang agent pemanggil | Lewat token user, approval, execution, dan audit hanya yang `agent`-nya = agent pemanggil (item agent lain → `404`). Action **privileged** (`ssh.sudo` dan sejenisnya), jendela sudo, dan approval-nya tidak pernah tampil; minta lewat id → `403 infra_only`; plan yang memberinya → problem `privileged_action` (termasuk wildcard yang mencakupnya). Token statis tetap melihat semuanya |
| Tetap infra (token statis) | credential, buat/ubah/hapus koneksi resource, agent dan token, policy sisi agent (`subject.agent_id`/`role`), action privileged dan jendela sudo, audit verify, revoke, pemulihan. Endpoint tulis satu-per-satu (`PUT /v1/admin/roles/{id}`, `POST /v1/admin/policies`, …) juga tetap infra |
| Baca | `GET /v1/admin/roles` (`RoleView`: `held_by_agents`, `editable`), `/users`, `/policies?side=user`, `/resources` (`ResourceView`, tanpa secret maupun id credential), `/actions` (`ActionInfo`: `risk`, `read_only`, `source`, `state`) |
| Direktori | `GET /v1/admin/directory/users?q=&limit=`, `/directory/groups?q=`, dari IdP lewat service account read-only milik gateway. IdP mati → `503 directory_unavailable` |
| Akses efektif | `GET /v1/admin/access?subject=` → role beserta item `users.json` yang memberinya, grant (user ∩ agent pemanggil) dengan `decision` `allow`/`requester`/`admin` dan policy-nya, serta `denied` beserta alasan |
| Katalog | `GET /v1/admin/resources/{id}/catalog`, `POST …/sync` (diff `added`/`removed`/`changed`; gagal → `502 sync_failed`, snapshot lama tetap), `POST …/catalog/acknowledge` `{tools}`. SQL: tabel + kolom dari `information_schema`. Resource type baru `mcp_server`: `tools/list` → action `mcp.<resource>.<tool>` (huruf kecil, selain `[a-z0-9_]` → `_`, bagian yang tidak diawali `a-z` → awalan `t_`; tabrakan dan nama tool > 64 dilewati dan dilaporkan di `SyncOut.skipped`, sync tetap `200`). `Catalog.resource` = nama resource. `readOnlyHint: true` = read (risk `low`), write `destructiveHint: false` → `medium`, write lain → `high`. Wildcard tidak pernah mencakup action `mcp.…`. Skema berubah atau read → write = `needs_review`: semua panggilan ditolak sampai di-acknowledge. Sync tidak pernah memberi izin |
| Perubahan | Hanya lewat plan. `GET /v1/admin/config` → `AccessConfig` (`schema: agentgate-access/1`, kunci nama: `roles` yang tidak dipegang agent, seluruh `users`, policy sisi user, `resource_tables`). `POST /v1/admin/config/plan` → `PlanOut` (`changes`, `problems`: `missing_resource`, `missing_action`, `missing_role`, `role_held_by_agent`, `table_not_in_catalog`, `agent_side_policy`, `privileged_action`, `last_admin`, `self_lockout`; berlaku 15 menit). `POST /v1/admin/config/apply` `{plan_id}`: `409 plan_stale` bila digest berubah, `plan_has_problems`, `plan_expired`, dan `second_admin_required` bila setting `admin.apply_requires_second_admin` aktif (production) dan yang apply = yang membuat plan. Plan tak dikenal → `404 plan_not_found`. `GET /v1/admin/config/plans?status=open` (termasuk plan yang punya problem). `POST /v1/admin/config/plans/{id}/discard` → plan `status: discarded`, oleh admin akses mana pun, diaudit; bukan `open` → `409 plan_not_open`. Item `users` dengan `id` tak dikenal dicocokkan lewat `match`, selain itu dibuat dengan id baru |
| Sel matriks | Satu policy per sel resource × action: allow (`never`), requester (`requester`), admin (`always`), deny. Nama `<role>--<resource>--<action>` dengan titik → `_` |
| Approval admin | `GET /v1/admin/approvals?status=`, approve, reject `{reason}`. Admin tidak boleh menyetujui write yang ia minta sendiri → `409 self_approval` |
| History | `GET /v1/admin/executions?since=&until=&status=&subject=&action=&limit=&cursor=` → halaman `ExecutionView` (tanpa params/result), `GET /v1/admin/executions/{id}` → dengan params dan result yang sudah diredaksi. Terbaru dulu, `limit` 1–200 |
| Audit | `GET /v1/admin/audit?…&subject=&limit=&cursor=` → halaman. Verify tetap infra |
| Environment | Satu instance per environment. Console membandingkan dengan membaca `config` dari tiap instance, dan mem-promote dengan mem-plan config sumber di instance tujuan. Secret tidak pernah ada di config |
| Seed dev | Tiap agent memegang role sendiri (`agentgate-app`), bukan role orang. Role `platform-admin` untuk grup `platform-admin` (tanpa garis miring) di `admin.user_roles` kedua instance. Production `apply_requires_second_admin: true` |

### 23.1 Implementasi gateway (lane G + S, integrasi 10 Nov 2026)

- Auth: `apps/api_server/deps.py` (`AccessAdminDep` untuk kolom kiri kontrak §1, `AdminDep` untuk infra). Token agent tanpa `X-User-Token` di endpoint kolom kiri → `401`; di endpoint infra tetap `403 admin_required`. User bukan admin → `403 not_admin`; admin akses di endpoint infra → `403 infra_only`.
- Endpoint yang sudah ada (`roles`, `policies`, `resources`, `approvals`, `audit`) menjawab bentuk kontrak hanya untuk admin akses; token statis mendapat jawaban yang sama seperti sebelumnya. Endpoint baru ada di `routes_access_admin.py` dan menjawab bentuk kontrak untuk keduanya.
- Logika di `modules/administration/access.py` (config, plan, apply, akses efektif), `directory.py` (Keycloak, client credentials). Katalog dibaca lewat satu port, `modules/catalog/ports.py::CatalogPort`, diimplementasikan `CatalogService` (§11.6) yang dipasang `build_gateway`. Tampilan approval/execution/audit di `apps/api_server/admin_history.py`.
- Plan disimpan di `var/access_plans.json` (id `pln_<ULID>`, status `open`/`applied`/`expired`/`discarded`). Apply = satu event audit `access.applied` dengan diff lengkap, ditulis sebelum perubahan (fail closed). Discard = event `access.plan_discarded`. Plan yang sudah di-discard lalu di-apply → `409 plan_not_open`.
- Endpoint katalog (`routes_admin_catalog.py`) memakai `AccessAdminDep`; sync dan acknowledge oleh admin akses diaudit dengan actor user + `details.via_agent`, sama seperti tulis admin akses lainnya.
- Antrean approval admin memuat approval mode `admin` milik agent pemanggil, termasuk yang diminta tanpa user (`requested_by.subject: null`); action privileged tetap disembunyikan.
- Problem plan `missing_action` mengikuti engine: wildcard yang hanya mengenai action katalog (`mcp.desk.*`) tidak memberi apa-apa, jadi dilaporkan.
- Audit: actor admin akses = `{"type": "user", "id": "<sub>"}` dengan `details.via_agent` = id agent; `AuditEntryView` memetakannya ke `actor.kind/subject/via_agent` (nama agent). Bentuk entry audit tidak berubah, jadi hash chain lama tetap terverifikasi.
