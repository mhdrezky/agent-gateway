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
│   │   └── administration/      # operasi admin ber-audit (REST admin + CLI)
│   ├── brokers/
│   │   ├── base.py              # Broker protocol & ActionContext
│   │   ├── ssh/
│   │   ├── docker/
│   │   ├── github/
│   │   ├── cloudflare/
│   │   └── http/
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

- Plaintext credential hanya hidup di dalam `ActionContext` selama eksekusi broker.
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
- Dikelola admin: `agw user add --group staff --role staff`, `agw user add --subject <sub> --role author`, `agw user list`, `agw user delete <usr_id>` (nanti juga `agw apply`, slice 9). Setiap perubahan diaudit `user.updated`.

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

`read_only` (default `false`, jadi action baru dianggap mengubah sesuatu) menentukan anotasi tool MCP (§16). Action yang tidak mengubah apa pun: `ssh.system.info`, `ssh.service.status`, `ssh.logs.tail`, `docker.container.list`, `docker.container.logs`. Selain itu adalah tulis, termasuk `ssh.service.restart`, `ssh.sudo`, `docker.container.restart`, dan `docker.container.stop`. Action privileged tidak boleh `read_only`.

SSH broker memakai `asyncssh`, wajib verifikasi `host_key_fingerprint` (tidak ada auto-accept). Koneksi hanya meminta algoritma `host_key_algorithm` (default `ssh-ed25519`), karena server OpenSSH punya beberapa host key dan tanpa batasan ini asyncssh menegosiasikan RSA sehingga fingerprint ed25519 tidak pernah cocok (ditemukan saat uji e2e). Docker broker memakai Docker Engine API; hanya container dengan label `agw.managed=true` atau di allowlist resource yang boleh disentuh.

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

`correlation_id` opsional. REST membacanya dari header `X-Correlation-Id`; `tools/call` (di `/mcp/actions` maupun `/mcp`) dari `_meta["agentgate/correlation_id"]`, dan dari header bila `_meta` tidak membawanya. Bila keduanya ada dan berbeda, permintaan ditolak `422` (`invalid_params`) tanpa execution. Nilainya 1–200 karakter tanpa karakter kontrol. Ia disimpan di execution dan di `details.correlation_id` pada setiap event audit execution itu (termasuk approval-nya). Ia bukan bagian dari `params_digest` dan tidak mengubah idempotensi. Tanpa id, tidak ada field baru di baris audit, sehingga rantai hash fase 2 tetap sah.

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

`auth.failed`, `token.created`, `token.revoked`, `agent.created`, `agent.updated`, `resource.*`, `credential.created`, `credential.rotated`, `policy.*`, `user.updated` (fase 4), `execution.requested`, `execution.denied`, `execution.rejected`, `approval.requested`, `approval.approved`, `approval.rejected`, `approval.expired`, `execution.started`, `execution.succeeded`, `execution.failed`.

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
| 404 | `action_not_found`, `resource_not_found`, `execution_not_found`, `agent_not_found`, `credential_not_found`, `approval_not_found` |
| 409 | `approval_not_pending`, `conflict` |
| 422 | `invalid_params` |
| 429 | `rate_limited` |
| 503 | `audit_unavailable` |

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
users:
  oidc:                   # opsional; tanpa ini X-User-Token selalu ditolak (§9.4)
    issuer: https://idp.example.com/realms/company   # nilai klaim iss yang diharapkan
    audience: agentgate
    jwks_url: http://idp:8080/realms/company/protocol/openid-connect/certs
    groups_claim: groups
    algorithms: [RS256, ES256]
    leeway_seconds: 30
    jwks_cache_seconds: 300
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
| Broker | SSH broker ke container `openssh-server`, Docker broker ke Docker lokal | pytest marker `@broker` |
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
| 9 | `agw apply <seed.yaml>` | Onboarding deklaratif dan idempoten (agent, role, policy, resource, user, referensi credential) |
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
| Tool (MCP) | `/mcp/actions`, Streamable HTTP. `tools/list`: satu tool per action yang boleh dipakai pemanggil, dengan nama `^[a-zA-Z0-9_-]{1,64}$` (titik → garis bawah) dan `resource_id` enum di `inputSchema`. `tools/call` → `structuredContent` = `ToolOutcome` (`ok`, `pending`, `denied`, `error`), dari status execution: `succeeded` → `ok`, `pending_approval` → `pending`, `denied` → `denied`, lainnya → `error` |
| Model | `GET /v1/models` → `[{name, model_id}]`; `POST /v1/models/{name}/chat` dengan `ChatIn` → `ChatOut` (selalu ada `model_id` bila `ok`). Nama yang tidak boleh dipakai → `status: denied`; nama tak dikenal → `404 model_not_found` |
| Approval user | `GET /v1/approvals/mine?status=` dan `POST /v1/approvals/{id}/decide` `{"decision": "confirm"\|"reject"}`, wajib `X-User-Token` (tanpa itu `401`). Approval orang lain atau mode admin → `404 approval_not_found`; sudah diputuskan → `409 approval_not_pending`. **Tidak pernah tersedia sebagai tool MCP** |
| Cek nama | `POST /v1/bind` `{models, tools, resources}` → `200 {models: {name: model_id}}` atau `409 names_missing` dengan daftar yang hilang; diaudit; butuh user author atau reviewer |
| `users.json` | Item `{id, match: {subject} \| {group}, roles}`; role user = gabungan semua item yang cocok |
| Error | `{"error": {"code", "message"}}` dengan kode §15.3, ditambah `approval_not_found`, `model_not_found`, `names_missing` |
