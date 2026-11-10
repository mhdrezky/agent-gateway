# Lane G: API admin akses `agentgate-gateway-admin/1` (10 Nov 2026)

Branch `claude/admin-api-2d39bb`, dipotong dari `feat/admin-contract` (`03a6b6c`). Belum di-push, belum di-merge.
Sumber kebenaran: repo agentgate `app/docs/gateway-admin-contract.md` (commit `19a259e`), tipe wire `packages/contracts/src/agentgate_contracts/gateway_admin.py`, desain `devnotes/design-gateway-admin-20261110.md` (A1–A13). Kontrak tidak diubah. Ringkasan dan catatan implementasi: SPEC §23 dan §23.1.

## Yang dibangun

**AG1: admin akses lewat OIDC**
- `apps/api_server/deps.py`:
  - `AccessAdminDep` untuk endpoint di kolom kiri kontrak §1. Menerima token admin statis, atau token agent + `X-User-Token` milik user yang salah satu role-nya ada di `admin.user_roles`. Hak agent tidak berperan.
  - `AdminDep` (infra) tetap hanya token statis. Admin akses → `403 infra_only`. User bukan admin → `403 not_admin`.
  - Token agent tanpa token user: `401 unauthenticated` di endpoint kolom kiri, `403 admin_required` di endpoint infra (seperti sebelumnya).
- Endpoint yang `infra_only` untuk admin akses: agents, tokens, credentials, buat/ubah/hapus resource, `PUT/DELETE roles/{id}`, `POST/PUT/DELETE policies`, `GET policies?side=agent`, `audit/verify`.
- Sudut pandang agent pemanggil (`apps/api_server/admin_history.py`):
  - approval, execution, dan audit hanya milik agent pemanggil; item agent lain → `404`;
  - action privileged (registry `privileged=True`) dan event elevation tidak pernah tampil; minta lewat id → `403 infra_only`.
- Approval admin: daftar (hanya mode `admin`, approval `requester` tetap di Inbox app), approve, dan reject (wajib `reason`). `409 self_approval` bila execution diminta oleh admin itu sendiri. Keputusan lewat `ApprovalWorkflow.decide_as_access_admin`: actor audit `{"type": "user", "id": sub}` + `details.via_agent`.
- `GET /v1/contract` → `["agentgate-gateway/1", "agentgate-gateway-admin/1"]`.
- Token statis tetap mendapat semua endpoint dengan bentuk jawaban lama.

**AG2: baca, direktori, akses efektif**
- `GET /v1/admin/roles` (`RoleView`), `/users`, `/policies?side=user` (`UserPolicy`, nama resource), `/resources` (`ResourceView`: tanpa atribut, tanpa id credential), `/actions` (`ActionInfo`; privileged disembunyikan untuk admin akses; `model.chat` ikut).
- `CatalogPort` + `NullCatalog` di `modules/administration/catalog_port.py`. Lane S memasang implementasi lewat `build_gateway(catalog=...)`. Isi port: `summary`, `tables`, `action_state`, `action_resource`.
- Direktori `modules/administration/directory.py`, Keycloak admin REST:
  - client credentials; secret dari credential store (nama di `admin.directory.credential`, tipe `api_token`), dibuka untuk satu request token lalu di-wipe;
  - token dipakai ulang sampai 30 detik sebelum habis; satu kali retry saat `401`;
  - `/directory/users?q=&limit=` (1–100, default 20) dan `/directory/groups?q=`;
  - IdP mati, secret salah, atau tanpa konfigurasi → `503 directory_unavailable`.
- `GET /v1/admin/access?subject=`:
  - grup dibaca dari direktori; `roles` beserta `via` (item `users.json`);
  - `grants` dihitung dengan `DefaultPolicyEngine`, user ∩ agent pemanggil; `policy` = policy sisi user yang mengizinkan;
  - `denied` = action yang diberikan role user tetapi tidak sampai ke resource mana pun, dengan alasan dari engine;
  - subject tak dikenal → `404 user_not_found`.

**AG3: config, plan, apply**
- `modules/administration/access.py` (`AccessAdmin`):
  - `GET /config`: `AccessConfig`, kunci nama.
  - `POST /config/plan`: `PlanOut` dengan `changes` dan semua kode problem §8.2. Berlaku 15 menit; `base_digest` = `sha256:` dari config kanonik.
  - `POST /config/apply`: `plan_stale`, `plan_has_problems`, `plan_expired`, `second_admin_required`.
  - `GET /config/plans?status=open|applied|expired`.
- Plan disimpan di `var/access_plans.json` lewat `JsonCollection` (P7).
- Apply menulis satu event audit `access.applied` (diff lengkap, `plan_id`, `planned_by`, `via_agent`) sebelum mengubah apa pun (fail closed), lalu menulis role, user, policy, dan `allowed_tables`. Berlaku di request berikutnya, tanpa restart.
- `GET /v1/admin/executions` (halaman, cursor = id execution, terbaru dulu, `limit` 1–200) dan `/executions/{id}` (dengan params dan result yang tersimpan sudah diredaksi).
- `GET /v1/admin/audit` untuk admin akses: halaman `AuditEntryView` (cursor = `seq`), filter `since/until/event/subject`.

Mesin `agw apply` (`apply.py`) **tidak dipakai langsung**: ia menulis lewat `AdminService` (wajib principal admin statis, satu event audit per objek, tidak pernah menghapus), sedangkan kontrak minta satu event per apply dan hapus untuk yang tidak ada di config. Yang dipakai ulang: model `Role`/`Policy`/`User`, pola match user (`subject:`/`group:`), dan validasi atribut resource.

## Test

- Baru: 89 test.
  - `tests/integration/test_access_admin_auth.py`: 39 (AG1, approval, history, audit).
  - `tests/integration/test_access_admin_reads.py`: 15 (AG2).
  - `tests/integration/test_access_admin_config.py`: 26 (AG3).
  - `tests/unit/test_admin_directory.py`: 9.
- Diubah:
  - `test_principles.py`: `GET /v1/admin/audit` dengan token agent saja sekarang `401`, bukan `403 admin_required`.
  - `test_mcp_actions.py`: daftar versi kontrak.
  - `test_approvals_flow.py`: approve dengan token agent saja sekarang `401`, bukan `403`.
- Fixture: `tests/access_world.py`, `tests/fakes/keycloak.py` (IdP admin palsu lewat `httpx.MockTransport`). `tests/world.py::build_world` mendapat `extra_brokers`, `catalog`, `directory_transport`, `clock`.
- `ruff check`, `ruff format --check`, `mypy --strict` (src + tests): hijau. Repo ini memakai mypy, bukan pyright.
- `pytest`: 1066 passed, 21 deselected (`broker`). Sebelumnya 977.

## Penyimpangan

1. **Bentuk jawaban bergantung pemanggil** di `GET roles`, `policies`, `resources`, `approvals`, `audit`, dan `POST approve/reject`. Admin akses mendapat tipe kontrak, token statis mendapat bentuk lama, karena kontrak §3 bilang token statis "exactly as before". Endpoint baru menjawab tipe kontrak untuk keduanya.
2. **Audit actor**: entry audit tidak mendapat field baru (hash chain lama harus tetap terverifikasi). Admin akses dicatat `actor {type: user, id: sub}` + `details.via_agent` (id agent). `AuditEntryView` memetakannya ke `actor.kind/subject/via_agent`, dengan `via_agent` berisi nama agent.
3. **Policy tanpa nama** (dibuat lewat CLI/REST) diekspor dengan nama = id-nya dalam huruf kecil (`pol_01…`). Saat apply tetap tanpa nama, sehingga round-trip stabil.
4. **Policy yang semua resource-nya sudah dihapus** diekspor dengan `tags: ["gateway:no-resource"]`, karena `ResourceNames` wajib punya names atau tags. Tag itu tidak ada di resource mana pun.
5. **Item user dengan `id` yang tidak dikenal** (promote dari instance lain) dicocokkan lewat `match`. Bila tidak ada yang cocok, item itu dibuat baru dengan id baru. Ini jawaban sementara untuk pertanyaan W no. 2.
6. **`resource_tables` yang tidak disebut** di config berarti "tidak berubah", bukan dikosongkan. Tabel kosong ditolak `422`, karena skema SQL wajib minimal satu tabel.
7. **Masalah semantik hanya dicek pada item yang dibuat atau diubah**: `missing_action`, `privileged_action`, `missing_resource`, `table_not_in_catalog`. Role atau policy lama yang tidak disentuh tidak memblokir plan. `missing_role` juga muncul untuk item lama bila role-nya dihapus oleh plan itu.
8. **Kesalahan struktur** (id role tidak valid, pola action tidak valid, nama ganda, `expires_at` rusak) → `422 invalid_params`, bukan problem. Plan tidak dibuat.
9. **Plan tak dikenal** → `404 not_found`. Kontrak tidak punya kode khusus.
10. **`/access` dengan token statis** wajib `?agent=<nama>`, karena tidak ada agent pemanggil. Tanpa itu `422`.
11. **Subject policy agent di config** diterima parser (`ConfigSubject` punya `agent_id`/`role`), supaya plan bisa melaporkan `agent_side_policy` dan tidak berhenti di `422`. Saat dikirim balik, kunci yang `null` dibuang, jadi tetap cocok dengan `UserSubject` kontrak yang strict.
12. Credential direktori memakai tipe yang sudah ada, **`api_token`**. Tidak ada tipe baru `client_secret`.

## Untuk integrator

**Key config baru** (`config.py`, `AdminSettings`, `DirectorySettings`):

```yaml
admin:
  user_roles: [platform-admin]
  apply_requires_second_admin: false   # production: true
  directory:                           # opsional; tanpa ini /directory dan /access → 503
    provider: keycloak
    base_url: http://keycloak:8080
    realm: agentgate-dev
    client_id: agentgate-directory
    credential: keycloak-directory     # credential tipe api_token
    groups_full_path: false            # true bila klaim groups berisi "/staff"
    timeout_seconds: 10
```

Seed contoh untuk credential-nya:

```yaml
credentials:
  - name: keycloak-directory
    type: api_token
    secret_env: KEYCLOAK_DIRECTORY_CLIENT_SECRET
```

**Titik sambung dengan lane S**:
- `build_gateway(..., catalog=<CatalogPort>)`. Default `NullCatalog`: tanpa snapshot, cek tabel dilewati.
- `ActionInfo.source` = `mcp` untuk id yang diawali `mcp.`; `resource` dan `state` diambil dari port.
- Lane S cukup mendaftarkan router-nya di `app.py` dan memasang catalog di `runtime.py`. File yang saya ubah dan mungkin juga disentuh S: `runtime.py` (`Gateway` dapat field `access`, `approvals`, `executions`), `app.py` (satu baris `include_router`), `config.py`, `common/errors.py`.

**File lain yang berubah**:
- `modules/identity/models.py`: `UserIdentity.groups`, dipakai untuk cek `self_lockout`. Field ini juga muncul di `whoami`.
- `modules/identity/users.py`: helper `matching_users` dan `user_roles`.
- `modules/approvals/*`: `decide_as_access_admin`.
- `modules/audit/models.py`: event `access.applied`.
- `common/ids.py`: prefix `pln`.

## Pertanyaan terbuka (kontrak tidak diubah)

1. **Agent saja ke endpoint kolom kiri**: kontrak bilang `401`, padahal sebelumnya `403 admin_required`. Saya pakai `401` di kolom kiri dan tetap `403 admin_required` di endpoint infra. Apakah kontrak perlu menyebut ini?
2. **Kode `plan_not_found`** tidak ada di kontrak (sekarang `404 not_found`). Tambahkan?
3. **`apply_requires_second_admin` tidak bisa dibaca console** (sama dengan pertanyaan W no. 1). Usul: tampilkan di `GET /v1/contract` atau di endpoint kecil `GET /v1/admin/instance`.
4. **`plans?status=open` memuat plan yang punya problem** (W no. 3). Saya memuatnya, karena statusnya memang `open`. Belum ada endpoint untuk membuang plan.
5. **Approval tanpa user**: approval admin milik agent pemanggil yang diminta tanpa `X-User-Token` (agent saja, bukan privileged) ikut tampil di antrean console. Kontrak §1.1 bilang "for people". Perlu disaring?
6. **`/access` untuk user yang ada di `users.json` tetapi tidak ada di direktori** → `404 user_not_found`, sesuai kontrak. Akibatnya override per subject untuk user yang sudah dihapus dari IdP tidak bisa diperiksa lewat endpoint ini.
7. **`AuditEntryView.actor.subject` untuk token statis** berisi id token admin (`tok_…`), bukan subject IdP. Bentuk ini perlu disepakati.
8. **Grup bertingkat dan nama grup**: `DirectoryGroup.name` mengikuti `groups_full_path` (W no. 6). Hitungan member dibatasi 1000 per grup, karena diambil dari satu halaman.
