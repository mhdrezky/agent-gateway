# Lane S: katalog, `agw sync`, dan MCP custom (10 Nov 2026)

Branch `claude/agw-sync-765ffe`, dari `feat/admin-contract` (`03a6b6c`). Belum di-push, belum di-merge. Kontrak: `agentgate-gateway-admin/1` §7, §7.1 (repo agentgate `19a259e`), tidak diubah. Spesifikasi lengkap: SPEC §11.6.

## Yang dibangun

| Slice | Isi |
| ----- | --- |
| AG4 | `modules/catalog/`: snapshot per resource di `var/catalogs.json` (JSON atomic yang sudah ada), diff `added`/`removed`/`changed`, `removed_tables`. `brokers/sql/introspect.py`: baca tabel, kolom, tipe, nullable, komentar dari `pg_catalog` untuk `schema_name`, dengan login resource sendiri; seam T-SQL = `INTROSPECTORS[engine]`. Broker SQL menolak tabel yang hilang walau masih di `allowed_tables`; `pending_review` true selama itu. `allowed_tables` boleh kosong |
| AG5 | Resource type `mcp_server` + `brokers/mcp/` (SDK MCP resmi, Streamable HTTP, bearer dari credential `api_token`). Tool → action `mcp.<resource>.<tool>` persis §7.1, risk dari anotasi, skema dari server (divalidasi JSON Schema), `needs_review` untuk skema berubah / read → write, tool baru aktif tanpa grant, tool hilang di-unregister. Action terdaftar setelah sync, saat start, dan di tick dispatcher (sync dari CLI). Panggilan lewat engine biasa |
| Guard | `ActionGuard` di engine: hanya bisa mengubah allow → deny (`catalog review pending`, `action belongs to another resource`). Dicek saat submit, saat konfirmasi requester, dan sebelum eksekusi yang sudah di-approve jalan |
| REST | File baru `apps/api_server/routes_admin_catalog.py` (satu baris `include_router` di `app.py`): `GET …/catalog`, `POST …/sync`, `POST …/catalog/acknowledge`. Dependency: `AdminDep` (token statis) |
| CLI | `agw sync [resource]`, `agw catalog show`, `agw catalog ack` |
| Fixture | `tests/fixtures/mcp_fixture.py` (A11): tool read, write, tanpa anotasi, varian `v2`, bisa jalan sendiri (`python -m tests.fixtures.mcp_fixture`) |

Keputusan yang saya ambil (tidak bertentangan dengan kontrak, tetapi perlu diketahui):

1. **Wildcard tidak pernah mencakup action katalog** (sama seperti action privileged): role dan policy harus menyebut `mcp.desk.lookup_order` persis. Tanpa ini, role `mcp.desk.*` otomatis memberi tool baru hasil sync berikutnya, padahal §7 bilang tool baru "granted to nobody". Console memang menulis id persis per sel.
2. **Risk**: read → `low`; write dengan `destructiveHint: false` → `medium`; write lain (termasuk tanpa anotasi) → `high`. Kontrak hanya membedakan read/write.
3. **Tabel "removed"** = tabel yang pernah terlihat di katalog lalu hilang. Tabel di `allowed_tables` yang belum pernah terlihat tidak ditandai (itu urusan problem plan `table_not_in_catalog`).
4. Katalog SQL hanya berisi relasi yang bisa di-`SELECT` login resource dan bernama identifier huruf kecil.
5. Error di luar kontrak: `404 catalog_not_found` (belum pernah sync), `422 catalog_not_supported` (tipe tanpa katalog / broker mati), `409 invalid_action_id` (lihat pertanyaan 2).

## Config dan atribut baru

- `brokers.mcp.enabled` (default `false`). Homelab tidak berubah: SSH tetap, broker baru mati secara default, `catalogs.json` baru dibuat saat sync pertama.
- Resource `mcp_server`: `url` (http/https, tanpa userinfo), `transport` (`streamable_http`), `timeout_seconds` (1–55, default 30). Credential opsional `api_token`.
- `sql_database.allowed_tables`: default `[]` (sebelumnya minimal satu).
- Event audit: `catalog.synced`, `catalog.sync_failed`, `catalog.acknowledged`.
- `ActionDefinition.bound_resource`, `InMemoryActionRegistry.replace_group/group_of`, `GatewayExecutionEngine(guard=…)`, `Gateway.catalog`.
- Dependency: `jsonschema` jadi dependency langsung (sebelumnya transitif lewat `mcp`), `types-jsonschema` di dev.
- `tests/broker/sql/init.sql`: komentar, tabel tanpa grant, tabel mixed-case, default privileges. Stack SQL perlu `down -v` sekali.

## Antarmuka baca untuk lane G

`gateway.catalog` (`CatalogService`), kontraknya `modules/catalog/ports.py::CatalogPort`:

| Method | Untuk |
| ------ | ----- |
| `await tables(resource_id) -> list[str] \| None` | problem plan `table_not_in_catalog` (`None` = belum pernah sync) |
| `await state(resource) -> CatalogState` | `ResourceView.catalog` (`synced_at`, `snapshot_id`, `pending_review`) |
| `await catalog_actions() -> list[CatalogActionInfo]` | `ActionInfo` dengan `source="mcp"`: `action`, `resource_id`, `resource_name`, `state`, `read_only`, `risk` |
| `await snapshot(resource_id)` | snapshot mentah |

Untuk integrator:
- Ganti `AdminDep` di `routes_admin_catalog.py` dengan dependency admin akses; `_actor()` di sana membuat `Actor` audit dan perlu versi user (`actor.kind=user`, subject, via_agent).
- Kemungkinan konflik merge dengan G: `runtime.py` (field `Gateway`, `build_gateway`), `config.py` (`BrokerSettings`), `audit/models.py` (event baru), `app.py` (satu baris router), `cli.py` (perintah baru di akhir file).
- `ActionInfo.risk`: gateway memakai `low/medium/high/critical`; fake lane W memakai `read`/`write`. Perlu disepakati di G/integrasi.
- Plan untuk `resource_tables` cukup memanggil `admin.update_resource(... allowed_tables ...)`; `pending_review` SQL hilang sendiri karena dihitung live.

## Test

| Suite | Hasil |
| ----- | ----- |
| `ruff check`, `ruff format --check` | bersih |
| `mypy` (strict, checker repo; tidak ada config pyright di repo) | bersih, 209 file |
| `pytest` (default, tanpa `broker`) | 1052 passed, 25 deselected (`broker`); 74 test baru di 4 file baru |
| Live Postgres (`-m broker tests/broker/test_sql_live.py`, `agw-broker-sql` :15432) | 13 passed (9 lama + 4 baru) |

Test baru: `tests/unit/test_catalog.py` (aturan §7.1, risk, diff tabel/tool, acknowledge, grup registry), `tests/unit/test_mcp_broker.py` (atribut, params JSON Schema tanpa echo nilai, hasil, SDK client ke fixture, bearer), `tests/integration/test_catalog_api.py` (REST + engine end to end: sync, granted-to-nobody, panggilan, resource lain, needs_review sampai acknowledge, review saat approval menunggu, 502, 409 collision/too_long, restart, sync dari proses lain, hapus resource, `/mcp/actions` enum, SQL removed table, akses dan error), `tests/integration/test_mcp_sync_cli.py` (fixture di uvicorn, socket nyata, `agw sync`/`catalog show`/`catalog ack`), 4 test live SQL, satu aturan import (`modules.catalog`).

## Pertanyaan terbuka (kontrak tidak diubah)

1. **409 pada sync**: apakah sync dibatalkan seluruhnya, atau tool lain tetap disimpan? Saya baca "neither is added" sebagai: snapshot disimpan tanpa tool bermasalah, respons `409` dengan kode masalah pertama dan pesan yang menyebut semuanya. Konsekuensinya klien tidak menerima `SyncOut` untuk sync itu (bisa `GET …/catalog`).
2. **Bagian id yang diawali `_`** (tool `_private`, atau `über` → `_ber`) sah menurut aturan §7.1 tetapi bukan id action gateway (segmen harus diawali huruf). Sekarang: tidak ditambahkan, `409 invalid_action_id`. Usul: §7.1 juga memberi awalan `t_` untuk `_` di depan, atau mendefinisikan kode ini.
3. **`Catalog.resource`**: id atau nama? Saya ikuti fake lane W (id). `ActionInfo.resource` = nama.
4. **Ganti nama resource** mengubah id action MCP baru pada sync berikutnya; policy yang menyebut id lama tidak cocok lagi. Kontrak belum menyebut.
5. **Risk** untuk write: apakah console butuh membedakan destruktif atau tidak (`medium`/`high`), atau cukup read/write?
