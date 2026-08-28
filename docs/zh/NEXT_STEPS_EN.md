# Remaining Work List (NEXT_STEPS)

> Records varwof-engine items that are incomplete / blocked by environment / optional optimizations. Continuously updated, kept in sync with the implementation.

## High-Risk Fixes (confirmed 2026-08-20)

Tracked in `docs/RISKS.md` / `docs/zh/RISKS.md`. Fix order: R1+R2 (DA nonce batch pipeline + crash safety), R3 (single-statement bulk revocation), R4 (write pipeline sharding), R6+R9 (query pagination + AIC janitor), R8+R10 (memory budget + metrics).

| Item | Status |
|---|---|
| R1+R2 — DA nonce batch pipeline + crash safety | ✅ Done (2026-08-20): tagged RecordBuffer Item pipeline + `AddDANonceSync` (WAL fsync) + `db.BulkStoreDANonces` |
| R3 — Single-statement bulk UPDATE revocation | ✅ Done (2026-08-20): `db.BulkRevokeCertificates` CASE UPDATE, wired into `RevokeCertsBatch` |
| R4 — Write pipeline sharding / worker pool | ✅ Done (2026-08-20): sharded writers (`WriteWorkers`, FNV-1a key routing, same-key ordering, `FlushAll` all-shard barrier) |
| R6+R9 — Query pagination + AIC janitor cleanup | ✅ Done (2026-08-20): `CertCursor` + SPKI/UID/agent query `(limit, after)` pagination (`filterSortedSetPage`, bounded limit+1 heap, exact hasMore); janitor cascades `AICIndex.removeByCert` + `db.DeleteAICExtension` for evicted certificates |
| R8+R10 — Memory budget + AIC metrics | ✅ Done (2026-08-20): `MaxResidentBytes` byte budget applied to `CertIndex`/`AICIndex` (estimated on put/remove/evict, expired evicted first, otherwise `ErrBackpressure`); `Metrics` adds issue/revoke/AIC-cleanup counters, certificate+AIC resident bytes, WAL size, flush latency histogram — all rendered via `PrometheusMetrics` |
| RBAC user/Token memory indexes (in-memory auth) | ✅ Done (2026-08-27): `userIndex`/`tokenIndex` (engine/user_token.go) + `ListRBACUsers`/`ListAllTokenHashes` startup load; `GetUserByUsername`/`GetUserByID`/`GetToken` (in-memory expiry+enabled check) /`PutUser`/`DeleteUserByID`/`PutTokenHash`/`DeleteTokenByHash`/`DeleteTokenByID`/`DeleteTokensByUserID`; serve read paths engine-first/DB-fallback (`getUserByUsername`/`getToken`), write-through writes. AIC PG retest: 3,529 → **4,111 certs/s (hit 600ms injection ceiling 4,167/s)**, p50 47ms→2.7ms; DB activity now only bulk `INSERT INTO certificates`. Consistency wedge documented as R11 in `docs/RISKS.md` |
| R12 — Write pipeline blocks on half-open connection (MySQL+engine collapse: 21GB/conn reset) | ✅ Done (2026-08-27): two-layer root cause — 21GB proven via dmesg to be an OOM kill (now bounded by the 2GiB `MaxResidentBytes` budget); the real defect was MySQL having no read deadline, so a half-open connection blocked `bulkInsertChunk→Exec→readPacket` forever while holding `flushMu` → `Stop()→FlushAll()` deadlock. Fix: mysql DSN gets `timeout=10s&readTimeout=30s&writeTimeout=30s` (`ensureMySQLTimeouts`) + `ExecContext` + `BulkInsertCertRecordsCtx`/`BulkStoreDANoncesCtx` + recordbuffer `flushDBTimeout=2min` ctx fallback. Also raised the PG/MySQL bulk chunk 39→**500 rows/statement** (`certChunkSize`, ~13× fewer round-trips); MySQL AIC @100ms 4,325→**6,034 certs/s**. Real-DB verification all exit=0 with a full report (MySQL regular @100ms 7,575/s, AIC @100ms 6,034/s, AIC @600ms 4,114/s; PG AIC @600ms 4,054/s no regression). `-race` green; new unit tests `TestEnsureMySQLTimeouts`/`TestBulkInsertCertRecordsCtxCancelled`/`TestBulkStoreDANoncesCtxCancelled` |
| R13 — Full-buffer DA nonce store thundering-herds onto flushMu (sustained-load server freeze) | ✅ Done (2026-08-27): under sustained AIC load the buffer fills (~18s at default 20k pending), and every `AddDANonce` then did a synchronous `FlushAll()` that held `flushMu` across the whole O(backlog) pass — all request goroutines serialize on one mutex and the server freezes (40s bench plateaued at ~108k successes, p99 → 22s, ~2k goroutines blocked in `FlushAll`). Fix: full-buffer appends now `waitForCapacity()` — signal the drain loop and sleep on a close-and-replace broadcast channel fired per flush pass (all waiters wake at once); if capacity can't be freed in 5s, `recordbuffer.ErrBackpressure` → normalized to `engine.ErrBackpressure` → HTTP 503 (issuance fails, replay protection never weakened). Result: 40s AIC @100ms (MySQL/engine/2500 agents) restored to **~163k successes (~4.1k certs/s)** = the sustained MySQL bulk-insert ceiling (500-row chunks ≈ 7.3k certs/s measured standalone; 20s runs burst to ~5.3k/s via buffer absorption); zero goroutines block in `FlushAll`; backpressure surfaces as clean 503s. New unit tests `TestRecordBufferAddDANonceWaitsForCapacity`/`TestRecordBufferAddDANonceConcurrentWaits`/`TestRecordBufferAddDANonceBackpressureTimeout`; `-race` green |

### Real-Database Verification Complete (2026-08-20)

`db.BulkStoreDANonces` / `db.BulkRevokeCertificates` dialect branches verified on local PostgreSQL 15 (localhost:5432, `PG_TEST_DSN`) and MariaDB 10.11 (localhost:3306, `MYSQL_TEST_DSN`): added `TestPGBulkStoreDANonces` / `TestPGBulkRevokeCertificates` / `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates`. The SQLite path is covered by `TestBulkStoreDANonces` / `TestBulkRevokeCertificates`. `-tags postgres` / `-tags mysql ./...` full suites green.

Note: the previously documented isolated MariaDB instance at 127.0.0.1:3307 was not running; used the local system MariaDB on 3306 instead (created `varwof`@`localhost` / `varwof`@`127.0.0.1` users with full grants). PostgreSQL got a `varwof` login role + `pki` database + `CREATEDB`.

### Revocation Path Data Race Fixed (2026-08-20)

`setRevokedLocked` (`engine/cert_index.go`) previously mutated the shared `*db.CertRecord` in place (`Status` / `RevokedAt` / `RevokeReason`), while `recordStatus` (`engine/reads.go`) and the recordbuffer drain read those fields outside the index lock — `TestConvergenceMemoryAuthoritative` / `TestConcurrentReadsDuringBulkRevoke` were flaky under `-race`. Fix = copy-on-write: records are immutable once published; on revocation a clone is published (`setRevokedLocked` → `replaceLocked`) replacing the instance in the primary index + all secondary indexes; `removeLocked` resolves the current instance by primary key for deletion, ensuring eviction-window heap-held pre-revocation pointers still delete correctly. `RevokeCertsBatch` now writes each entry's reason into its own clone before publishing (no more post-hoc in-place mutation). Both tests + full engine suite green under `-race`.

### WAL Concurrency Hardening (2026-08-20, R1/R2 follow-up)

Running R6/R9 under `-race` exposed a real `recordbuffer` race: `bufio.Writer` + WAL `os.File` shared by the drain goroutine (`flushLocked`), periodic fsync inside `add()`, and `AddDANonceSync` with no common lock. Fix: added `RecordBuffer.walMu`, serializing all WAL write / flush / sync / truncate / seek / close. `TestStoreDANonceWALCrashRecovery` also made deterministic under `-race` (the crash helper closes the DB handle after `load()` so drain fails without persisting/truncating WAL, keeping the "DB empty before replay" assertion reliable).

## Blocked Items (require external environment)

| Item | Blocking Reason | Status |
|---|---|---|
| Phase G: varwof-core gradual migration (`IMPLEMENTATION_PLAN.md` Phase G 1-6) | varwof-core repository does not exist | Pending integration |
| Crash recovery end-to-end verification (kill -9 → restart → WAL replay → intact memory indexes) | Requires varwof-core integration environment; engine side already covered by `TestEngineRebuildFullState` / `TestConvergenceMemoryAuthoritative` | Awaiting integration environment |
| MySQL/MariaDB real-database verification | Complete (2026-08-10 + 2026-08-20): local MariaDB 10.11. On 2026-08-20 switched to the 3306 system instance (`varwof` user created) to run `-tags mysql`; added `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates` (real-DB verification of R1/R3 dialect branches), full suite green | ✅ Done |
| `go test -race ./...` | Concurrency tests run clean under `-race` locally and in CI (`.github/workflows/ci.yml`); earlier revocation race fixed (see "Revocation Path Data Race Fixed") | ✅ Done |
| CI workflow (test + vet + race + coverage gate) | ✅ Done (2026-08-24): `.github/workflows/ci.yml` (build/vet/test/race/coverage gate 85%/real PG & MariaDB service containers) | ✅ Done |

> **PostgreSQL ready** (2026-08-10 + 2026-08-20): local PG 15 online. On 2026-08-20 created the `varwof` role (`$PASSWORD`) + `pki` database + `CREATEDB`, `PG_TEST_DSN="postgres://varwof:$PASSWORD@localhost:5432/pki?sslmode=disable"`.
> PG-gated cases: `go test -tags postgres ./db/ -run 'TestPGConnect|TestPGAdvisoryLockReal|TestPGTransferToReal|TestCreatePGDatabaseReal|TestPGBulkStoreDANonces|TestPGBulkRevokeCertificates'`.
> Covers full migration, advisory lock against a real DB, `TransferTo`'s pgx sequence-update branch, R1/R3 dialect branches (db coverage 83.5% → 86.5% with PG real DB).
> Real-database testing exposed and fixed a `NewDistLock` type-assertion bug (`d.dialect.(pgDialect)` fails to match `*pgDialectWithConfig`).

> **MariaDB ready** (2026-08-10 + 2026-08-20): local 3306 system instance (the 3307 isolated instance recorded on 2026-08-10 was not running).
> `MYSQL_TEST_DSN="varwof:$PASSWORD@tcp(127.0.0.1:3306)/pki_mysql?charset=utf8mb4&parseTime=true" go test -tags mysql ./db/`.
> Covers full migration, certificate CRUD roundtrip, 999-variable chunked bulk (2000 records), `TransferTo` generic path, R1/R3 dialect branches (db coverage 83.5% → 86.1% with MySQL real DB).
> Note: MariaDB's `NewDistLock` uses file locks (only PG uses advisory locks).

## Coverage Remaining Uncovered (engine 97.0% / db 83.5% / cache 99.1% / recordbuffer 81.6%)

| Location | Description | Coverable? |
|---|---|---|
| `engine/load.go:31-59` | Error branches of ListNonces / ListSubCAs / ListTrustAnchors / ListAICExtensions (mirror of the covered certs error branches) | Needs injectable query failure; low value |
| `engine/load.go:66` | AIC pagination offset increment (`TestEngineRebuildAICPagination` covers the same logic for certs) | See above |
| `engine/writes.go:39-44` | `!rb.Add(rec)` branch (race window after the IsFull precheck; practically unreachable) | Race; cannot trigger deterministically |
| `db/transfer.go:51-55` | `TransferTo` pgx branch — **covered by `TestPGTransferToReal`** (incl. sequence update) | ✅ Covered |
| `db/lock.go:77-82` | `pgAdvisoryLock.TryLock` `acquired=true` branch — **covered by `TestPGAdvisoryLockReal`** | ✅ Covered |

## Optional Optimizations / Candidate Tests

- [ ] `BulkInsertAICExtensions` batch insert (currently AICs written one by one)
- [ ] `GetRevokedCertEntries` conversion pooling (object reuse on the CRL generation path)
- [ ] Dialect coverage tests for `UpsertSubCA` / `UpsertTrustAnchor` / `UpsertAICExtension`
- [ ] Deterministic test constructing the `RecordBuffer.Add` vs `IsFull` race under high concurrency
- [ ] `TransferTo` tests targeting non-empty databases / idempotent re-entry

## Environment Notes (measured on Intel Core Ultra 5 125H desktop, 2026-08-24)

- `go test -race` runs clean locally and in CI (GitHub Actions).
- Benchmark numbers are hardware-dependent; re-test within the same environment for comparison; README "Benchmarks" table refreshed periodically (run `go test ./... -bench . -benchmem` directly). 3-machine comparison (desktop / Raspberry Pi 5 / PN41) in `docs/BENCHMARK_COMPARISON.md`.

## Code Review Rules (write-path routing)

- [ ] Hot-path reads must go through engine memory; PRs must not add new "query DB as fallback" code (decision in `REQUIREMENTS.md` §7 read/write path routing).
- [ ] New write methods (IssueCert/Revoke/ConsumeNonce) must not make synchronous DB calls inside the index lock; persistence only via RecordBuffer/WAL asynchronously.
- [ ] New exported methods need doc comments (sync `docs/functions.md`).
- [ ] After changing dialect/migrations, regress with the `-tags postgres` and `-tags mysql` real-database suites.
