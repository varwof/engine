# Remaining Work (NEXT_STEPS)

> Tracks varwof-engine items that are incomplete, environment-blocked, or optional optimizations. Kept in sync with implementation.

## High-Risk Fixes (agreed 2026-08-20)

Tracked in `docs/RISKS.md` / `docs/zh/RISKS.md`. Fix order: R1+R2 (DA nonce batch pipeline + crash safety), R3 (single-statement bulk revoke), R4 (write pipeline sharding), R6+R9 (query pagination + AIC janitor), R8+R10 (memory budget + metrics).

| Item | Status |
|---|---|
| R1+R2 — DA nonce batch pipeline + crash safety | ✅ Done (2026-08-20): tagged RecordBuffer Item pipeline + `AddDANonceSync` (WAL fsync) + `db.BulkStoreDANonces` |
| R3 — single-statement bulk UPDATE revocation | ✅ Done (2026-08-20): `db.BulkRevokeCertificates` CASE UPDATE, `RevokeCertsBatch` wired |
| R4 — write pipeline sharding / worker pool | ✅ Done (2026-08-20): sharded writer (`WriteWorkers`, FNV-1a key routing, same-key ordering preserved, `FlushAll` barriers all shards) |
| R6+R9 — query pagination + AIC janitor cleanup | ✅ Done (2026-08-20): `CertCursor` + `(limit, after)` pagination on SPKI/UID/agent queries (`filterSortedSetPage`, bounded limit+1 heap, exact hasMore); janitor cascades `AICIndex.removeByCert` + `db.DeleteAICExtension` for evicted certs |
| R8+R10 — memory budget + AIC metrics | ✅ Done (2026-08-20): `MaxResidentBytes` byte budget on `CertIndex`/`AICIndex` (estimate on put/remove/evict, expired-first eviction, `ErrBackpressure` otherwise); `Metrics` gained issued/revoked/AIC-pruned counters, cert+AIC resident bytes, WAL size, flush-latency histogram, all rendered in `PrometheusMetrics` |
| RBAC user/Token memory indexes (in-memory auth) | ✅ Done (2026-08-27): `userIndex`/`tokenIndex` (engine/user_token.go) + `ListRBACUsers`/`ListAllTokenHashes` startup load; `GetUserByUsername`/`GetUserByID`/`GetToken` (in-memory expiry+enabled check) /`PutUser`/`DeleteUserByID`/`PutTokenHash`/`DeleteTokenByHash`/`DeleteTokenByID`/`DeleteTokensByUserID`; serve read paths engine-first/DB-fallback (`getUserByUsername`/`getToken`), write-through writes. AIC PG retest: 3,529 → **4,111 certs/s (hit 600ms injection ceiling 4,167/s)**, p50 47ms→2.7ms; DB activity now only bulk `INSERT INTO certificates`. Consistency wedge documented as R11 in `docs/RISKS.md` |
| R12 — Write pipeline blocks on half-open connection (MySQL+engine collapse: 21GB/conn reset) | ✅ Done (2026-08-27): two-layer root cause — 21GB proven via dmesg to be an OOM kill (now bounded by the 2GiB `MaxResidentBytes` budget); the real defect was MySQL having no read deadline, so a half-open connection blocked `bulkInsertChunk→Exec→readPacket` forever while holding `flushMu` → `Stop()→FlushAll()` deadlock. Fix: mysql DSN gets `timeout=10s&readTimeout=30s&writeTimeout=30s` (`ensureMySQLTimeouts`) + `ExecContext` + `BulkInsertCertRecordsCtx`/`BulkStoreDANoncesCtx` + recordbuffer `flushDBTimeout=2min` ctx fallback. Also raised the PG/MySQL bulk chunk 39→**500 rows/statement** (`certChunkSize`, ~13× fewer round-trips); MySQL AIC @100ms 4,325→**6,034 certs/s**. Real-DB verification all exit=0 with a full report (MySQL regular @100ms 7,575/s, AIC @100ms 6,034/s, AIC @600ms 4,114/s; PG AIC @600ms 4,054/s no regression). `-race` green; new unit tests `TestEnsureMySQLTimeouts`/`TestBulkInsertCertRecordsCtxCancelled`/`TestBulkStoreDANoncesCtxCancelled` |
| R13 — Full-buffer DA nonce store thundering-herds onto flushMu (sustained-load server freeze) | ✅ Done (2026-08-27): under sustained AIC load the buffer fills (~18s at default 20k pending), and every `AddDANonce` then did a synchronous `FlushAll()` that held `flushMu` across the whole O(backlog) pass — all request goroutines serialize on one mutex and the server freezes (40s bench plateaued at ~108k successes, p99 → 22s, ~2k goroutines blocked in `FlushAll`). Fix: full-buffer appends now `waitForCapacity()` — signal the drain loop and sleep on a close-and-replace broadcast channel fired per flush pass (all waiters wake at once); if capacity can't be freed in 5s, `recordbuffer.ErrBackpressure` → normalized to `engine.ErrBackpressure` → HTTP 503 (issuance fails, replay protection never weakened). Result: 40s AIC @100ms (MySQL/engine/2500 agents) restored to **~163k successes (~4.1k certs/s)** = the sustained MySQL bulk-insert ceiling (500-row chunks ≈ 7.3k certs/s measured standalone; 20s runs burst to ~5.3k/s via buffer absorption); zero goroutines block in `FlushAll`; backpressure surfaces as clean 503s. New unit tests `TestRecordBufferAddDANonceWaitsForCapacity`/`TestRecordBufferAddDANonceConcurrentWaits`/`TestRecordBufferAddDANonceBackpressureTimeout`; `-race` green |

### Real-DB verification complete (2026-08-20)

`db.BulkStoreDANonces` / `db.BulkRevokeCertificates` dialect branches verified against live PostgreSQL 15 (localhost:5432, `PG_TEST_DSN`) and MariaDB 10.11 (localhost:3306, `MYSQL_TEST_DSN`): new `TestPGBulkStoreDANonces` / `TestPGBulkRevokeCertificates` / `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates`. SQLite paths covered by `TestBulkStoreDANonces` / `TestBulkRevokeCertificates`. Full `-tags postgres` / `-tags mysql ./...` suites green.

Note: the previously-documented MariaDB isolated instance on 127.0.0.1:3307 is not running; the local system MariaDB on 3306 was used instead (created `varwof`@`localhost` / `varwof`@`127.0.0.1` users with full privileges). PostgreSQL got a `varwof` login role + `pki` database + `CREATEDB`.

### Data race on revocation resolved (2026-08-20)

`setRevokedLocked` (`engine/cert_index.go`) used to mutate the shared `*db.CertRecord` in place (`Status` / `RevokedAt` / `RevokeReason`) while `recordStatus` (`engine/reads.go`) and the recordbuffer drain read those fields without the index lock — flaky under `-race` in `TestConvergenceMemoryAuthoritative` / `TestConcurrentReadsDuringBulkRevoke`. Fixed with copy-on-write: records are immutable once published; revocation publishes a clone (`setRevokedLocked` → `replaceLocked`) that swaps the instance across the primary + all secondary indexes, and `removeLocked` resolves the current instance by primary key so the eviction-window heap's pre-revocation pointer still deletes correctly. `RevokeCertsBatch` now writes each entry's reason into its clone before publication (no post-hoc mutation). `-race` on both tests and the full engine suite is green.

### WAL concurrency hardening (2026-08-20, R1/R2 follow-up)

While running `-race` for R6/R9, `recordbuffer` showed a real race: `bufio.Writer` + WAL `os.File` were shared between the drain goroutine (`flushLocked`), the periodic fsync in `add()`, and `AddDANonceSync` without a common lock. Fixed by adding `RecordBuffer.walMu`, which serializes every WAL write / flush / sync / truncate / seek / close. `TestStoreDANonceWALCrashRecovery` also made deterministic under `-race` (the crash helper now closes the DB handle after `load()` so the drain fails without persisting/truncating, keeping the DB-empty-before-replay assertion reliable).

## Blocked (Require External Environment)

| Item | Blocker | Status |
|---|---|---|
| Phase G: varwof-core gradual migration (`IMPLEMENTATION_PLAN.md` Phase G 1-6) | varwof-core integration | Pending |
| Crash recovery end-to-end (kill -9 → restart → WAL replay → in-memory index intact) | Requires varwof-core integration environment; engine side covered by `TestEngineRebuildFullState` / `TestConvergenceMemoryAuthoritative` | Pending integration |
| MySQL/MariaDB real-DB verification | Completed (2026-08-10 + 2026-08-20): local MariaDB 10.11. On 2026-08-20 switched to the 3306 system instance (`varwof` user created) for `-tags mysql`, adding `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates` (R1/R3 dialect branches on real DB), full suite green | ✅ Done |
| `go test -race ./...` | Concurrency tests run clean under `-race` locally and in CI (`.github/workflows/ci.yml`); earlier revocation race fixed (see "Data race on revocation resolved") | ✅ Done |
| CI workflow (test + vet + race + coverage gate) | ✅ Done (2026-08-24): `.github/workflows/ci.yml` (build/vet/test/race / coverage gate 85% / real PG & MariaDB service containers) | ✅ Done |

> **PostgreSQL ready** (2026-08-10 + 2026-08-20): local PG 15 online. On 2026-08-20 created `varwof` role (`$PG_PASSWORD`) + `pki` database + `CREATEDB`; `PG_TEST_DSN="postgres://varwof:$PG_PASSWORD@localhost:5432/pki?sslmode=disable"`.
> PG gated cases: `go test -tags postgres ./db/ -run 'TestPGConnect|TestPGAdvisoryLockReal|TestPGTransferToReal|TestCreatePGDatabaseReal|TestPGBulkStoreDANonces|TestPGBulkRevokeCertificates'`.
> Covers v1 (consolidated) migration, advisory lock real-DB, `TransferTo` pgx sequence update branch, R1/R3 dialect branches (db coverage 83.5% → 86.5% with PG real DB).

> **MariaDB ready** (2026-08-10 + 2026-08-20): local 3306 system instance (the 3307 isolated instance from 2026-08-10 is not running).
> `MYSQL_TEST_DSN="varwof:$MYSQL_PASSWORD@tcp(127.0.0.1:3306)/pki_mysql?charset=utf8mb4&parseTime=true" go test -tags mysql ./db/`.
> Covers v1 (consolidated) migration, certificate CRUD roundtrip, 999-variable bulk (2000 records), `TransferTo` general path, R1/R3 dialect branches (db coverage 83.5% → 86.1% with MySQL real DB).
> Note: MariaDB `NewDistLock` uses file lock (only PG uses advisory lock).

## Coverage Gaps (engine 97.0% / db 83.5% / cache 99.1% / recordbuffer 81.6%)

| Location | Description | Coverable? |
|---|---|---|
| `engine/load.go:31-59` | ListNonces / ListSubCAs / ListTrustAnchors / ListAICExtensions error branches (mirrors already-covered certs error branches) | Requires injected query failure, low value |
| `engine/load.go:66` | AIC pagination offset increment (`TestEngineRebuildAICPagination` already covers same logic for certs path) | See above |
| `engine/writes.go:39-44` | `!rb.Add(rec)` branch (race window after IsFull pre-check, practically unreachable) | Race, cannot deterministically trigger |
| `db/transfer.go:51-55` | `TransferTo` pgx branch — **already covered by `TestPGTransferToReal`** (including sequence update) | ✅ Covered |
| `db/lock.go:77-82` | `pgAdvisoryLock.TryLock` `acquired=true` branch — **already covered by `TestPGAdvisoryLockReal`** | ✅ Covered |

## Optional Optimizations / Candidate Tests

- [ ] `BulkInsertAICExtensions` bulk insert (currently AIC written one-by-one)
- [ ] `GetRevokedCertEntries` conversion pooling (object reuse on CRL generation path)
- [ ] `UpsertSubCA` / `UpsertTrustAnchor` / `UpsertAICExtension` dialect coverage tests
- [ ] Deterministic construction test for `RecordBuffer.Add` and `IsFull` race under high concurrency
- [ ] `TransferTo` target non-empty DB / idempotent re-entry test

## Environment Notes (measured on Intel Core Ultra 5 125H desktop, 2026-08-24)

- `go test -race` runs clean locally (and in CI on GitHub Actions).
- Benchmark figures are hardware-dependent; re-measure on same environment for comparison; README "Benchmarks" table updated periodically (run `go test ./... -bench . -benchmem` directly). See `docs/BENCHMARK_COMPARISON.md` for a 3-machine comparison (desktop / Raspberry Pi 5 / PN41).

## Code Review Rules (Write-Path Routing)

- [ ] Hot-path reads must go through engine memory; PRs must not introduce new "read DB as fallback" code (decision in `REQUIREMENTS.md` §7 read/write path routing).
- [ ] New write methods (IssueCert/Revoke/ConsumeNonce) must not issue synchronous DB calls inside index locks; persistence only via RecordBuffer/WAL asynchronously.
- [ ] New exported methods must have doc comments (keep `docs/functions.md` in sync).
- [ ] After dialect/migration changes, regress with `-tags postgres` and `-tags mysql` real-DB suites.
