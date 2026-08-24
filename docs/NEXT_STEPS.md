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
| `go test -race ./...` | Local arm64 kernel ASLR entropy fixed at 39bit (TSan needs ≤32, `vm.mmap_rnd_bits` sysctl refuses downgrade, kernel recompilation needed); concurrency tests designed for CI `-race`. The former pre-existing revocation race is fixed (see "Data race on revocation resolved"); engine suite runs `-race` clean locally | Pending CI |
| CI workflow (test + vet + race + coverage gate) | Current directory is not a git repo; **local equivalent ready: `scripts/ci.sh`** (build/vet/test/race auto-skip / coverage gate 85% / optional PG real-DB) | Ready for repo化 |

> **PostgreSQL ready** (2026-08-10 + 2026-08-20): local PG 15 online. On 2026-08-20 created `varwof` role (`$PG_PASSWORD`) + `pki` database + `CREATEDB`; `PG_TEST_DSN="postgres://varwof:$PG_PASSWORD@localhost:5432/pki?sslmode=disable"`.
> PG gated cases: `go test -tags postgres ./db/ -run 'TestPGConnect|TestPGAdvisoryLockReal|TestPGTransferToReal|TestCreatePGDatabaseReal|TestPGBulkStoreDANonces|TestPGBulkRevokeCertificates'`.
> Covers v1 (consolidated) migration, advisory lock real-DB, `TransferTo` pgx sequence update branch, R1/R3 dialect branches (db coverage 85.6% → 86.5%).

> **MariaDB ready** (2026-08-10 + 2026-08-20): local 3306 system instance (the 3307 isolated instance from 2026-08-10 is not running).
> `MYSQL_TEST_DSN="varwof:$MYSQL_PASSWORD@tcp(127.0.0.1:3306)/pki_mysql?charset=utf8mb4&parseTime=true" go test -tags mysql ./db/`.
> Covers v1 (consolidated) migration, certificate CRUD roundtrip, 999-variable bulk (2000 records), `TransferTo` general path, R1/R3 dialect branches (db coverage 85.6% → 86.1%).
> Note: MariaDB `NewDistLock` uses file lock (only PG uses advisory lock).

## Coverage Gaps (engine 99.0% / db 86.5%)

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

## Environment Notes (Local Raspberry Pi 4B)

- TF card slow: `go test -fuzz` must run full package tests before fuzzing; db package ~60-90s previously caused 120s timeout. **Fuzz must add `-run='^$'`**.
- `go test -race` unavailable (see above).
- Benchmark figures are hardware-dependent; re-measure on same environment for comparison; README "Benchmarks" table updated periodically (use `scripts/bench.sh` to freeze output).

## Code Review Rules (Write-Path Routing)

- [ ] Hot-path reads must go through engine memory; PRs must not introduce new "read DB as fallback" code (decision in `REQUIREMENTS.md` §7 read/write path routing).
- [ ] New write methods (IssueCert/Revoke/ConsumeNonce) must not issue synchronous DB calls inside index locks; persistence only via RecordBuffer/WAL asynchronously.
- [ ] New exported methods must have doc comments (keep `docs/en/functions.md` in sync).
- [ ] After dialect/migration changes, regress with `-tags postgres` and `-tags mysql` real-DB suites.
