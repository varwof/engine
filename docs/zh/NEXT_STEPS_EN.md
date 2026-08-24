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
| `go test -race ./...` | Local arm64 kernel ASLR entropy fixed at 39bit (TSan needs ≤32; `vm.mmap_rnd_bits` sysctl refuses lowering; kernel rebuild required); concurrency tests designed so CI can run `-race`. The earlier revocation race has been fixed (see "Revocation Path Data Race Fixed"); engine suite fully green locally under `-race` | Awaiting CI |
| CI workflow (test + vet + race + coverage gate) | Current directory is not a git repository; **local equivalent ready: `scripts/ci.sh`** (build/vet/test/race auto-skip/coverage gate 85%/optional real PG) | Convert to real CI once repo-hosted |

> **PostgreSQL ready** (2026-08-10 + 2026-08-20): local PG 15 online. On 2026-08-20 created the `varwof` role (`$PASSWORD`) + `pki` database + `CREATEDB`, `PG_TEST_DSN="postgres://varwof:$PASSWORD@localhost:5432/pki?sslmode=disable"`.
> PG-gated cases: `go test -tags postgres ./db/ -run 'TestPGConnect|TestPGAdvisoryLockReal|TestPGTransferToReal|TestCreatePGDatabaseReal|TestPGBulkStoreDANonces|TestPGBulkRevokeCertificates'`.
> Covers full migration, advisory lock against a real DB, `TransferTo`'s pgx sequence-update branch, R1/R3 dialect branches (db coverage 85.6% → 86.5%).
> Real-database testing exposed and fixed a `NewDistLock` type-assertion bug (`d.dialect.(pgDialect)` fails to match `*pgDialectWithConfig`).

> **MariaDB ready** (2026-08-10 + 2026-08-20): local 3306 system instance (the 3307 isolated instance recorded on 2026-08-10 was not running).
> `MYSQL_TEST_DSN="varwof:$PASSWORD@tcp(127.0.0.1:3306)/pki_mysql?charset=utf8mb4&parseTime=true" go test -tags mysql ./db/`.
> Covers full migration, certificate CRUD roundtrip, 999-variable chunked bulk (2000 records), `TransferTo` generic path, R1/R3 dialect branches (db coverage 85.6% → 86.1%).
> Note: MariaDB's `NewDistLock` uses file locks (only PG uses advisory locks).

## Coverage Remaining Uncovered (engine 99.0% / db 86.5%)

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

## Environment Notes (local Raspberry Pi 4B)

- TF card is slow: `go test -fuzz` must run the full package tests before fuzzing; the db package takes ~60-90s which once caused a 120s timeout. **Fuzz must add `-run='^$'`**.
- `go test -race` unavailable (see above).
- Benchmark numbers are hardware-dependent; re-test within the same environment for comparison; README "Benchmarks" table refreshed periodically (can codify output via `scripts/bench.sh`).

## Code Review Rules (write-path routing)

- [ ] Hot-path reads must go through engine memory; PRs must not add new "query DB as fallback" code (decision in `REQUIREMENTS.md` §7 read/write path routing).
- [ ] New write methods (IssueCert/Revoke/ConsumeNonce) must not make synchronous DB calls inside the index lock; persistence only via RecordBuffer/WAL asynchronously.
- [ ] New exported methods need doc comments (sync `docs/functions.md`).
- [ ] After changing dialect/migrations, regress with the `-tags postgres` and `-tags mysql` real-database suites.
