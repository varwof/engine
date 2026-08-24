# Risk Register — Large-Scale AIC Issuance Scenarios

> Identified: 2026-08-20. Risk assessment for the memory-is-truth engine (`engine` package + `recordbuffer`) under large-scale AIC issuance workloads (mass issuance / bulk revocation / high-frequency queries). Kept in sync with `docs/zh/IMPLEMENTATION_PLAN.md` and `docs/zh/NEXT_STEPS.md`.

## Severity Legend

- 🔴 **High risk** — Security, consistency, or hard throughput ceiling. Fix first.
- 🟠 **Medium risk** — Performance degradation at scale, or OOM / slow-path risk under load.
- 🟡 **Low risk** — Ops / observability / capacity planning gaps.

---

## 🔴 R1 — DA nonce single-row writes (AIC-specific write amplification)

**Location:** `engine/writes.go` `StoreDANonce` / `ConsumeNonce`

Every AIC issuance consumes one DelegationAuthorization nonce. `StoreDANonce` enqueues a single-row INSERT into the serial writer channel (`writerCh`), **bypassing the batch write pipeline**. At 7K–11K TPS issuance that is 7K single-row DB writes per second, all serialized behind a single worker — a hidden bottleneck growing linearly with issuance rate.

**Fix:** Route DA nonce storage through the RecordBuffer batch path (WAL-protected batch upsert), or merge distinct nonces into periodic batch writes.

**Status: ✅ Fixed (2026-08-20)** — `RecordBuffer` changed to a tagged `Item` pipeline (`KindCert` / `KindDANonce`); `StoreDANonce` writes nonces to WAL, and batch flush persists them via the new `db.BulkStoreDANonces` multi-row INSERT. Tests: `TestBulkStoreDANonces`, `TestRecordBufferAddDANonceSyncPersistsBatch`, `TestStoreDANonceBatchConvergence`.

## 🔴 R2 — DA nonce crash window (replayable vulnerability)

**Location:** `engine/writes.go` `StoreDANonce` + `engine/load.go`

Memory is truth: the DA nonce is marked used in the in-memory `NonceSet` first, then queued for async persistence. If the process crashes between the memory mark and enqueue → nonce lost after restart → the same DA signature can be replayed to issue a second AIC. The `da_nonces` table is the eventual persistence target but is unprotected during this window.

**Fix:** Persist (or WAL fsync) before the nonce becomes memory-authoritative, or force WAL fsync before confirming each AIC issuance.

**Status: ✅ Fixed (2026-08-20)** — `RecordBuffer.AddDANonceSync` synchronously fsyncs the WAL before returning; without WAL, `StoreDANonce` falls back to synchronous DB persistence. The nonce is persisted before issuance confirmation; restart recovery replays from WAL into the `da_nonces` table + memory. Tests: `TestStoreDANonceWALCrashRecovery` (kill -9 child process), `TestStoreDANonceNoWALFallbackSync`, `TestRecordBufferDANonceWALReplay`.

## 🔴 R3 — Bulk revocation as N serial UPDATEs

**Location:** `engine/writes.go` `RevokeCertsBatch` / `RevokeCertsByPrincipalUid` / `RevokeCertsBySubCA`

Bulk revocation of N certificates executes N UPDATEs one by one inside a single writer goroutine. Revoking 100K certificates ≈ 100K serial UPDATEs (~1ms each → ~100 seconds). The memory flip is already fast under a single lock; DB convergence becomes the bottleneck.

**Fix:** Persist each bulk revocation with a single batch statement (`UPDATE ... CASE WHEN` / temp-table JOIN / multi-row VALUES), preserving the writer's ordering guarantees.

**Status: ✅ Fixed (2026-08-20)** — Added `db.BulkRevokeCertificates`: per ~199-row chunk, one `UPDATE ... revoke_reason=CASE ... WHERE (...) AND status='V'` (CASE expression carries per-row reason); `Engine.RevokeCertsBatch` now calls it instead of N serial UPDATEs. Tests: `TestBulkRevokeCertificates` (300 rows across 2 chunks, per-row reason, idempotent rerun), `TestRevokeCertsBatchBulkConvergence`.

---

## 🟠 R4 — Single write pipeline is a hard ceiling

**Location:** `engine/engine.go` `writerCh` + `recordbuffer.RecordBuffer`

A single RecordBuffer (single drain goroutine + single flush mutex) + a single writer goroutine serialize all persistence. Measured 7K–11K TPS is near the limit; going beyond requires scaling the write path.

**Fix:** Shard the write pipeline (multi-worker partitioned by key) or increase writer concurrency while preserving ordered semantics.

**Status: ✅ Fixed (2026-08-20)** — Backend writers changed to a sharded pool (`EngineOptions.WriteWorkers`, default 4). Operations are routed via `writerShardForKey` (FNV-1a hash): same-key operations (nonce Store→Consume, certificate issue→revoke, sub-CA re-insert) stay ordered within a single goroutine; different keys run in parallel. `FlushAll` sets a barrier across all shards. Ordering guarantees of `RevokeCertsBatch`/`FlushAll` preserved (flush INSERTs first; bulk operations are idempotent). Tests: `TestWriterShardForKeyStable`, `TestShardedWriterNonceOrdering`, `TestShardedWriterAllShardsActive`, `TestRevokeCertsBatchOrderingAcrossShards`. Certificate bulk insertion remains on the RecordBuffer batch path (SQLite's single-writer lock makes parallel flushes counterproductive).

## 🟠 R5 — Single certificate index lock

**Location:** `engine/cert_index.go` `CertIndex.mu` (single RWMutex)

All inserts and revocations contend on the write lock; each lock hold performs 5-6 map writes + one heap push. At 50K+ TPS the write lock serializes issuance.

**Fix:** Shard the index by CA (or key hash), each shard with its own lock.

## 🟠 R6 — Full result materialization + unbounded sorting

**Location:** `engine/cert_index.go` `filterSortedSetPage` + `getBySPKI` / `getByUid` / `getByAgent`

Queries originally returned the entire matching set sorted O(n log n). 100K certificates for one principal = full copy + sort per query, blocking the calling goroutine.

**Fix:** Paginate high-cardinality lookups + return caps + cursors.

**Status: ✅ Fixed (2026-08-20)** — Added `CertCursor` (opaque cursor: NotBefore descending + serial descending position); `getBySPKI` / `getByUid` / `getByAgent` now accept `(limit, after)` and paginate via `filterSortedSetPage` — using a bounded min-heap to keep only the best `limit+1` candidates (O(n) scan + O(n log limit) heap operations, materializing only `limit+1` records), returning an exact `hasMore`. `limit<=0` keeps the old full-result contract. Engine-level `GetCertBySPKIHash` / `ListCertsByPrincipalUid` / `ListCertsByAgentID` expose the same signature (recs, next cursor, hasMore, error). Tests: `TestPagedGetCertBySPKIHash` (250 records sharing SPKI, NotBefore-clustered), `TestPagedListCertsByAgentID` (status-filtered), `TestPagedListCertsByPrincipalUid` — all traverse page by page asserting uniqueness + canonical order.

## 🟠 R7 — Slow startup rebuild at scale

**Location:** `engine/load.go` (paginated 1000/step, per-record put + heap push O(log n) each)

Loading 1M certificates = 1000 paginated queries + 1M heap pushes + index building. Startup can take tens of seconds, during which the engine reports `Loading()`.

**Fix:** Parallel loading (sharded by CA) + progress metrics + optional deferred index building.

---

## 🟡 R8 — No byte budget for memory residency

**Location:** `engine/options.go` `MaxCerts` (by count, default 200K)

Each resident `CertRecord` includes cert_der (1–4KB) + AIC JSON + 5 secondary-index pointers ≈ 200K records exceed 1GB. Eviction considers only NotAfter, not access heat — long-lived active AICs stay resident forever.

**Fix:** Byte budget / per-CA caps + hot/warm tiering.

**Status: ✅ Fixed (2026-08-20)** — Added `EngineOptions.MaxResidentBytes` (default 2 GiB), enforced together with `MaxCerts` in `CertIndex.insertIfAbsent`: when the resident byte estimate (base overhead + cert_der + string fields, maintained as `CertIndex.residentBytes` on put/remove/evict) exceeds budget, expired certificates are evicted first; otherwise `IssueCert` returns `ErrBackpressure`. AIC extensions are accounted the same way (`AICIndex.residentBytes`). Both exposed via `CertIndex.ResidentBytes()` / `AICIndex.ResidentBytes()` and the `CertResidentBytes` / `AICResidentBytes` metrics. Tests: `TestByteBudgetRejectsOversizedInsert`, `TestByteBudgetEvictsExpiredFirst`, `TestAICResidentBytes`.

## 🟡 R9 — Unbounded growth of aic_extensions table

**Location:** `engine/engine.go` janitor + `engine/load.go` AIC pagination

One record per AIC; the janitor cleans only nonces and certificates, not AIC extensions belonging to expired certificates → unbounded table growth slowing every startup.

**Fix:** Janitor cleans AIC extensions whose certificates have left the hot window.

**Status: ✅ Fixed (2026-08-20)** — `CertIndex.evictExpired` now returns the `(ca, serial)` keys of evicted certificates; the janitor cascades to the new `AICIndex.removeByCert` (deleting from the byCert / byAgent / byUid maps) and queues `db.DeleteAICExtension`, using the same shard key as `UpsertAICExtension` (`ca/serial`) so deletes order after inserts / same-serial re-issuance. AIC rows for hot certificates are retained. Tests: `TestJanitorPrunesAICForEvicted` (memory + backend assertions), `TestJanitorSkipsAICForMissingCert`.

## 🟡 R10 — Missing AIC-specific metrics

**Location:** `engine/engine.go` `Metrics` / `PrometheusMetrics`

Missing: issue/revoke rates, eviction breakdown, AIC index size, resident bytes, pipeline latency histogram, WAL size.

**Fix:** Add gauge/counter/histogram.

**Status: ✅ Fixed (2026-08-20)** — `Metrics` adds `CertIssued` / `CertRevoked` counters (wired into `IssueCert` + all 4 revocation paths), `AICPruned` (janitor AIC cleanup), `CertResidentBytes` / `AICResidentBytes` (R8 accounting), `WalBytes` (recordbuffer WAL file size), `FlushDuration` histogram (4 buckets, rendered cumulatively in Prometheus output). `PrometheusMetrics` renders all: `varwof_engine_cert_issued_total`, `varwof_engine_cert_revoked_total`, `varwof_engine_aic_pruned_total`, `varwof_engine_cert_resident_bytes`, `varwof_engine_aic_resident_bytes`, `varwof_engine_wal_bytes`, `varwof_engine_flush_duration_seconds` (histogram). Tests: `TestMetricsCounters`, `TestPrometheusMetricsNewFields`, `TestRevokeCountersBulk`.

---

## Fix Order (confirmed 2026-08-20)

1. ~~R1 + R2 — DA nonce batch pipeline + crash safety~~ ✅ (2026-08-20)
2. ~~R3 — Single-statement bulk UPDATE revocation~~ ✅ (2026-08-20)
3. ~~R4 — Write pipeline sharding / worker pool~~ ✅ (2026-08-20)
4. ~~R6 + R9 — Query pagination + AIC janitor cleanup~~ ✅ (2026-08-20)
5. ~~R8 + R10 — Memory budget + metrics~~ ✅ (2026-08-20)

Fix status for each item tracked in `docs/NEXT_STEPS.md` and `docs/zh/NEXT_STEPS.md`.

> **Real-database verification complete (2026-08-20)**: `BulkStoreDANonces` / `BulkRevokeCertificates` dialect branches verified on local PostgreSQL 15 and MariaDB 10.11 — added `TestPGBulkStoreDANonces` / `TestPGBulkRevokeCertificates` / `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates` (each run creates a fresh database; batch store + duplicate-ignore/idempotent rerun + 32-byte validation + cross-chunk per-row reason). `go test -tags postgres` / `-tags mysql ./...` full suites green.
