# Risk Register — Large-Scale AIC Issuance

> Identified 2026-08-20. Assessment of the memory-centric engine (`engine` package + `recordbuffer`) against the projected large-scale AIC issuance workload (mass issue / bulk revoke / high-frequency queries). Kept in sync with `docs/IMPLEMENTATION_PLAN.md` and `docs/NEXT_STEPS.md`.

## Severity Legend

- 🔴 **High** — security, consistency, or hard throughput ceiling. Fix first.
- 🟠 **Medium** — performance regression at scale, or risk of OOM / slow path under load.
- 🟡 **Low** — operational / observability / capacity-planning gaps.

---

## 🔴 R1 — DA nonce written one-by-one (AIC-specific write amplification)

**Location:** `engine/writes.go` `StoreDANonce` / `ConsumeNonce`

Each AIC issuance consumes one DelegationAuthorization nonce. `StoreDANonce` enqueues a **single-row INSERT** to the serialized writer channel (`writerCh`); it does not go through the batched write pipeline. At 7K–11K TPS issuance this becomes 7K single-row DB writes per second behind a single worker — a hidden bottleneck that grows linearly with issuance rate.

**Fix:** route DA nonce storage through the RecordBuffer batch path (WAL-protected bulk upsert), or coalesce distinct nonces into a periodic batch write.

**Status: ✅ FIXED (2026-08-20)** — `RecordBuffer` is now a tagged `Item` pipeline (`KindCert` / `KindDANonce`); `StoreDANonce` writes the nonce into the WAL and the batch flush persists all pending nonces via the new `db.BulkStoreDANonces` multi-row INSERT. Tests: `TestBulkStoreDANonces`, `TestRecordBufferAddDANonceSyncPersistsBatch`, `TestStoreDANonceBatchConvergence`.

## 🔴 R2 — DA nonce crash window (replay vulnerability)

**Location:** `engine/writes.go` `StoreDANonce` + `engine/load.go`

Memory is authoritative: a DA nonce is marked used in the in-memory `NonceSet` and only then enqueued for async persistence. If the process crashes between the in-memory mark and the enqueue, the nonce is lost on restart — the same DA signature could be replayed to mint a second AIC. The `da_nonces` table is the eventual sink but offers no protection inside that window.

**Fix:** persist (or WAL-fsync) the DA nonce *before* it becomes authoritative in memory, or force a WAL fsync before each AIC issuance acknowledges success.

**Status: ✅ FIXED (2026-08-20)** — `RecordBuffer.AddDANonceSync` synchronously fsyncs the WAL before returning; without a WAL, `StoreDANonce` falls back to synchronous DB persistence. The nonce is durable before the issuance is acknowledged, and restart recovery replays it from the WAL into `da_nonces` + memory. Tests: `TestStoreDANonceWALCrashRecovery` (kill -9 subprocess), `TestStoreDANonceNoWALFallbackSync`, `TestRecordBufferDANonceWALReplay`.

## 🔴 R3 — Bulk revocation is N serial UPDATEs

**Location:** `engine/writes.go` `RevokeCertsBatch` / `RevokeCertsByPrincipalUid` / `RevokeCertsBySubCA`

A batch revocation of N certificates persists N individual UPDATE statements serially inside the single writer goroutine. Revoking 100K certificates ≈ 100K serial UPDATEs (≈1ms each → ~100s). The in-memory flip is already single-lock and fast; the DB convergence is the bottleneck.

**Fix:** persist each bulk revocation as a single batch statement (`UPDATE ... CASE WHEN` / temp-table JOIN / multi-row VALUES), preserving the writer's ordering guarantee.

**Status: ✅ FIXED (2026-08-20)** — new `db.BulkRevokeCertificates` issues one `UPDATE ... revoke_reason=CASE ... WHERE (...) AND status='V'` per ~199-entry chunk (a CASE expression carries per-row reasons); `Engine.RevokeCertsBatch` now uses it instead of N serial UPDATEs. Tests: `TestBulkRevokeCertificates` (300 rows, 2 chunks, per-row reasons, idempotent re-run), `TestRevokeCertsBatchBulkConvergence`.

---

## 🟠 R4 — Single write pipeline is a hard ceiling

**Location:** `engine/engine.go` `writerCh` + `recordbuffer.RecordBuffer`

One RecordBuffer (single drain goroutine + single flush mutex) + one writer goroutine serialize all persistence. Measured 7K–11K TPS is close to the ceiling. Beyond that, scale the write path.

**Fix:** shard the write pipeline (multiple workers with ordering partitioned by key) or raise the writer concurrency with careful ordering semantics.

**Status: ✅ FIXED (2026-08-20)** — the backend writer is now a sharded pool (`EngineOptions.WriteWorkers`, default 4). Ops are routed by `writerShardForKey` (FNV-1a hash): same-key ops (nonce Store→Consume, cert issue→revoke, sub-CA re-insert) stay ordered on one goroutine; different keys run in parallel. `FlushAll` barriers every shard. `RevokeCertsBatch`/`FlushAll` order guarantees preserved (INSERTs flushed first, bulk ops idempotent). Tests: `TestWriterShardForKeyStable`, `TestShardedWriterNonceOrdering`, `TestShardedWriterAllShardsActive`, `TestRevokeCertsBatchOrderingAcrossShards`. Certificate bulk inserts remain on the RecordBuffer batch path (SQLite single-writer makes parallel flush counterproductive there).

## 🟠 R5 — Single certificate-index lock

**Location:** `engine/cert_index.go` `CertIndex.mu` (single RWMutex)

All inserts and revocations take the write lock; each lock hold does 5–6 map writes + a heap push. Under 50K+ TPS the write lock serializes issuance.

**Fix:** shard the index by CA (or by key hash) with per-shard locks.

## 🟠 R6 — Full result materialization + unbounded sort

**Location:** `engine/cert_index.go` `filterSortedSetPage` + `getBySPKI` / `getByUid` / `getByAgent`

Queries returned the full matching set and sorted it O(n log n). A principal with 100K certs meant a full copy + sort per query, blocking the calling goroutine.

**Fix:** pagination + result cap + cursor for high-cardinality lookups.

**Status: ✅ FIXED (2026-08-20)** — new `CertCursor` (opaque: NotBefore desc + serial desc position); `getBySPKI` / `getByUid` / `getByAgent` now take `(limit, after)` and page the result via `filterSortedSetPage`, which keeps the best `limit+1` candidates in a bounded min-heap (O(n) scan + O(n log limit) work, only `limit+1` records materialized) and returns an exact `hasMore`. `limit<=0` preserves the old all-at-once contract. Engine-level `GetCertBySPKIHash` / `ListCertsByPrincipalUid` / `ListCertsByAgentID` expose the same signature (recs, next cursor, hasMore, error). Tests: `TestPagedGetCertBySPKIHash` (250 shared-SPKI records, clustered NotBefore), `TestPagedListCertsByAgentID` (status-filtered), `TestPagedListCertsByPrincipalUid` — all walk every page and assert uniqueness + canonical order.

## 🟠 R7 — Slow startup rebuild at scale

**Location:** `engine/load.go` (paginated 1000/step, sequential put with O(log n) heap push per record)

Loading 1M certs = 1000 page queries + 1M heap pushes + index builds. Startup can take tens of seconds during which the engine reports `Loading()`.

**Fix:** parallel load (per-CA shards) + progress metrics + optional deferred indexing.

---

## 🟡 R8 — No byte-budget for memory residency

**Location:** `engine/options.go` `MaxCerts` (count-based, default 200K)

Each resident `CertRecord` carries cert_der (1–4KB) + AIC JSON + pointers across 5 secondary indexes ≈ 1GB+ at 200K certs. Eviction only considers NotAfter, not access recency — long-lived active AICs stay resident forever.

**Fix:** byte-budget / per-CA caps + hot/warm tiering.

**Status: ✅ FIXED (2026-08-20)** — new `EngineOptions.MaxResidentBytes` (default 2 GiB), enforced alongside `MaxCerts` in `CertIndex.insertIfAbsent`: when the estimated resident bytes (base overhead + cert_der + string fields, tracked on put/remove/evict as `CertIndex.residentBytes`) exceed the budget, expired certs are evicted first; otherwise `IssueCert` returns `ErrBackpressure`. AIC extensions get the same accounting (`AICIndex.residentBytes`). Both are exposed via `CertIndex.ResidentBytes()` / `AICIndex.ResidentBytes()` and the `CertResidentBytes` / `AICResidentBytes` metrics. Tests: `TestByteBudgetRejectsOversizedInsert`, `TestByteBudgetEvictsExpiredFirst`, `TestAICResidentBytes`.

## 🟡 R9 — aic_extensions table grows unbounded

**Location:** `engine/engine.go` janitor + `engine/load.go` AIC pagination

One row per AIC; janitor prunes nonces/certs but not AIC extensions for expired certificates. The table grows without bound and slows every startup.

**Fix:** janitor cleanup of AIC extensions whose certificates have left the hot window.

**Status: ✅ FIXED (2026-08-20)** — `CertIndex.evictExpired` now returns the evicted certs' `(ca, serial)` keys; the janitor cascades through the new `AICIndex.removeByCert` (drops the extension from the byCert / byAgent / byUid maps) and queues `db.DeleteAICExtension` on the same shard key as `UpsertAICExtension` (`ca/serial`), so the delete orders after the insert / any re-issue. AIC rows for hot certs survive. Tests: `TestJanitorPrunesAICForEvicted` (memory + backend assertions), `TestJanitorSkipsAICForMissingCert`.

## 🟡 R10 — Missing AIC-specific metrics

**Location:** `engine/engine.go` `Metrics` / `PrometheusMetrics`

Missing: issuance/revocation rate, eviction breakdown, AIC index size, resident bytes, pipeline latency histogram, WAL size.

**Fix:** add gauges/counters/histograms.

**Status: ✅ FIXED (2026-08-20)** — `Metrics` gained `CertIssued` / `CertRevoked` counters (wired through `IssueCert` + all four revoke paths), `AICPruned` (janitor AIC cleanup), `CertResidentBytes` / `AICResidentBytes` (R8 accounting), `WalBytes` (recordbuffer WAL file size), and a `FlushDuration` histogram (4 buckets, cumulative in the Prometheus output). `PrometheusMetrics` renders all of them: `varwof_engine_cert_issued_total`, `varwof_engine_cert_revoked_total`, `varwof_engine_aic_pruned_total`, `varwof_engine_cert_resident_bytes`, `varwof_engine_aic_resident_bytes`, `varwof_engine_wal_bytes`, `varwof_engine_flush_duration_seconds` (histogram). Tests: `TestMetricsCounters`, `TestPrometheusMetricsNewFields`, `TestRevokeCountersBulk`.

---

## Fix Order (agreed 2026-08-20)

1. ~~R1 + R2 — DA nonce batch pipeline + crash safety~~ ✅ (2026-08-20)
2. ~~R3 — single-statement bulk UPDATE revocation~~ ✅ (2026-08-20)
3. ~~R4 — write pipeline sharding / worker pool~~ ✅ (2026-08-20)
4. ~~R6 + R9 — query pagination + AIC janitor cleanup~~ ✅ (2026-08-20)
5. ~~R8 + R10 — memory budget + metrics~~ ✅ (2026-08-20)

Status of each fix is tracked in `docs/NEXT_STEPS.md` and `docs/zh/NEXT_STEPS.md`.

> **Real-DB verification complete** (2026-08-20): `BulkStoreDANonces` / `BulkRevokeCertificates` dialect branches verified against live PostgreSQL 15 and MariaDB 10.11 — new `TestPGBulkStoreDANonces` / `TestPGBulkRevokeCertificates` / `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates` (fresh per-run database, batch store + duplicate-ignore/idempotent re-run + 32-byte validation + per-row reasons across chunk boundaries). Full `go test -tags postgres` / `-tags mysql ./...` suites green.