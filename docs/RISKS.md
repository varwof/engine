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

## 🟡 R11 — RBAC user/Token index consistency wedge (2026-08-27)

Authentication read paths (authByToken / authByBasic / authFromAIC / gateway
delegation) and user/Token management writes all go through the serve wrapper
methods (engine-first, DB-fallback; write-through = persist to DB first, then
refresh/remove the resident row). Two accepted wedges remain:

1. **OOB-create invisibility**: a user/Token created directly in the DB
   (CLI / second instance, bypassing serve) is not resident → that account's
   authentication falls back to the DB (still usable, no feature loss), but does
   not enjoy the memory fast path until the next full restart load.
2. **OOB-delete residue (mirror image of certs)**: a user/Token deleted in the
   DB but still resident keeps authenticating from memory (memory-is-truth) —
   the opposite direction of the cert out-of-band "read falls back and sees DB
   writes". Mitigation: in-tree delete/update/password-rotation all go through
   write-through, keeping memory and backend in step; pure-DB deletions require
   a restart or routing the op through the wrapper.

**Status: 🟡 Accepted trade-off (2026-08-27)** — consistent with the R2
no-WAL stance (memory is authoritative; out-of-band operations degrade to DB
round-trips / restart convergence). Documented in `docs/REQUIREMENTS.md` and the
serve wrapper method comments.

## 🔴 R12 — Write pipeline blocks forever on a half-open backend connection (2026-08-27)

**Location:** `db/batch.go` / `db/da_nonces.go` / `recordbuffer/record_buffer.go`

When a MySQL connection goes half-open (peer dead/reset), the inner
`bulkInsertChunk→Exec→mysqlConn.readPacket` blocks **forever with no read
deadline** while the flush holds `flushMu` for the whole pass: the drain
goroutine wedges → pending is pinned at maxPending (every request 503) →
`Stop()→FlushAll()` deadlocks on the same lock → graceful shutdown hangs. The
previously documented "MySQL+engine write pipeline collapse: 21GB memory +
connection reset by peer" is this failure family (the 21GB part was proven via
dmesg to be an OOM kill: `oom-kill bench-smoke anon-rss ~21GB`; the current
build is bounded by the 2GiB `MaxResidentBytes` budget and no longer reproduces it).

**Fix:**
1. `db/db.go`: the mysql branch of `OpenWithDialect` now injects
   `ensureMySQLTimeouts` (adds `timeout=10s&readTimeout=30s&writeTimeout=30s`
   only when absent; skips `@unix(` DSNs); new `ExecContext` (context-aware
   rebind+adapt batch Exec).
2. `db/batch.go` / `db/da_nonces.go`: new `BulkInsertCertRecordsCtx` /
   `BulkStoreDANoncesCtx` plus chunk-level ctx variants; the legacy entries
   delegate to `context.Background()`.
3. `recordbuffer/record_buffer.go`: `flushLocked` / `replayWAL` bulk writes are
   wrapped in `context.WithTimeout(..., flushDBTimeout=2min)` — a half-open
   connection now returns an error after at most 2 minutes and the pass retries
   instead of blocking indefinitely.

**Status: ✅ FIXED (2026-08-27)** — also raised the PG/MySQL bulk chunk from
39 rows to 500 rows per statement (`certChunkSize`; SQLite keeps the 999-variable
bound), cutting write round-trips ~13× and lifting MySQL AIC @100ms from 4,325 to
**6,034 certs/s**. Real-DB verification: MySQL regular @100ms (original crash
scenario) 7,575 certs/s, AIC @100ms 6,034 certs/s, AIC @600ms 4,114/s — all
exit=0 with a full report; PG AIC @600ms 4,054/s (no regression). `-race` green.
New unit tests: `TestEnsureMySQLTimeouts`, `TestBulkInsertCertRecordsCtxCancelled`,
`TestBulkStoreDANoncesCtxCancelled`.

Status of each fix is tracked in `docs/NEXT_STEPS.md` and `docs/zh/NEXT_STEPS.md`.

> **Real-DB verification complete** (2026-08-20): `BulkStoreDANonces` / `BulkRevokeCertificates` dialect branches verified against live PostgreSQL 15 and MariaDB 10.11 — new `TestPGBulkStoreDANonces` / `TestPGBulkRevokeCertificates` / `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates` (fresh per-run database, batch store + duplicate-ignore/idempotent re-run + 32-byte validation + per-row reasons across chunk boundaries). Full `go test -tags postgres` / `-tags mysql ./...` suites green.
## 🔴 R13 — Full-buffer DA nonce store thundering-herds onto flushMu (2026-08-27)

**Location:** `recordbuffer/record_buffer.go` (`AddDANonce` / `AddDANonceSync`)

When the record buffer reaches `maxPending`, `AddDANonce` performed a
synchronous `FlushAll()` on every request. `FlushAll` holds `flushMu` for the
entire pass (a bulk insert of **all** pending records, O(backlog)), so once the
buffer filled — sustained AIC load fills it at ~18s with the default 20k
pending — every request goroutine serialized behind the same `flushMu`: the
whole server froze with pending pinned at maxPending. Under the engine bench
this surfaced as a hard throughput collapse: the 40s AIC @100ms run plateaued at
~108k successes (identical to the 20s run) with p99 growing to ~22s and ~2,000
goroutines blocked in `FlushAll`, while the drain goroutine was still mid-flush
of an 85k-record batch.

**Fix:** the synchronous append paths no longer flush themselves. When full,
`waitForCapacity()` signals the drain loop and sleeps on a close-and-replace
broadcast channel (`capacitySignal`) that the drain fires on every flush pass;
all waiters wake at once the moment capacity frees. If the drain cannot free
capacity within `fullWaitTimeout` (5s), `AddDANonce` returns the new
`recordbuffer.ErrBackpressure`, which `Engine.StoreDANonce` normalizes onto
`engine.ErrBackpressure` so the serve caller responds 503 (issuance fails, no
certificate is minted, replay protection is never weakened). This is genuine
backpressure — a full buffer means the backend cannot absorb writes — degraded
gracefully instead of a server-wide deadlock.

**Status: ✅ FIXED (2026-08-27)** — 40s AIC @100ms (MySQL, engine, 2500 agents)
restored from the ~108k plateau to **~163k successes (~4.1k certs/s)**, which is
exactly the sustained MySQL bulk-insert ceiling (~8k records/s incl. DA nonces,
measured: 500-row chunks ≈ 7.3k certs/s standalone); no goroutines block in
`FlushAll` anymore; backpressure surfaces as clean 503s. 20s runs burst to
~5.3k certs/s above the ceiling (buffer absorbs), settling to ~4k/s sustained.
New unit tests: `TestRecordBufferAddDANonceWaitsForCapacity`,
`TestRecordBufferAddDANonceConcurrentWaits`,
`TestRecordBufferAddDANonceBackpressureTimeout`. `-race` green across
`recordbuffer/`/`engine/`/`db/`.
