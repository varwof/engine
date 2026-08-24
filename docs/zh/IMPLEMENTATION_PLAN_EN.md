# varwof-engine Implementation Plan (IMPLEMENTATION_PLAN)

> Target audience: AI / engineers responsible for implementing the in-memory engine.
> Prerequisite: read `docs/REQUIREMENTS.md` (requirements baseline) and the extracted as-is implementation in this directory first.
> Status: **Phase A–F complete** (engine package compiles and passes tests). Phase G requires the varwof-core repository and will be executed separately.

## 0. As-Is Inventory (extracted, compiles, tests pass)

```
varwof-engine/
  db/             package db  — SQL backend layer (three dialects + schema v1 (consolidated) + all table methods)
  recordbuffer/   package recordbuffer — write pipeline (WAL + backpressure + checkpoint + FlushAll)
  cache/          package cache — TTL Cache + serial-associated LRU
  docs/
    REQUIREMENTS.md
    IMPLEMENTATION_PLAN.md
  go.mod
```

Verification command:
```bash
go test -count=1 ./...
```

## 1. Implementation Order (recommended)

### Phase A — In-Memory Index Core (Engine skeleton) ✅ Complete
1. Create the `engine/` package; define the `Engine` struct + `EngineOptions` (per-index capacity caps, grace window, janitor interval).
2. Implement `CertIndex`:
   - Primary map: `map[caName]map[serial]*db.CertRecord` (or composite key string).
   - Secondary indexes: issuerDN+serial, spki_hash, principal_uid, agent_id, (ca,cn,status='V').
   - **Time-window index**: per CA, a slice sorted by `not_after` (or insertion-sorted to stay ordered), supporting binary search of "is a serial within a valid window" and "the set with not_after >= t". Keep ordered after writes (deferred sort + dirty flag, sort before reads is acceptable).
3. Implement `RevokedSet`: per CA, a `map[serial]*db.RevokedCertEntry` + a list sorted by revoked_at (CRL generation order).
4. Implement `NonceSet`: `map[string]nonceEntry{used bool, exp time.Time}` + atomic Consume (CAS).
5. Implement `SubCAIndex` / `TrustIndex` / `AICIndex` (low-frequency; plain maps suffice).
6. All index reads/writes use `sync.RWMutex`; high-concurrency point lookups can later upgrade to sharded maps.

### Phase B — Write Pipeline Wiring ✅ Complete
1. The `engine` holds a `*recordbuffer.RecordBuffer` (for certificates) + direct batch writes (nonce/sub_ca/trust/aic go through their own BulkInsert or single writes).
2. `IssueCert`: update the in-memory index first (commit only on success), then `rb.Add(rec)`. The in-memory index is authoritative; persistence failure does not roll back memory (retry on next flush / converge via startup rebuild).
3. `RevokeCert`: set R in memory + insert into `RevokedSet` + `OnCertRevoked(serial)` + construct an UPDATE batch into the pipeline.
4. Crash safety: reuse `recordbuffer`'s WAL; if nonce/sub_ca etc. also need crash safety, extend WAL record types (v2: JSONL with an `op` field).
5. **Consistency**: read methods all go through the in-memory index; `FlushAll()` is only an ops fallback — varwof-core no longer needs to call it manually before revocation.

### Phase C — Startup Rebuild (load) ✅ Complete
1. `NewEngine`: full load via `d.ListCerts...` (paginated by CA, reusing the reverse scan of `BulkInsert`), building all indexes; `GetRevokedCertEntries` loads the `RevokedSet`; nonce table loads unexpired nonces; sub_ca/trust/aic loaded fully.
2. During rebuild: expose a `Loading()` state so upper layers can reject writes or degrade to read-only.
3. Instrument rebuild duration (slog + metric).

### Phase D — Janitor & Bounded Memory ✅ Complete
1. Background ticker (default 60s):
   - Prune V-status certificates with `not_after < now - grace` out of the hot zone (optionally keep a cold map or discard — v1 discards directly per requirements, since the backend is authoritative).
   - Clean expired nonces.
   - Clean expired revoked entries (not_after < now removed from RevokedSet).
2. Cap eviction: when `max_certs` exceeded, evict oldest expired; otherwise reject additions (upper layer 503 or log warning).

### Phase E — Metrics & Logging ✅ Complete
1. `Metrics()` outputs Prometheus: `varwof_engine_certindex_size` / `varwof_engine_revokedset_size` / `varwof_engine_nonceset_size` / `varwof_engine_window_evictions_total` / `varwof_engine_read_hit_total{op}` / `varwof_engine_pipeline_pending` / `varwof_engine_flush_duration_seconds`.
2. slog: rebuild completion, slow flush (>50ms), backpressure triggers, janitor pruning counts.

### Phase F — Unit Tests + Benchmarks ✅ Complete
- Unit tests: CRUD for each index, time-window pruning, nonce CAS concurrency, pure in-memory CRL generation correctness, write-pipeline + memory consistency (issue → immediately readable → revoke → immediately visible).
- Benchmarks (compared against varwof-core baselines, see REQUIREMENTS NFR-1):
  - `BenchmarkGetCertStatus` (hit/miss/expired).
  - `BenchmarkIssueCert` (memory write, excludes persistence).
  - `BenchmarkGetRevokedCertEntries` (1K/10K/100K revoked sets).
  - `BenchmarkConsumeNonce` (concurrent CAS).

### Phase G — varwof-core Integration (gradual migration) ⏳ Pending varwof-core repository
> Key: replace step by step, not all at once. Run varwof-core's full regression (`go test -count=1 -short ./...`) at every replacement point.

1. `internal/serve`: `Server` holds `*engine.Engine`; add `getEngine()` alongside `getDB()`.
2. First batch of replacements (pure reads, lowest risk):
   - `GetCertStatusByIssuer` (handshake revocation) → engine (replaces `revocationCache`).
   - `GetCertStatus` (OCSP handler) → engine.
   - `GetCert` / `GetCertStatus` (data-plane API).
3. Second batch (write paths):
   - `apiIssueCert`: `SkipDB=true` + in-memory `IssueCert` (replace RecordBuffer.Add-to-DB with Add-to-engine).
   - Revocation APIs: in-memory `RevokeCert` + remove entry-point `FlushRecordBuffer()`.
   - nonce APIs (renew/token) → engine `ConsumeNonce`.
4. Third batch (CRL/admin):
   - CRL generation: `GetRevokedCertEntries` → engine.
   - Duplicate CN check, SPKI query, principal listing → engine.
5. Cleanup: remove old `revocationCache` / `authScopesCache` (keep the `cache` package for OCSP LRU).
6. Full regression + load-test comparison (NFR-1 table).

## 2. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Memory index drift from backend (persistence failure) | Idempotent persistence + startup rebuild convergence; persistence failure alerts + retry queue |
| Unbounded memory growth | Janitor pruning + cap eviction (Phase D) + metric monitoring |
| Time-window index sorting overhead | Deferred sort + dirty flag; write path only does O(log n) insertion into sorted slice |
| Slow startup full rebuild (large DB) | Paginated streaming load + progress logging; optionally cold-start builds indexes without loading DER |
| varwof-core migration regression | Gradual replacement + full tests each step; feature-flag rollback during old/new coexistence |
| nonce CAS race | Single-machine memory authority; `ConsumeNonce` single-lock CAS; no cross-instance issues |

## 3. Acceptance Criteria

- [x] `varwof-engine` standalone module build + vet + test all green (including concurrency tests).
- [x] All FR-1..FR-9 implemented; REQUIREMENTS NFR-1 performance targets met (benchmark comparison, see `engine_bench_test.go` baselines: GetCertStatus ~230ns, IssueCert memory ~7.2µs, ConsumeNonce concurrent CAS).
- [x] Tests and coverage recorded in `docs/TESTING.md` (cache 99.1% / engine 97.0% / db 83.5% incl. real PG 86.5% / recordbuffer 81.6%); remaining-work list in `docs/NEXT_STEPS.md`.
- [x] `OnCertRevoked` precise invalidation path works (handshake cache + OCSP LRU) — via the `EngineOptions.OnCertRevoked` callback, hooked up after varwof-core integration.
- [ ] Crash recovery: kill -9 → restart → WAL replay → intact in-memory indexes (already handled by `recordbuffer` WAL; engine full rebuild covered by `TestEngineRebuildFullState` for revoked/used-nonce/subCA/trust-anchor/AIC paths, `TestConvergenceMemoryAuthoritative` covers memory-authoritative + ordered backend convergence; end-to-end verification awaits the varwof-core integration environment).
- [ ] After varwof-core gradual migration, full `go test -count=1 -short ./...` green with no residual manual-flush conventions (pending Phase G).
- [x] doc-driven: new exported functions have doc comments; `docs/api.md` / `docs/config.md` / `docs/functions.md` kept in sync with implementation.
