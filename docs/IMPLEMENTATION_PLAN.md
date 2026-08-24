# varwof-engine Implementation Plan (IMPLEMENTATION_PLAN)

> Audience: AI / engineers responsible for implementing the in-memory engine.
> Prerequisite: read `docs/REQUIREMENTS.md` (requirements baseline) and the existing implementation extracted into this directory.
> Status: **Phase A–F completed** (engine package compiles and passes tests). Phase G requires varwof-core integration, executed separately.

## 0. Current State (Extracted, Compilable, Testable)

```
varwof-engine/
  db/             package db  — SQL backend (3-way dialect + schema v1 (consolidated) + all table methods)
  recordbuffer/   package recordbuffer — write pipeline (WAL + backpressure + checkpoint + FlushAll)
  cache/          package cache — TTL Cache + serial-associated LRU
  docs/
    REQUIREMENTS.md
    IMPLEMENTATION_PLAN.md
  go.mod
```

Verification:
```bash
go test -count=1 ./...
```

## 1. Implementation Order (Recommended)

### Phase A — In-Memory Index Core (Engine Skeleton) ✅ Done
1. Create `engine/` package, define `Engine` struct + `EngineOptions` (per-index capacity limits, grace window, janitor interval).
2. Implement `CertIndex`:
   - Primary map: `map[caName]map[serial]*db.CertRecord` (or composite key string).
   - Secondary indexes: issuerDN+serial, spki_hash, principal_uid, agent_id, (ca,cn,status='V').
   - **Time-window index**: per-CA sorted slice (or insertion-sort keeping order) by `not_after`, supporting binary "is serial in any valid window" / "集合 of not_after >= t". Writes maintain order (can defer sort + dirty flag, sort before reads).
3. Implement `RevokedSet`: per-CA `map[serial]*db.RevokedCertEntry` + sorted list by revoked_at (CRL generation order).
4. Implement `NonceSet`: `map[string]nonceEntry{used bool, exp time.Time}` + atomic Consume (CAS).
5. Implement `SubCAIndex` / `TrustIndex` / `AICIndex` (low-frequency, plain maps).
6. All index read/write uses `sync.RWMutex`; high-concurrency point queries can upgrade to sharded maps later.

### Phase B — Write Pipeline Wiring ✅ Done
1. `engine` holds `*recordbuffer.RecordBuffer` (write certificates) + direct bulk writes (nonce/sub_ca/trust/aic use their own BulkInsert or single writes).
2. `IssueCert`: update memory index first (succeed → committed), then `rb.Add(rec)`. Memory index is the source of truth; persistence failure does not rollback memory (next flush retry / startup rebuild converges).
3. `RevokeCert`: memory set to R + insert into `RevokedSet` + `OnCertRevoked(serial)` + construct UPDATE batch into pipeline.
4. Crash safety: inherits `recordbuffer` WAL; if nonce/sub_ca also need crash safety, extend WAL record types (v2: JSONL with `op` field).
5. **Consistency**: read methods go through memory index; `FlushAll()` is only for ops fallback, varwof-core no longer needs manual flush conventions before revocation.

### Phase C — Startup Rebuild (load) ✅ Done
1. `NewEngine`: `d.ListCerts...` full load (per-CA paged, reusing `BulkInsert` reverse scan), build all indexes; `GetRevokedCertEntries` load `RevokedSet`; nonce table load unexpired nonces; sub_ca/trust/aic full load.
2. During rebuild: provide `Loading()` state, upper layer can reject writes or serve read-only fallback.
3. Rebuild duration tracked (slog + metric).

### Phase D — Janitor & Bounded Memory ✅ Done
1. Background ticker (default 60s):
   - Prune `not_after < now - grace` V-status certificates from hot zone (optional keep cold map or discard — v1 discards, since backend is authoritative).
   - Clean expired nonces.
   - Clean expired revocation entries (not_after < now removed from RevokedSet).
2. Overflow eviction: `max_certs` exceeded → evict oldest expired; otherwise reject new inserts (upper layer returns 503 or logs alert).

### Phase E — Metrics & Logging ✅ Done
1. `Metrics()` outputs Prometheus: `varwof_engine_certindex_size` / `varwof_engine_revokedset_size` / `varwof_engine_nonceset_size` / `varwof_engine_window_evictions_total` / `varwof_engine_read_hit_total{op}` / `varwof_engine_pipeline_pending` / `varwof_engine_flush_duration_seconds`.
2. slog: rebuild completion, slow flush (>50ms), backpressure trigger, janitor prune counts.

### Phase F — Unit Tests + Benchmarks ✅ Done
- Tests: per-index CRUD, time-window pruning, nonce CAS concurrency, CRL generation pure-memory correctness, write pipeline + memory consistency (issue → immediately readable → revoke → immediately visible).
- Benchmarks (compared to varwof-core baseline, see REQUIREMENTS NFR-1):
  - `BenchmarkGetCertStatus` (hit/miss/expired).
  - `BenchmarkIssueCert` (memory write, excludes persistence).
  - `BenchmarkGetRevokedCertEntries` (1K/10K/100K revoked sets).
  - `BenchmarkConsumeNonce` (concurrent CAS).

### Phase G — varwof-core Integration (Gradual Migration) ⏳ Pending varwof-core integration
> Key: gradual replacement, not one-shot. Each replacement point runs varwof-core full regression (`go test -count=1 -short ./...`).

1. `internal/serve`: `Server` holds `*engine.Engine`; alongside `getEngine()`.
2. First batch (reads, lowest risk):
   - `GetCertStatusByIssuer` (handshake revocation) → engine (replaces `revocationCache`).
   - `GetCertStatus` (OCSP handler) → engine.
   - `GetCert` / `GetCertStatus` (data-plane APIs).
3. Second batch (write paths):
   - `apiIssueCert`: `SkipDB=true` + in-memory `IssueCert` (replaces RecordBuffer.Add to DB, routes to engine instead).
   - Revocation APIs: in-memory `RevokeCert` + remove entry-point `FlushRecordBuffer()`.
   - nonce API (renew/token) → engine `ConsumeNonce`.
4. Third batch (CRL/management):
   - CRL generation: `GetRevokedCertEntries` → engine.
   - Duplicate CN check, SPKI lookup, principal listing → engine.
5. Cleanup: remove old `revocationCache` / `authScopesCache` (keep `cache` package for OCSP LRU).
6. Full regression + load test comparison (NFR-1 table).

## 2. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Memory index drift from backend (persistence failure) | Idempotent persistence + startup rebuild converges; persistence failure alert + retry queue |
| Unbounded memory growth | Janitor pruning + overflow eviction (Phase D) + metric monitoring |
| Time-window index sort overhead | Deferred sort + dirty flag; write path only O(log n) insert into sorted slice |
| Slow full rebuild on startup (large DB) | Paged streaming load + progress logs; optional cold-start build indexes only without loading DER |
| varwof-core migration regression | Gradual replacement + full test at each step; feature flag fallback during coexistence |
| nonce CAS race | In-memory single-machine authority, `ConsumeNonce` single-lock CAS; no cross-instance issues |

## 3. Acceptance Criteria

- [x] `varwof-engine` standalone module build + vet + test all green (including concurrency tests).
- [x] All FR-1..FR-9 implemented; REQUIREMENTS NFR-1 performance targets met (benchmarks in `engine_bench_test.go`: GetCertStatus ~160–300ns, IssueCert memory ~14µs, ConsumeNonce concurrent CAS).
- [x] Tests and coverage recorded in `docs/TESTING.md` (cache 99.1% / engine 97.0% / db 83.5% / recordbuffer 81.6%); remaining work in `docs/NEXT_STEPS.md`.
- [x] `OnCertRevoked` precise invalidation path effective (handshake cache + OCSP LRU) — via `EngineOptions.OnCertRevoked` callback, to be wired after varwof-core integration.
- [ ] Crash recovery: kill -9 → restart → WAL replay → in-memory index intact (already covered by `recordbuffer` WAL; engine full rebuild covered by `TestEngineRebuildFullState` and `TestConvergenceMemoryAuthoritative`; end-to-end verification pending varwof-core integration environment).
- [ ] varwof-core gradual migration then full `go test -count=1 -short ./...` green, no manual flush conventions remaining (pending Phase G).
- [x] Doc-driven: new exported functions have doc comments; `docs/api.md` / `docs/config.md` / `docs/functions.md` kept in sync with implementation.
