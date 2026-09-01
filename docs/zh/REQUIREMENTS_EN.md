# varwof-engine Requirements Specification (REQUIREMENTS)

> Version: v0.2
> Status: **Implemented** (the engine package was delivered per this spec's Phase A–F; Phase G pending varwof-core repository integration)
> Implementation owner: AI implementation agent (opencode)

## 1. Background & Goals

varwof-core's current data layer has the following structural contradictions (confirmed by high-concurrency load testing):

1. **Write path**: SQLite global page-cache lock + single-writer lock are throughput bottlenecks. The existing RecordBuffer decouples "signing + DB write"; batch persistence raised throughput from 33 TPS → 7142 TPS (same machine, EC P-256, a 52x improvement), but it is still "async persistence + memory as a mere flush buffer" — the memory layer does not participate in reads; reads still hit SQL.
2. **Read path**: mTLS handshake, OCSP, CRL, and nonce validation are all high-frequency point lookups. Currently handled by 3 independent small caches (`revocationCache`, `authScopesCache`, OCSP LRU) each with TTL + manual invalidation, scattered across `cmd/pki/serve.go` and `internal/serve` with no unified in-memory data plane.
3. **Visibility window**: Under RecordBuffer, new certificates cannot be read for ≤500ms after issuance; before revocation one must manually call `FlushRecordBuffer()` to synchronously drain, otherwise the race of "issued but revocation UPDATE matched 0 rows" occurs.
4. **No time dimension**: OCSP/CRL queries do not prune by certificate validity window; expired certificates stay resident on the hot path — memory/queries unbounded.

**Goal**: build an **in-memory-centric dedicated high-speed data subsystem** (varwof-engine):

- All high-frequency read/write queries hit in-memory indexes, **memory is truth**, zero SQL reads, writes go to memory first then persist asynchronously.
- Batch persistence to backend databases (SQLite/PG/MySQL three dialects), crash-safe (WAL).
- Maintain dedicated efficient query structures for hot data such as OCSP / CRL / nonce / cert status, optimized by certificate validity window.
- Single-instance authority (multi-instance sharing of the backend DB is handled by upper layers; this library v1 does not do distributed consistency).
- As an independent subproject `github.com/varwof/engine`; varwof-core integrates via **brand-new interfaces with gradual migration**.

## 2. Scope

### 2.1 Hot-Path Data (in-memory storage, 5 categories)

| Data | Source Table | In-Memory Purpose |
|---|---|---|
| Certificates | `certificates` | Status point lookups (OCSP/handshake), CRL generation, SPKI/principal/AIC associated queries, duplicate CN check, counting |
| Revoked set | `certificates` (status='R') | CRL generation, fast revocation determination (no full-table scan) |
| nonce | `renewal_tokens` | One-time anti-replay (Store/Consume/IsUsed), TTL auto-cleanup |
| Sub-CA | `sub_cas` | Sub-CA status/protocol point lookups, CA relationship traversal |
| Trust anchor | `trust_anchors` | Hot data for trust chain verification |
| AIC extensions | `aic_extensions` | AIC queries by (ca,serial)/principal/agent |
| Users | `rbac_users` | **Auth hot data (new 2026-08-27)**: full rows resident (username→credentials/role/CA scope/enabled + id index); credential checks, role/cascope resolution and token joins never hit SQL |
| API tokens | `rbac_api_tokens` | **Auth hot data (new 2026-08-27)**: only SHA-256 hashes resident (never raw tokens); reads enforce expiry + owning user enabled in memory (mirrors `db.GetToken`'s JOIN+WHERE semantics) |

> audit_log / audit_salts / acme_* / ra_* / webhook_subscriptions / key_escrow / ct_logs / gateway_registry / scep_requests / cross_certs / ca_meta and other **low-frequency tables remain pure SQL** (passed through via the underlying `db` package). **rbac_users / rbac_api_tokens are auth hot data as of 2026-08-27**: engine loads them in full at startup and reads are memory-is-truth (serve reads engine-first, DB-fallback); writes go through serve write-through (persist to DB first, then refresh the resident row).

### 2.2 Backend Persistence (write-through target)

All three dialects retained: SQLite (default, file + WAL) / PostgreSQL / MySQL. The in-memory engine only cares about "batch semantics of inserts/deletes/updates"; concrete SQL is handled by the underlying `db` package (`db/` in this directory); dialect differences are fully encapsulated in `db.Dialect`.

### 2.3 Non-Goals (explicitly out of scope for v1)

- Distributed consistency / multi-instance cache synchronization (single-instance authority).
- Putting all tables into memory.
- The in-memory engine's own data persistence (e.g., snapshots); crash recovery relies on backend WAL + full rebuild (see §7).

## 3. Architecture Overview

```
                    ┌──────────────────────────────────────────────┐
                    │  varwof-engine (memory-centric engine)        │
  varwof-core ──────► │                                              │
  (serve handlers)   │  ┌────────────────────────────────────────┐  │
                    │  │ Engine (memory is truth)                 │  │
                    │  │  CertIndex   — cert status/time-window index │
                    │  │  RevokedSet  — revoked set (CRL snapshot)    │
                    │  │  NonceSet    — one-time nonces               │
                    │  │  SubCAIndex  — sub-CAs                       │
                    │  │  TrustIndex  — trust anchors                 │
                    │  │  AICIndex    — AIC extensions                │
                    │  │  → Read: O(1)/range queries              │  │
                    │  │  → Write: into memory index first (atomic)   │
                    │  └────────────┬─────────────────────────────┘  │
                    │               │ write event stream              │
                    │               ▼                               │
                    │  ┌────────────────────────────────────────┐  │
                    │  │ WritePipeline (batch persistence, from RecordBuffer)│ │
                    │  │  WAL pre-write log → bulk BulkInsert     │  │
                    │  │  checkpoint / backpressure / FlushAll   │  │
                    │  └────────────┬─────────────────────────────┘  │
                    └───────────────┼──────────────────────────────┘
                                    ▼
                       ┌────────────────────────┐
                       │ db (SQL backend, 3 dialects) │
                       │  SQLite / PG / MySQL    │
                       └────────────────────────┘
```

## 4. Functional Requirements

### 4.1 In-Memory Indexes (Engine)

**FR-1 Certificate index `CertIndex`**
- Primary index: `(ca_name, serial_number)` → `CertRecord` (including status, NotBefore/NotAfter/RevokedAt/RevokeReason/DER reference).
- Secondary indexes (maintained synchronously on write):
  - `(issuer_dn, serial_number)` → status (handshake revocation point lookup, corresponding to `GetCertStatusByIssuer`).
  - `spki_hash` → `[]CertRecord` (query certificates by SPKI).
  - `principal_uid` → `[]CertRecord` (revoke/list by person).
  - `agent_id` → `[]CertRecord`.
  - `(ca_name, common_name, status='V')` → active certificates (duplicate CN check).
  - **`(ca_name, status)` time-window index sorted by `not_before`/`not_after`** (see FR-3).

**FR-2 Revoked set `RevokedSet`**
- Per CA, maintain the set of revoked entries with `status='R'` and `not_after >= now`, sorted by `revoked_at`.
- Corresponds to `GetRevokedCertEntries` (CRL generation) and `GetRevokedCerts`; **CRL generation is a pure in-memory traversal, zero SQL**.
- Revocation operations `RevokeCert` / `RevokeCertsByPrincipalUid` / `RevokeCertsBySubCA`: atomically update `CertIndex` status in memory + insert into `RevokedSet` + trigger write-pipeline batch persistence + trigger cache invalidation.

**FR-3 Time-Window Optimization (certificate validity window, key user requirement)**
- OCSP point lookup: first hit `CertIndex` by `(ca, serial)`; if `NotAfter < now` and `status='V'`, return `Unknown` directly (no DB access), consistent with current handler semantics (`internal/ocsp/handler.go:239`).
- **Window index**: per CA, maintain a structure sorted by `not_after` (sorted slice / b-tree) supporting:
  - Fast determination of "does a given serial fall within any valid window";
  - Expiry pruning: background janitor periodically moves entries with `not_after < now - grace` out of hot memory (or marks them read-only cold), keeping memory bounded;
  - CRL generation only traverses revoked entries with `not_after >= now` (current SQL already carries `AND not_after >= ?`; the in-memory version inherits that semantic).
- Metrics: `evicted_expired`, `window_hit/miss`, `revokedset_size`, `certindex_size`.

**FR-4 nonce one-time set `NonceSet`**
- `StoreNonce` / `ConsumeNonce` / `IsNonceUsed`: in-memory map + TTL, atomic.
- Concurrency safe: Consume must be an atomic CAS of "unused → used" semantics (concurrent double-spend: only one succeeds).
- Background TTL cleanup (corresponding to `CleanupExpiredNonces`), batch-deleting backend `renewal_tokens`.
- Note: MySQL `VARBINARY(16)` / PG `BYTEA` / SQLite `BLOB` nonce primary-key dialect differences are handled by the underlying db package.
- **DA nonce (32B, `da_nonces`) anti-replay requires persist-before-confirm**: with WAL enabled, nonces are synchronously fsynced to WAL (`AddDANonceSync`) and batch-converged to the backend (`BulkStoreDANonces`); without WAL, they buffer through the batch write pipeline (`AddDANonce`) and converge on the next bulk flush (memory is authoritative for replay checks; unflushed nonces are not crash-safe on WAL-less backends by design). See `docs/RISKS.md` R1/R2.

**FR-5 Sub-CA / Trust Anchor / AIC**
- `SubCAIndex`: `(name)` → SubCA record + `parent_ca` reverse index.
- `TrustIndex`: `(id)` → TrustAnchor record + trusted/source filtering.
- `AICIndex`: `(ca_name, serial)` → AICExtension, secondary `principal_uid` / `agent_id`.

### 4.2 Write Pipeline (WritePipeline, derived from RecordBuffer)

**FR-6 Write pipeline capabilities (inherits all RecordBuffer mechanisms)**
- `Add(rec)` writes to the in-memory index first (cannot fail — memory is truth), then appends to the write pipeline.
- Batching: `threshold` records or `max_latency` expiry triggers bulk persistence (BulkInsert).
- Backpressure: `max_pending` hard cap; when exceeded `Add` returns false → upper layer responds 503.
- WAL pre-write log: crash-safe, replayed on restart. `<db>-records.wal` (only for file-backed SQLite; `:memory:`/PG/MySQL have no WAL).
- WAL checkpoint: periodic convergence when `pending==0`, preventing unbounded WAL growth.
- `drain()` continuous-drain rate limiting against lost signals.
- `FlushAll()`: synchronous drain before read-modify-write operations (revoke/renew), **but since the in-memory index is already visible ahead of time, varwof-core no longer needs manual flush conventions** (see FR-7 consistency).
- **Sharded backend writers (R4)**: revoke/nonce/metadata operations partitioned by FNV-1a key hash across `WriteWorkers` goroutines — same-key operations (nonce Store→Consume, certificate issue→revoke, sub-CA re-insert) stay ordered within a single goroutine; different keys run in parallel. `FlushAll` sets a barrier across all shards. Certificate bulk insertion remains on the RecordBuffer path (SQLite single-writer lock).

**FR-7 Consistency model: memory is truth**
- **Read-after-write**: `IssueCert` (memory insert) → immediate `GetCertStatus` / `GetCertBySPKIHash` hits memory — no ≤500ms visibility window; **the convention of manual `FlushRecordBuffer()` before revocation is abolished**.
- **Revocation**: `RevokeCert` atomically sets R in memory + notifies `OnCertRevoked` → precise cache invalidation; backend persistence is asynchronous.
- **Crash semantics**: loss of in-memory indexes → full rebuild from backend at startup (see §7); WAL only protects batches not yet persisted in the write pipeline.

### 4.3 Unified Cache Invalidation

**FR-8 Cache (`cache` package extracted)**
- Generic TTL `Cache` (bounded; when full, clear expired first then drop new): handshake revocation cache, authScopes.
- Generic LRU `LRU` (serial-associated batch invalidation): OCSP response cache.
- `OnCertRevoked(serial)` callback → precise invalidation (handshake cache + OCSP LRU `PurgeSerial`); bulk revocation → full invalidation.

### 4.4 External Interfaces (new API for varwof-core)

**FR-9 Proposed Engine API (converged against varwof-core call sites during implementation, see `docs/IMPLEMENTATION_PLAN.md`)**

```go
type Engine struct { ... }

// Construction: full load from backend DB → resident in-memory indexes
func NewEngine(d *db.DB, opts EngineOptions) (*Engine, error)

// Certificates (read)
func (e *Engine) GetCert(caName, serial string) (*db.CertRecord, error)
func (e *Engine) GetCertStatus(caName, serial string) (*db.CertStatus, error)
func (e *Engine) GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error)
func (e *Engine) GetCertBySPKIHash(spkiHash, caName, status string) ([]*db.CertRecord, error)
func (e *Engine) ListCertsByPrincipalUid(uid, status string) ([]*db.CertRecord, error)
func (e *Engine) CheckDuplicateCN(caName, cn string, nb, na time.Time) error

// Certificates (write) — memory first, async persistence
func (e *Engine) IssueCert(rec *db.CertRecord) error          // write memory + enqueue pipeline
func (e *Engine) RevokeCert(caName, serial string, reason int) error
func (e *Engine) RevokeCertsByPrincipalUid(uid string, reason int) (int, error)
func (e *Engine) RevokeCertsBySubCA(caName string, reason int) (int, error)

// CRL (pure in-memory generation)
func (e *Engine) GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)
func (e *Engine) GetRevokedCerts(caName string) ([]*db.CertRecord, error)

// nonce
func (e *Engine) StoreNonce(nonce []byte) error
func (e *Engine) ConsumeNonce(nonce []byte) error
func (e *Engine) IsNonceUsed(nonce []byte) (bool, error)

// Sub-CA / trust anchor / AIC
func (e *Engine) GetSubCA(name string) (*db.SubCA, error)
func (e *Engine) GetTrustAnchor(id int) (*db.TrustAnchor, error)
func (e *Engine) GetAICExtensionByCert(caName, serial string) (*db.AICExtension, error)

// Lifecycle
func (e *Engine) Start() error      // startup rebuild + janitor + write pipeline
func (e *Engine) Stop() error       // FlushAll + stop janitor
func (e *Engine) FlushAll() error   // synchronous drain (ops/revocation fallback)
```

> High-frequency read methods must avoid full `cert_der` deserialization (reuse the existing lightweight `CertStatus` struct). Low-frequency management interfaces like `ListCerts` / `ListCertsFilteredPage` / pagination may continue passing through the underlying `db` package for now.

## 5. Non-Functional Requirements

### NFR-1 Performance (reference existing load-test baselines)
| Scenario | Existing baseline (varwof-core, post-RecordBuffer) | Target |
|---|---|---|
| Single issuance (sequential) | 1724 TPS | ≥ 1800 TPS |
| Single issuance (concurrent w16) | 16350 TPS | ≥ 20K TPS |
| mTLS handshake revocation point lookup | Dominated by SQLite global pcache lock | Zero SQL (pure in-memory map), P99 microsecond-level |
| OCSP point lookup | SQL + LRU | Pure memory, hits are zero-SQL |
| CRL generation | Full SQL scan + filter | Pure in-memory traversal of `RevokedSet` |
| nonce Consume | Two-phase SQL | In-memory atomic CAS |

### NFR-2 Bounded Memory
- Default residency: full `certindex` (certificate record count × ~1KB structured reference per record); expired certificates pruned per FR-3.
- Configurable caps: `max_certs` (over-limit evicts oldest expired), `max_nonces`, `max_revoked_entries`.
- Provides `Metrics()` Prometheus output (size / evicted / hit-rate).

### NFR-3 Crash Safety
- Write-pipeline WAL guarantees replay after restart of batches "committed to memory but not persisted".
- Startup rebuild: full backend load → in-memory indexes; service availability during loading is decided by upper layers (may fall back to read-only first).
- Idempotent persistence: `INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` / `INSERT IGNORE` (dialect differences handled at the db layer).

### NFR-4 Concurrency Safety
- Index reads/writes use RWMutex / sharded shard maps; point lookups take read locks.
- `ConsumeNonce` must be atomic CAS.
- No global lock hotspots (leveraging RecordBuffer's solved slog lock contention / DB connection pool tuning experience).

### NFR-5 Observability
- Metrics: per-index size / hit rate / eviction / write-pipeline pending / flush duration / WAL size.
- Structured logging (slog) covering: rebuild duration, slow-flush alerts, backpressure triggers, janitor pruning.

## 6. Existing Implementation & Documentation Inventory (this directory)

| Path | Content | Status |
|---|---|---|
| `db/` | SQL backend layer: three-dialect Dialect, schema migration v1 (consolidated schema), CertRecord CRUD, BulkInsert, nonce, AIC, sub_ca, trust_anchor, rbac/acme/ra and all other table methods, distributed lock | ✅ Extracted from `core/internal/db`, tests green |
| `recordbuffer/` | Write pipeline: batch buffering + WAL + backpressure + checkpoint + drain + FlushAll | ✅ Extracted from `core/internal/serve/record_buffer.go` (`flushAll` exported as `FlushAll`), tests green |
| `cache/` | Generic TTL Cache + LRU (serial-associated invalidation) | ✅ Extracted and merged from `internal/ocsp/cache.go` + `cmd/pki/serve.go` + `internal/serve/rbac.go`, tests green |
| `engine/` | In-memory engine: CertIndex/RevokedSet/NonceSet/SubCA/Trust/AIC indexes + write pipeline wiring + startup rebuild + janitor + Metrics | ✅ Implemented per IMPLEMENTATION_PLAN Phase A–F, tests + benchmarks green |
| `docs/REQUIREMENTS.md` | Requirements specification | ✅ v0.2 implemented |
| `docs/IMPLEMENTATION_PLAN.md` | Implementation steps | ✅ Phase A–F complete, Phase G pending varwof-core |
| `docs/api.md` / `docs/config.md` / `docs/functions.md` | User-facing API / config / function documentation (doc-driven requirement) | ✅ Kept in sync with implementation |

## 7. Key Design Decisions (confirmed with user)

| Decision Point | Conclusion |
|---|---|
| Memory coverage | 5 hot-path categories (certificates/revoked set/nonce/sub_cas/trust_anchors/aic_extensions) |
| Backend dialects | SQLite / PG / MySQL — all three retained |
| Integration approach | Brand-new Engine API, varwof-core gradual migration (not signature-compatible) |
| Consistency | Memory is truth; writes to memory first, async persistence; manual flush convention abolished |
| Deployment form | Single-instance authority; v1 does not do distributed consistency |
| Time window | OCSP/CRL optimized by certificate validity window (FR-3) |
| Read/write path routing | **Reads must go through engine memory; direct DB access forbidden inside write paths**: any read within the write pipeline (RecordBuffer persistence) or revocation queuing path must hit the in-memory primary; adding "DB-read fallback" logic to hot paths is forbidden. Memory updates synchronously without delay; DB is only a persistence sink. Same rationale as ShardingSphere `transactionalReadQueryStrategy=PRIMARY` — under weak consistency do not introduce FIXED/DYNAMIC (DB-read fallback) |
