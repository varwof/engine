# varwof-engine Requirements Specification (REQUIREMENTS)

> Version: v0.2
> Status: **Implemented** (engine package delivered per this spec, Phase A–F; Phase G pending varwof-core integration)
> Implementation lead: AI implementation agent (opencode)

## 1. Background & Goal

varwof-core's current data layer exhibits the following structural contradictions (confirmed under high-concurrency load testing):

1. **Write path**: SQLite global page-cache lock + single-write lock is the throughput bottleneck. The existing RecordBuffer decouples "sign + write-to-DB", improving throughput from 33 TPS → 7142 TPS (same machine EC P-256, 52× improvement), but it remains "async persistence + memory only as pending buffer" — memory does not participate in reads, reads still hit SQL.
2. **Read path**: mTLS handshake, OCSP, CRL, nonce verification are all high-frequency point queries. Currently relies on 3 independent small caches (`revocationCache`, `authScopesCache`, OCSP LRU) each with its own TTL + manual invalidation, scattered across `cmd/pki/serve.go` and `internal/serve` — no unified memory data plane.
3. **Visibility window**: Under RecordBuffer, a newly issued certificate is unreadable for ≤500ms; before revocation you must manually `FlushRecordBuffer()` to drain synchronously, otherwise "issued but revocation UPDATE matches 0 rows" race occurs.
4. **No time dimension**: OCSP/CRL queries have no certificate-validity-time-window pruning; expired certificates remain in the hot path, memory/query unbounded.

**Goal**: Build an **in-memory-centric dedicated high-speed data subsystem** (varwof-engine):

- High-frequency read/write queries hit in-memory indexes; **memory is truth**, zero SQL for reads, writes go to memory first then persist asynchronously.
- Batch persistence to backend database (SQLite/PG/MySQL with 3-way dialect), crash-safe (WAL).
- Maintain dedicated efficient query structures for OCSP / CRL / nonce / cert-status hot data, optimized by certificate validity time window.
- Single-instance authority (multi-instance handled by upper layer sharing backend DB; v1 does not do distributed consensus).
- Standalone sub-project `github.com/varwof/engine`, varwof-core integrates via **entirely new API, gradual migration**.

## 2. Scope

### 2.1 Hot-Path Data (In-Memory Storage, 5 Categories)

| Data | Source Table | In-Memory Purpose |
|---|---|---|
| Certificates | `certificates` | Status point query (OCSP/handshake), CRL generation, SPKI/principal/AIC association queries, duplicate CN check, counting |
| Revoked set | `certificates` (status='R') | CRL generation, fast revocation check (no full-table scan) |
| Nonce | `renewal_tokens` | One-time anti-replay (Store/Consume/IsUsed), TTL auto-cleanup |
| Sub-CA | `sub_cas` | Sub-CA status/protocol point query, CA relationship traversal |
| Trust anchor | `trust_anchors` | Trust chain verification hot data |
| AIC extension | `aic_extensions` | AIC query by (ca,serial)/principal/agent |

> rbac_users / rbac_api_tokens / audit_log / audit_salts / acme_* / ra_* / webhook_subscriptions / key_escrow / ct_logs / gateway_registry / scep_requests / cross_certs / ca_meta etc. **low-frequency tables remain pure SQL** (via underlying `db` package passthrough), not loaded into memory.

### 2.2 Backend Persistence (Write-Through Target)

3-way dialect fully preserved: SQLite (default, file + WAL) / PostgreSQL / MySQL. The in-memory engine only concerns itself with "batch semantics of insert/update/delete"; concrete SQL is handled by the underlying `db` package (this directory's `db/`), dialect differences fully encapsulated in `db.Dialect`.

### 2.3 Non-Goals (v1 Explicitly Excluded)

- Distributed consistency / multi-instance cache sync (single-instance authority).
- All tables in memory.
- In-memory engine's own data persistence (e.g. snapshot); crash recovery relies on backend WAL + full rebuild (see §7).

## 3. Architecture Overview

```
                    ┌──────────────────────────────────────────────┐
                    │  varwof-engine (memory-centric engine)       │
  varwof-core ──────► │                                              │
  (serve handlers)  │  ┌────────────────────────────────────────┐  │
                    │  │ Engine (memory is truth)                 │  │
                    │  │  CertIndex   — cert status/time window  │  │
                    │  │  RevokedSet  — revoked set (CRL snapshot)│ │
                    │  │  NonceSet    — one-time nonce            │  │
                    │  │  SubCAIndex  — sub-CA                    │  │
                    │  │  TrustIndex  — trust anchor              │  │
                    │  │  AICIndex    — AIC extension              │  │
                    │  │  → read: O(1)/range query                │  │
                    │  │  → write: memory index first (atomic)    │  │
                    │  └────────────┬─────────────────────────────┘  │
                    │               │ write event stream              │
                    │               ▼                                 │
                    │  ┌────────────────────────────────────────┐  │
                    │  │ WritePipeline (batch persistence,       │  │
                    │  │   from RecordBuffer)                    │  │
                    │  │  WAL pre-write log → BulkInsert         │  │
                    │  │  checkpoint / backpressure / FlushAll   │  │
                    │  └────────────┬─────────────────────────────┘  │
                    └───────────────┼──────────────────────────────────┘
                                    ▼
                       ┌────────────────────────┐
                       │ db (SQL backend, 3-way) │
                       │  SQLite / PG / MySQL    │
                       └────────────────────────┘
```

## 4. Functional Requirements

### 4.1 In-Memory Indexes (Engine)

**FR-1 Certificate Index `CertIndex`**
- Primary index: `(ca_name, serial_number)` → `CertRecord` (including status, NotBefore/NotAfter/RevokedAt/RevokeReason/DER reference).
- Secondary indexes (maintained synchronously on write):
  - `(issuer_dn, serial_number)` → status (handshake revocation point query, `GetCertStatusByIssuer`)
  - `spki_hash` → `[]CertRecord` (SPKI-based certificate lookup)
  - `principal_uid` → `[]CertRecord` (per-person revocation / listing)
  - `agent_id` → `[]CertRecord`
  - `(ca_name, common_name, status='V')` → active certificates (duplicate CN check)
  - **`(ca_name, status)` time-window index by `not_before`/`not_after`** (see FR-3)

**FR-2 Revoked Set `RevokedSet`**
- Per-CA maintains `status='R'` AND `not_after >= now` revoked entries, sorted by `revoked_at`.
- Corresponds to `GetRevokedCertEntries` (CRL generation) and `GetRevokedCerts`; **CRL generation is pure in-memory traversal, zero SQL**.
- Revocation operations `RevokeCert` / `RevokeCertsByPrincipalUid` / `RevokeCertsBySubCA`: atomic in-memory `CertIndex` status update + `RevokedSet` insert + write pipeline trigger + cache invalidation.

**FR-3 Time-Window Optimization (Certificate Validity Window)**
- OCSP point query: first hit `CertIndex` by `(ca, serial)`; `NotAfter < now` with `status='V'` returns `Unknown` directly (no persistence), matching current handler semantics.
- **Window index**: per-CA structure sorted by `not_after` (sorted slice / b-tree), supporting:
  - Fast "is a serial in any valid window" check;
  - Expiry pruning: background janitor periodically moves entries with `not_after < now - grace` out of hot memory (or into read-only cold zone), ensuring bounded memory;
  - CRL generation only traverses `not_after >= now` revoked entries (current SQL already has `AND not_after >= ?`, in-memory version inherits this).
- Metrics: `evicted_expired`, `window_hit/miss`, `revokedset_size`, `certindex_size`.

**FR-4 One-Time Nonce Set `NonceSet`**
- `StoreNonce` / `ConsumeNonce` / `IsNonceUsed`: in-memory map + TTL, atomic.
- Concurrency safe: Consume must be "unused → used" atomic CAS semantics (concurrent double-spend allows only one success).
- Background TTL cleanup (corresponding to `CleanupExpiredNonces`), bulk deletes backend `renewal_tokens`.
- Note: MySQL `VARBINARY(16)` / PG `BYTEA` / SQLite `BLOB` nonce primary key dialect differences handled by underlying db package.
- **DA nonce (32B, `da_nonces`)** replay protection requires durability *before* acknowledgment: with WAL enabled the nonce is WAL-fsynced synchronously (`AddDANonceSync`) and converges to the backend in bulk (`BulkStoreDANonces`); without WAL it is persisted synchronously. See `docs/RISKS.md` R1/R2.

**FR-5 Sub-CA / Trust Anchor / AIC**
- `SubCAIndex`: `(name)` → SubCA record + `parent_ca` reverse index.
- `TrustIndex`: `(id)` → TrustAnchor record + trusted/source filtering.
- `AICIndex`: `(ca_name, serial)` → AICExtension, secondary `principal_uid` / `agent_id`.

### 4.2 Write Pipeline (WritePipeline, from RecordBuffer)

**FR-6 Write Pipeline Capabilities (inherits all RecordBuffer mechanisms)**
- `Add(rec)` writes to memory index first (cannot fail, memory is truth), then appends to write pipeline.
- Batch accumulation: `threshold` records or `max_latency` expiry triggers bulk persistence (BulkInsert).
- Backpressure: `max_pending` hard limit, exceeded → `Add` returns false → upper layer returns 503.
- WAL pre-write log: crash-safe, replays on restart. `<db>-records.wal` (file-backed SQLite only; `:memory:` / PG / MySQL have no WAL).
- WAL checkpoint: `pending==0` periodic convergence, prevents unbounded WAL growth.
- `drain()` consecutive drain resists signal-loss throttling.
- `FlushAll()`: read-modify-write operations (revocation/renewal) drain synchronously, **but memory index is already visible first, varwof-core no longer needs manual flush conventions** (see FR-7 consistency).
- **Sharded backend writer** (R4): revoke/nonce/meta ops are partitioned across `WriteWorkers` goroutines by FNV-1a key hash — same-key ops (nonce Store→Consume, cert issue→revoke, sub-CA re-insert) keep ordering on one goroutine; different keys run in parallel. `FlushAll` barriers every shard. Certificate batch inserts stay on the RecordBuffer path (SQLite single-writer).

**FR-7 Consistency Model: Memory is Truth**
- **Post-write read**: `IssueCert` (memory insert) → immediately `GetCertStatus` / `GetCertBySPKIHash` hits memory, no ≤500ms visibility window, **abolishes pre-revocation manual `FlushRecordBuffer()` convention**.
- **Revocation**: `RevokeCert` atomically sets R + notifies `OnCertRevoked` → precise cache invalidation; backend persistence async.
- **Crash semantics**: in-memory index lost → full rebuild from backend at startup (see §7); WAL only protects write-pipeline batches not yet persisted.

### 4.8 Unified Cache Invalidation

**FR-8 Cache (`cache` package extracted)**
- Generic TTL `Cache` (bounded, evict-expired-first-then-drop on full): handshake revocation cache, authScopes.
- Generic LRU `LRU` (serial-associated batch invalidation): OCSP response cache.
- `OnCertRevoked(serial)` callback → precise invalidation (handshake cache + OCSP LRU `PurgeSerial`); bulk revocation → full invalidation.

### 4.4 External Interface (New API for varwof-core)

**FR-9 Proposed Engine API (converged at implementation per varwof-core call sites, see `docs/IMPLEMENTATION_PLAN.md`)**

```go
type Engine struct { ... }

// Construction: full load from backend → in-memory index
func NewEngine(d *db.DB, opts EngineOptions) (*Engine, error)

// Certificates (read)
func (e *Engine) GetCert(caName, serial string) (*db.CertRecord, error)
func (e *Engine) GetCertStatus(caName, serial string) (*db.CertStatus, error)
func (e *Engine) GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error)
func (e *Engine) GetCertBySPKIHash(spkiHash, caName, status string) ([]*db.CertRecord, error)
func (e *Engine) ListCertsByPrincipalUid(uid, status string) ([]*db.CertRecord, error)
func (e *Engine) CheckDuplicateCN(caName, cn string, nb, na time.Time) error

// Certificates (write) — memory-first, async persistence
func (e *Engine) IssueCert(rec *db.CertRecord) error          // write memory + enqueue pipeline
func (e *Engine) RevokeCert(caName, serial string, reason int) error
func (e *Engine) RevokeCertsByPrincipalUid(uid string, reason int) (int, error)
func (e *Engine) RevokeCertsBySubCA(caName string, reason int) (int, error)

// CRL (pure in-memory)
func (e *Engine) GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)
func (e *Engine) GetRevokedCerts(caName string) ([]*db.CertRecord, error)

// nonce
func (e *Engine) StoreNonce(nonce []byte) error
func (e *Engine) ConsumeNonce(nonce []byte) error
func (e *Engine) IsNonceUsed(nonce []byte) (bool, error)

// Sub-CA / Trust Anchor / AIC
func (e *Engine) GetSubCA(name string) (*db.SubCA, error)
func (e *Engine) GetTrustAnchor(id int) (*db.TrustAnchor, error)
func (e *Engine) GetAICExtensionByCert(caName, serial string) (*db.AICExtension, error)

// Lifecycle
func (e *Engine) Start() error      // Startup rebuild + janitor + write pipeline
func (e *Engine) Stop() error       // FlushAll + stop background goroutines
func (e *Engine) FlushAll() error   // Synchronous drain (ops/revocation fallback)
```

> High-frequency read methods must avoid full `cert_der` deserialization (using lightweight `CertStatus` structure). Low-frequency management interfaces like `ListCerts` / `ListCertsFilteredPage` / paged listing can continue using the underlying `db` package.

## 5. Non-Functional Requirements

### NFR-1 Performance (Reference Baseline from Existing Load Tests)
| Scenario | Current Baseline (varwof-core, post-RecordBuffer) | Target |
|---|---|---|
| Single sign (sequential) | 1724 TPS | ≥ 1800 TPS |
| Single sign (concurrent w16) | 16350 TPS | ≥ 20K TPS |
| mTLS handshake revocation point query | SQLite global pcache lock dominant | Zero SQL (pure in-memory map), P99 microsecond-level |
| OCSP point query | SQL + LRU | Pure in-memory, zero SQL on hit |
| CRL generation | SQL full-scan + filter | Pure in-memory traversal of `RevokedSet` |
| nonce Consume | SQL two-phase | In-memory atomic CAS |

### NFR-2 Bounded Memory
- Default resident: `certindex` full load (certificate count × ~1KB structured reference per record); expired certificates pruned per FR-3.
- Configurable limits: `max_certs` (overflow evicts oldest expired), `max_nonces`, `max_revoked_entries`.
- `Metrics()` Prometheus output (size / evicted / hit-rate).

### NFR-3 Crash Safety
- Write pipeline WAL guarantees "committed in memory but not yet persisted" batches replay on restart.
- Startup rebuild: full backend load → in-memory index; service availability during load determined by upper layer (read-only fallback optional).
- Idempotent persistence: `INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` / `INSERT IGNORE` (dialect differences handled at db layer).

### NFR-4 Concurrency Safety
- Index read/write uses RWMutex / sharded map; point queries use read lock.
- `ConsumeNonce` must be atomic CAS.
- No global lock hotspots (inheriting RecordBuffer's solved slog lock contention / DB connection pool tuning experience).

### NFR-5 Observability
- Metrics: per-index size / hit-rate / eviction / write-pipeline pending / flush duration / WAL size.
- Structured logging (slog), covering: rebuild duration, slow flush alert, backpressure trigger, janitor prune counts.

## 6. Current Implementation & Documentation Inventory

| Path | Content | Status |
|---|---|---|
| `db/` | SQL backend: 3-way Dialect, schema migration v1 (consolidated schema), CertRecord CRUD, BulkInsert, nonce, AIC, sub_ca, trust_anchor, rbac/acme/ra and all table methods, distributed lock | ✅ Extracted from `core/internal/db`, tests pass |
| `recordbuffer/` | Write pipeline: batch buffer + WAL + backpressure + checkpoint + drain + FlushAll | ✅ Extracted from `core/internal/serve/record_buffer.go` (`flushAll` exported as `FlushAll`), tests pass |
| `cache/` | Generic TTL Cache + LRU (serial-associated invalidation) | ✅ Extracted from `internal/ocsp/cache.go` + `cmd/pki/serve.go` + `internal/serve/rbac.go`, tests pass |
| `engine/` | In-memory engine: CertIndex/RevokedSet/NonceSet/SubCA/Trust/AIC indexes + write pipeline wiring + startup rebuild + janitor + Metrics | ✅ Implemented per IMPLEMENTATION_PLAN Phase A–F, tests + benchmarks pass |
| `docs/REQUIREMENTS.md` | Requirements specification | ✅ v0.2 implemented |
| `docs/IMPLEMENTATION_PLAN.md` | Implementation steps | ✅ Phase A–F complete, Phase G pending varwof-core |
| `docs/api.md` / `docs/config.md` / `docs/functions.md` | User-facing API / config / function docs (doc-driven requirement) | ✅ In sync with implementation |

## 7. Key Design Decisions (Confirmed with User)

| Decision Point | Conclusion |
|---|---|
| Memory coverage scope | Hot-path 5 categories (certificates/revoked set/nonce/sub_cas/trust_anchors/aic_extensions) |
| Backend dialect | SQLite / PG / MySQL 3-way fully preserved |
| Integration approach | Entirely new Engine API, varwof-core gradual migration (not signature-compatible) |
| Consistency | Memory is truth; write to memory first, async persistence; abolish manual flush convention |
| Deployment model | Single-instance authority; v1 does not do distributed consensus |
| Time window | OCSP/CRL optimized by certificate validity time window (FR-3) |
| Read/write path routing | **Reads must go through engine memory, writes in the write path must not connect directly to DB**: write pipeline (RecordBuffer persistence) / revocation queue reads must hit memory primary; no "read DB as fallback" logic in hot paths. Memory updates synchronously with no delay, DB is just a persistence sink. Same principle as ShardingSphere `transactionalReadQueryStrategy=PRIMARY` |
