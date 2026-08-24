# engine API Reference

> Version: v1 (engine package implementation complete, Phase A–F delivered)
> Documentation kept in sync with `engine/` implementation.

The `engine` package is varwof-engine's in-memory engine: hot-path data resides entirely in memory, reads hit zero SQL, writes go to memory first then persist asynchronously.

## Construction & Lifecycle

```go
func NewEngine(d *db.DB, opts EngineOptions) (*Engine, error)
func (e *Engine) Start()          // Start background janitor (idempotent)
func (e *Engine) Stop()           // Flush write pipeline and stop background goroutines
func (e *Engine) FlushAll() error // Synchronous flush (ops revocation fallback; not needed in normal use)
func (e *Engine) Loading() bool   // Whether startup rebuild is complete
func (e *Engine) DB() *db.DB      // Underlying backend handle
```

Usage order: `NewEngine` (performs full rebuild internally) → `Start()` (optional, enables expiry pruning) → business calls → `Stop()`.

## Certificates (Read)

| Method | Description |
|---|---|
| `GetCert(caName, serial string) (*db.CertRecord, error)` | Full-field lookup (includes CertDER) |
| `GetCertStatus(caName, serial string) (*db.CertStatus, error)` | Lightweight status for OCSP / handshake revocation |
| `GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error)` | Lookup by issuer DN + serial |
| `GetCertBySPKIHash(spkiHash, caName, status string) ([]*db.CertRecord, error)` | SPKI-associated query, filterable by CA/status |
| `ListCertsByPrincipalUid(uid, status string) ([]*db.CertRecord, error)` | List by principal |
| `ListCertsByAgentID(agent, status string) ([]*db.CertRecord, error)` | List by agent |
| `CheckDuplicateCN(caName, cn string, nb, na time.Time) error` | Active-certificate duplicate CN + time-overlap check |

Misses return `engine.ErrNotFound`. OCSP semantics (V but expired → Unknown) are applied by the caller based on `CertStatus.NotAfter`; the engine only guarantees certificates with `not_after < now - grace` have been evicted from hot memory.

## Certificates (Write) — Memory-First

| Method | Description |
|---|---|
| `IssueCert(rec *db.CertRecord) error` | Write memory first (immediately readable), then enqueue to WAL-protected write pipeline. Idempotent for same (ca,serial) + same fingerprint; different fingerprint returns `db.ErrDuplicateSerial`; pipeline full returns `engine.ErrBackpressure` (caller should return 503) |
| `RevokeCert(caName, serial string, reason int) atomically sets R → callback `OnCertRevoked` → internally flushes pipeline then enqueues UPDATE (ordering guaranteed, no manual flush needed) |
| `RevokeCertsByPrincipalUid(uid string, reason int) (int, error)` | Bulk revocation, returns count |
| `RevokeCertsBySubCA(caName string, reason int) (int, error)` | Bulk revocation of all certs issued by a sub-CA, returns count |

## CRL (Pure In-Memory)

| Method | Description |
|---|---|
| `GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)` | Revoked entries within valid window, sorted by revoked_at descending (CRL generation) |
| `GetRevokedCerts(caName string) ([]*db.CertRecord, error)` | Same as above, returns full records |

## nonce (One-Time Anti-Replay)

| Method | Description |
|---|---|
| `StoreNonce(nonce []byte) error` | 16-byte RenewalToken nonce. Failure: `db.ErrDuplicateNonce` / `engine.ErrBackpressure` |
| `ConsumeNonce(nonce []byte) error` | Atomic CAS; `db.ErrNonceAlreadyUsed` / `db.ErrNonceNotFound` |
| `IsNonceUsed(nonce []byte) (bool, error)` | Unknown nonces treated as unused |

Concurrent double-spend allows only one goroutine to succeed.

## DA nonce (DelegationAuthorization Anti-Replay)

| Method | Description |
|---|---|
| `StoreDANonce(nonce []byte) error` | 32-byte DA nonce (AIC spec SIZE(32)). Persisted when CA issues an AIC; same nonce cannot be used twice. Failure: `db.ErrDuplicateNonce` (replay) / `engine.ErrBackpressure` |
| `IsDANonceUsed(nonce []byte) (bool, error)` | Returns true if persisted (was used for issuance) |

Completely isolated from `StoreNonce` (16-byte, `renewal_tokens` table). DA nonces go to the `da_nonces` table (MySQL `VARBINARY(32)`); semantics are "existence = used", no consume step needed.

## Sub-CA / Trust Anchor / AIC

| Method | Description |
|---|---|
| `GetSubCA(name string) (*db.SubCAMeta, error)` | Sub-CA lookup |
| `GetTrustAnchor(id int) (*db.TrustAnchor, error)` | Lookup by id |
| `GetAICExtensionByCert(caName, serial string) (*db.AICExtension, error)` | Lookup by certificate |
| `ListAICExtensionsByAgentID(agentID string) ([]*db.AICExtension, error)` | List AIC extensions by agent |
| `ListAICExtensionsByPrincipalUid(uid string) ([]*db.AICExtension, error)` | List AIC extensions by principal |
| `UpsertSubCA(rec *db.SubCAMeta) error` | Write memory + async persistence |
| `UpsertTrustAnchor(rec *db.TrustAnchor) error` | Write memory + async persistence |
| `UpsertAICExtension(a *db.AICExtension) error` | Write memory + async persistence |

## Observability

```go
func (e *Engine) Metrics() Metrics                       // Structured snapshot
func (e *Engine) PrometheusMetrics() string              // Prometheus text format (zero external dependencies)
```

Metric fields: per-index sizes, `WindowEvictions`, `ReadHits/ReadMisses`, `PipelinePending`.

## Error Summary

| Error | Scenario |
|---|---|
| `engine.ErrNotFound` | Lookup miss |
| `engine.ErrDuplicate` | Key conflict (reserved; currently expressed via `db.ErrDuplicateSerial` for certificates) |
| `engine.ErrBackpressure` | Write pipeline full / memory limit reached with nothing to evict |
| `db.ErrDuplicateSerial` | Same key, different fingerprint |
| `db.ErrDuplicateNonce` / `db.ErrNonceAlreadyUsed` / `db.ErrNonceNotFound` | nonce semantics |

## Consistency Model

- **Memory is truth**: writes are immediately readable in memory, no ≤500ms visibility window.
- **Concurrency safe**: `IssueCert` conflict detection and insertion happen atomically under the index lock; bulk revocations also update under the index lock with no data races against concurrent point queries; revoked sets merge via single-sort (O(n log n)).
- **Revocation ordering**: `RevokeCert` flushes the write pipeline internally before queuing the UPDATE, guaranteeing no "revoked but still V" race. Callers no longer need manual `FlushRecordBuffer()`.
- **Crash recovery**: in-memory index is lost → full rebuild from backend at startup; `WalPath` only protects certificate batches still in the write pipeline.
- **Backend convergence**: idempotent persistence (`INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` / `INSERT IGNORE`).

## Write Pipeline Concurrency Guarantee

`recordbuffer`'s `flush()` / `FlushAll()` are serialized internally by a mutex: background drain overlapping with a caller `FlushAll` no longer loses batches.
