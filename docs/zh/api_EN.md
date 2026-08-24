# engine API Reference

> Version: v1 (corresponds to the completed `engine` package implementation, Phase A–F delivered)
> Documentation is kept in sync with the `engine/` implementation.

The `engine` package is varwof-engine's in-memory engine: hot-path data resides entirely in memory, reads are zero-SQL, writes go to memory first then persist asynchronously.

## Construction & Lifecycle

```go
func NewEngine(d *db.DB, opts EngineOptions) (*Engine, error)
func (e *Engine) Start()          // Starts the background janitor (idempotent)
func (e *Engine) Stop()           // Drains the write pipeline and stops background goroutines
func (e *Engine) FlushAll() error // Synchronous drain (ops/revocation fallback; normally not needed)
func (e *Engine) Loading() bool   // Whether startup rebuild has completed
func (e *Engine) DB() *db.DB      // Underlying backend handle
```

Usage order: `NewEngine` (performs full rebuild internally) → `Start()` (optional, enables expiry pruning) → business calls → `Stop()`.

## Certificates (Read)

| Method | Description |
|---|---|
| `GetCert(caName, serial string) (*db.CertRecord, error)` | Full-field point lookup (includes CertDER) |
| `GetCertStatus(caName, serial string) (*db.CertStatus, error)` | Lightweight status for OCSP / handshake revocation |
| `GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error)` | Point lookup by issuer DN + serial |
| `GetCertBySPKIHash(spkiHash, caName, status string) ([]*db.CertRecord, error)` | SPKI-associated query, filterable by CA/status |
| `ListCertsByPrincipalUid(uid, status string) ([]*db.CertRecord, error)` | List by person |
| `ListCertsByAgentID(agent, status string) ([]*db.CertRecord, error)` | List by agent |
| `CheckDuplicateCN(caName, cn string, nb, na time.Time) error` | Active-certificate duplicate CN + time-overlap check |

Misses return `engine.ErrNotFound`. OCSP semantics (V and expired → Unknown) are applied by callers using `CertStatus.NotAfter`; the engine only guarantees that certificates with `not_after < now - grace` have been evicted from hot memory.

## Certificates (Write) — Memory First

| Method | Description |
|---|---|
| `IssueCert(rec *db.CertRecord) error` | Writes to memory first (immediately readable), then into the WAL-protected write pipeline. Same (ca,serial) with same fingerprint is idempotent; different fingerprint returns `db.ErrDuplicateSerial`; full pipeline returns `engine.ErrBackpressure` (upper layer should respond 503) |
| `RevokeCert(caName, serial string, reason int) error` | Atomically sets R in memory → invokes `OnCertRevoked` callback → internally flushes first then queues UPDATE (ordering guaranteed, no manual flush needed upstream) |
| `RevokeCertsByPrincipalUid(uid string, reason int) (int, error)` | Bulk revocation, returns count |
| `RevokeCertsBySubCA(caName string, reason int) (int, error)` | Bulk revocation of certificates issued by a sub-CA, returns count |

## CRL (Pure In-Memory)

| Method | Description |
|---|---|
| `GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)` | Revoked entries within the validity window, ordered by revoked_at descending (for CRL generation) |
| `GetRevokedCerts(caName string) ([]*db.CertRecord, error)` | Same as above, returns full records |

## nonce (One-Time Anti-Replay)

| Method | Description |
|---|---|
| `StoreNonce(nonce []byte) error` | 16-byte RenewalToken nonce. Failures: `db.ErrDuplicateNonce` / `engine.ErrBackpressure` |
| `ConsumeNonce(nonce []byte) error` | Atomic CAS; `db.ErrNonceAlreadyUsed` / `db.ErrNonceNotFound` |
| `IsNonceUsed(nonce []byte) (bool, error)` | Unknown nonce treated as unused |

Under concurrent double-spend only one goroutine succeeds.

## DA nonce (DelegationAuthorization Anti-Replay)

| Method | Description |
|---|---|
| `StoreDANonce(nonce []byte) error` | 32-byte DA nonce (AIC spec SIZE(32)), persisted when the CA issues an AIC so the same nonce cannot be used for a second issuance. Failures: `db.ErrDuplicateNonce` (replay) / `engine.ErrBackpressure` |
| `IsDANonceUsed(nonce []byte) (bool, error)` | Returns true if already persisted (previously used for issuance) |

Fully isolated from `StoreNonce` (16 bytes, `renewal_tokens` table): DA nonces land in the `da_nonces` table (MySQL `VARBINARY(32)`); the semantics are "exists = used", no consume step needed.


## Sub-CA / Trust Anchor / AIC

| Method | Description |
|---|---|
| `GetSubCA(name string) (*db.SubCAMeta, error)` | Sub-CA point lookup |
| `GetTrustAnchor(id int) (*db.TrustAnchor, error)` | Point lookup by id |
| `GetAICExtensionByCert(caName, serial string) (*db.AICExtension, error)` | Point lookup by certificate |
| `ListAICExtensionsByAgentID(agentID string) ([]*db.AICExtension, error)` | List AIC extensions by agent |
| `ListAICExtensionsByPrincipalUid(uid string) ([]*db.AICExtension, error)` | List AIC extensions by principal |
| `UpsertSubCA(rec *db.SubCAMeta) error` | Write memory + async persistence |
| `UpsertTrustAnchor(rec *db.TrustAnchor) error` | Write memory + async persistence |
| `UpsertAICExtension(a *db.AICExtension) error` | Write memory + async persistence |

## Observability

```go
func (e *Engine) Metrics() Metrics                       // Structured snapshot
func (e *Engine) PrometheusMetrics() string              // Prometheus text format (no third-party dependencies)
```

See the `Metrics` struct for metric items: per-index sizes, `WindowEvictions`, `ReadHits/ReadMisses`, `PipelinePending`.

## Error Summary

| Error | Scenario |
|---|---|
| `engine.ErrNotFound` | Point lookup miss |
| `engine.ErrDuplicate` | Key conflict (reserved; certificate duplicates currently expressed via `db.ErrDuplicateSerial`) |
| `engine.ErrBackpressure` | Write pipeline full / memory cap reached with nothing evictable |
| `db.ErrDuplicateSerial` | Certificate same key but different fingerprint |
| `db.ErrDuplicateNonce` / `db.ErrNonceAlreadyUsed` / `db.ErrNonceNotFound` | nonce semantics |

## Consistency Model

- **Memory is truth**: reads after writes hit memory immediately — no ≤500ms visibility window.
- **Concurrency safe**: `IssueCert` same-key conflict detection and insertion complete atomically under the index lock (concurrent issuance of same (ca,serial) with different fingerprints: only one succeeds); bulk revocation (`RevokeCertsByPrincipalUid` / `RevokeCertsBySubCA`) state changes also occur under the index lock with no data races against concurrent point queries; revoked sets merge via single-sort (O(n log n)), avoiding O(n²) from per-entry insertion.
- **Revocation ordering guarantee**: `RevokeCert` internally drains the write pipeline before queuing `UPDATE`, ensuring the backend never sees the race of "revoked but certificate still V". Upper layers no longer need manual `FlushRecordBuffer()`.
- **Crash recovery**: loss of in-memory indexes → full rebuild at startup; `WalPath` only protects certificate batches not yet persisted in the write pipeline.
- **Backend convergence**: idempotent persistence (`INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` / `INSERT IGNORE`).

## Write Pipeline Concurrency Guarantees

`recordbuffer`'s `flush()` / `FlushAll()` are serialized by an internal mutex: overlapping background drain and caller `FlushAll` no longer lose batches (two overlapping flushes could previously skip records appended between the two copies, causing persistence loss).
