# engine Function Index

> Version: v1 (corresponds to the completed `engine` package implementation)
> Organized automatically from exported methods in `engine/*.go`. All exported functions have doc comments.

## Lifecycle

| Function | File |
|---|---|
| `NewEngine(d *db.DB, opts EngineOptions) (*Engine, error)` | engine.go |
| `(*Engine) Start()` | engine.go |
| `(*Engine) Stop()` | engine.go |
| `(*Engine) FlushAll() error` | engine.go |
| `(*Engine) Loading() bool` | engine.go |
| `(*Engine) DB() *db.DB` | engine.go |
| `(*Engine) SetDB(d *db.DB)` | engine.go |

## Certificate Reads

| Function | File |
|---|---|
| `(*Engine) GetCert(caName, serial string) (*db.CertRecord, error)` | reads.go |
| `(*Engine) GetCertStatus(caName, serial string) (*db.CertStatus, error)` | reads.go |
| `(*Engine) GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error)` | reads.go |
| `(*Engine) GetCertBySPKIHash(spkiHash, caName, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool, error)` | reads.go |
| `(*Engine) ListCertsByPrincipalUid(uid, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool, error)` | reads.go |
| `(*Engine) ListCertsByAgentID(agent, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool, error)` | reads.go |
| `(*Engine) CheckDuplicateCN(caName, cn string, notBefore, notAfter time.Time) error` | reads.go |

## Certificate Writes

| Function | File |
|---|---|
| `(*Engine) IssueCert(rec *db.CertRecord) error` | writes.go |
| `(*Engine) RevokeCert(caName, serial string, reason int) error` | writes.go |
| `(*Engine) RevokeCertsBatch(entries []RevokeBatchEntry) (int, []RevokeBatchEntry, error)` | writes.go |
| `(*Engine) RevokeCertsByPrincipalUid(uid string, reason int) (int, error)` | writes.go |
| `(*Engine) RevokeCertsBySubCA(caName string, reason int) (int, error)` | writes.go |

## CRL

| Function | File |
|---|---|
| `(*Engine) GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)` | reads.go |
| `(*Engine) GetRevokedCertEntriesSince(caName string, since time.Time) ([]*db.RevokedCertEntry, error)` | reads.go |
| `(*Engine) GetRevokedCerts(caName string) ([]*db.CertRecord, error)` | reads.go |
| `(*Engine) GetRevokedCerts(caName string) ([]*db.CertRecord, error)` | reads.go |

## nonce

| Function | File |
|---|---|
| `(*Engine) StoreNonce(nonce []byte) error` | writes.go |
| `(*Engine) ConsumeNonce(nonce []byte) error` | writes.go |
| `(*Engine) IsNonceUsed(nonce []byte) (bool, error)` | reads.go |

## DA nonce (DelegationAuthorization Anti-Replay)

| Function | File |
|---|---|
| `(*Engine) StoreDANonce(nonce []byte) error` | writes.go |
| `(*Engine) IsDANonceUsed(nonce []byte) (bool, error)` | reads.go |

## Write Pipeline (recordbuffer)

| Function | File |
|---|---|
| `(*RecordBuffer) Add(rec *db.CertRecord) bool` | record_buffer.go |
| `(*RecordBuffer) AddDANonceSync(nonce []byte) error` | record_buffer.go — synchronously fsyncs the WAL before returning (DA nonce crash safety); returns `ErrWALDisabled` without WAL |
| `(*RecordBuffer) WALEnabled() bool` | record_buffer.go |
| `(*RecordBuffer) Pending() int32` / `IsFull() bool` / `FlushAll()` / `Stop()` | record_buffer.go |
| `(*RecordBuffer) WalBytes() int` | record_buffer.go — current WAL size in bytes (R10) |
| `(*RecordBuffer) FlushStats() (flushed int, bucketCounts []uint64)` | record_buffer.go — flush latency histogram buckets (R10) |
| `Item` / `ItemKind` (`KindCert`, `KindDANonce`) / `CertItem` / `DANonceItem` | record_buffer.go |

## Backend Bulk Persistence (db)

| Function | File |
|---|---|
| `(*DB) BulkStoreDANonces(nonces [][]byte) (int, error)` | da_nonces.go — multi-row INSERT, duplicates ignored, enforces 32 bytes |
| `(*DB) BulkRevokeCertificates(entries []RevokeBatchEntry) (int, error)` | bulk_revoke.go — chunked CASE UPDATE (~199 rows per statement), carries per-row reason |

## Sub-CA / Trust Anchor / AIC

| Function | File |
|---|---|
| `(*Engine) GetSubCA(name string) (*db.SubCAMeta, error)` | reads.go |
| `(*Engine) GetTrustAnchor(id int) (*db.TrustAnchor, error)` | reads.go |
| `(*Engine) GetAICExtensionByCert(caName, serial string) (*db.AICExtension, error)` | reads.go |
| `(*Engine) ListAICExtensionsByAgentID(agentID string) ([]*db.AICExtension, error)` | reads.go |
| `(*Engine) ListAICExtensionsByPrincipalUid(uid string) ([]*db.AICExtension, error)` | reads.go |
| `(*Engine) UpsertSubCA(rec *db.SubCAMeta) error` | writes.go |
| `(*Engine) UpsertTrustAnchor(rec *db.TrustAnchor) error` | writes.go |
| `(*Engine) UpsertAICExtension(a *db.AICExtension) error` | writes.go |

## Observability

| Function | File |
|---|---|
| `(*Engine) Metrics() Metrics` | engine.go |
| `(*Engine) PrometheusMetrics() string` | engine.go |

## Types & Errors

- `EngineOptions` (engine/options.go) → see `docs/config.md`
- `Metrics` (engine/engine.go) — includes `CertIssued` / `CertRevoked` / `AICPruned` counters, `CertResidentBytes` / `AICResidentBytes` (R8), `WalBytes`, `FlushDuration` histogram (R10)
- `CertCursor` (engine/cert_index.go) — opaque pagination cursor for high-cardinality certificate queries; encodes the position of the last returned record (NotBefore descending, serial descending). Pass back as the `after` argument to fetch the next page; nil starts from the beginning.
- Errors: `ErrNotFound`, `ErrDuplicate`, `ErrBackpressure` (engine.go)
- Index types (internal storage structures, exported constructors for engine use):
  - `NewCertIndex()` (engine/cert_index.go) — also provides `ResidentBytes()` (resident byte estimation, R8)
  - `NewRevokedSet(maxPerCA int)` (engine/revoked_set.go) — when `maxPerCA > 0`, per-CA over-limit evicts the oldest revocation (status remains R; only leaves the CRL window)
  - `NewNonceSet(max int)` (engine/nonce_set.go) — 16B RenewalToken nonces; DA nonces (32B) reuse the same type with exists-equals-used semantics (`has()` query), see `StoreDANonce` in `engine/writes.go`
  - `NewSubCAIndex()` / `NewTrustIndex()` / `NewAICIndex()` (engine/meta_index.go) — `AICIndex.ResidentBytes()` (R8)

## Metrics (Prometheus)

- `varwof_engine_certindex_size` / `varwof_engine_revokedset_size` / `varwof_engine_nonceset_size` / `varwof_engine_danonceset_size` / `varwof_engine_subca_size` / `varwof_engine_trustanchor_size` / `varwof_engine_aic_size` / `varwof_engine_window_evictions_total` / `varwof_engine_read_hit_total` / `varwof_engine_read_miss_total` / `varwof_engine_pipeline_pending` / `varwof_engine_flush_duration_seconds` (histogram)
- Added in R8/R10: **`varwof_engine_aic_pruned_total`** / **`varwof_engine_cert_issued_total`** / **`varwof_engine_cert_revoked_total`** / **`varwof_engine_cert_resident_bytes`** / **`varwof_engine_aic_resident_bytes`** / **`varwof_engine_wal_bytes`**
