# engine Function Index

> Version: v1 (engine package implementation complete)
> Auto-generated from `engine/*.go` exported methods. All exported functions have doc comments.

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

## Certificate Read

| Function | File |
|---|---|
| `(*Engine) GetCert(caName, serial string) (*db.CertRecord, error)` | reads.go |
| `(*Engine) GetCertStatus(caName, serial string) (*db.CertStatus, error)` | reads.go |
| `(*Engine) GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error)` | reads.go |
| `(*Engine) GetCertBySPKIHash(spkiHash, caName, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool, error)` | reads.go |
| `(*Engine) ListCertsByPrincipalUid(uid, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool, error)` | reads.go |
| `(*Engine) ListCertsByAgentID(agent, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool, error)` | reads.go |
| `(*Engine) CheckDuplicateCN(caName, cn string, notBefore, notAfter time.Time) error` | reads.go |

## Certificate Write

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
| `(*RecordBuffer) AddDANonceSync(nonce []byte) error` | record_buffer.go — WAL-fsyncs before returning (crash-safe DA nonce); `ErrWALDisabled` when no WAL |
| `(*RecordBuffer) WALEnabled() bool` | record_buffer.go |
| `(*RecordBuffer) Pending() int32` / `IsFull() bool` / `FlushAll()` / `Stop()` | record_buffer.go |
| `(*RecordBuffer) WalBytes() int` | record_buffer.go — current WAL size in bytes (R10) |
| `(*RecordBuffer) FlushStats() (flushed int, bucketCounts []uint64)` | record_buffer.go — flush latency histogram buckets (R10) |
| `Item` / `ItemKind` (`KindCert`, `KindDANonce`) / `CertItem` / `DANonceItem` | record_buffer.go |

## Backend Batch Sinks (db)

| Function | File |
|---|---|
| `(*DB) BulkStoreDANonces(nonces [][]byte) (int, error)` | da_nonces.go — multi-row INSERT, duplicates ignored, 32-byte enforced |
| `(*DB) BulkStoreDANoncesCtx(ctx context.Context, nonces [][]byte) (int, error)` | da_nonces.go — context-aware variant (used by the recordbuffer batch flush, wrapped in `flushDBTimeout`); legacy entry delegates to `context.Background()` |
| `(*DB) BulkInsertCertRecords(records []*CertRecord) (int, error)` / `BulkInsertCertRecordsCtx(ctx, records) (int, error)` | batch.go — multi-row INSERT (chunked by `certChunkSize` rows). PG/MySQL chunk = 500 rows/statement (~13× fewer round-trips), SQLite = 39 rows (999-variable bound) |
| `(*DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)` | db.go — context-aware rebind+adapt batch Exec (backend of the chunk-level Ctx variants) |
| `(*DB) BulkRevokeCertificates(entries []RevokeBatchEntry) (int, error)` | bulk_revoke.go — one CASE UPDATE per ~199-entry chunk, per-row reasons |

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
- `CertCursor` (engine/cert_index.go) — opaque pagination cursor for high-cardinality certificate queries; encodes the (NotBefore desc, serial desc) position of the last returned record. Pass back as the `after` argument to fetch the next page; nil starts at the beginning.
- Errors: `ErrNotFound`, `ErrDuplicate`, `ErrBackpressure` (engine.go)
- Index types (internal storage, exported constructors for engine use):
  - `NewCertIndex()` (engine/cert_index.go) — also `ResidentBytes()` (estimated resident bytes, R8)
  - `NewRevokedSet(maxPerCA int)` (engine/revoked_set.go) — when `maxPerCA > 0`, per-CA overflow evicts oldest revocation (certificate stays R, just exits CRL window)
  - `NewNonceSet(max int)` (engine/nonce_set.go) — 16B RenewalToken nonce; DA nonce (32B) reuses the same type with existence-as-used semantics (`has()` query), see `engine/writes.go` `StoreDANonce`
  - `NewSubCAIndex()` / `NewTrustIndex()` / `NewAICIndex()` (engine/meta_index.go) — `AICIndex.ResidentBytes()` (R8)

## Prometheus Metrics

- `varwof_engine_certindex_size` / `varwof_engine_revokedset_size` / `varwof_engine_nonceset_size` / `varwof_engine_danonceset_size` / `varwof_engine_subca_size` / `varwof_engine_trustanchor_size` / `varwof_engine_aic_size` / `varwof_engine_window_evictions_total` / `varwof_engine_read_hit_total` / `varwof_engine_read_miss_total` / `varwof_engine_pipeline_pending` / `varwof_engine_flush_duration_seconds` (histogram)
- R8/R10 additions: **`varwof_engine_aic_pruned_total`** / **`varwof_engine_cert_issued_total`** / **`varwof_engine_cert_revoked_total`** / **`varwof_engine_cert_resident_bytes`** / **`varwof_engine_aic_resident_bytes`** / **`varwof_engine_wal_bytes`**
