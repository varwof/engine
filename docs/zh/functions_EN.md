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
| `(*RecordBuffer) AddDANonce(nonce []byte) error` | record_buffer.go — WAL-less batch path: buffers a DA nonce into the write pipeline (converges via `BulkStoreDANonces`); never rejects (force-flushes if full) |
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
| `(*DB) BulkStoreDANoncesCtx(ctx context.Context, nonces [][]byte) (int, error)` | da_nonces.go — context-aware variant (used by the recordbuffer batch flush, wrapped in `flushDBTimeout`); legacy entry delegates to `context.Background()` |
| `(*DB) BulkInsertCertRecords(records []*CertRecord) (int, error)` / `BulkInsertCertRecordsCtx(ctx, records) (int, error)` | batch.go — multi-row INSERT (chunked by `certChunkSize` rows). PG/MySQL chunk = 500 rows/statement (~13× fewer round-trips), SQLite = 39 rows (999-variable bound) |
| `(*DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)` | db.go — context-aware rebind+adapt batch Exec (backend of the chunk-level Ctx variants) |
| `(*DB) BulkRevokeCertificates(entries []RevokeBatchEntry) (int, error)` | bulk_revoke.go — chunked CASE UPDATE (~199 rows per statement), carries per-row reason |

## RBAC users / API tokens (new 2026-08-27, in-memory authentication)

Memory-is-truth extension: on startup the engine fully loads rbac_users (full
rows) and rbac_api_tokens (SHA-256 hashes only, never raw token material); the
server's authentication read paths (authByToken / authByBasic / authFromAIC /
gateway delegation) read engine-first, DB-fallback.

| Function | File |
|---|---|
| `(*Engine) GetUserByUsername(username string) (*db.RBACUser, error)` | user_token.go — miss → `ErrNotFound` |
| `(*Engine) GetUserByID(id int) (*db.RBACUser, error)` | user_token.go — write path refreshes the resident row by id |
| `(*Engine) GetToken(token string) (*db.TokenInfo, error)` | user_token.go — in memory enforces expiry + owning user enabled (mirrors `db.GetToken`'s JOIN+WHERE) |
| `(*Engine) PutUser(u *db.RBACUser)` | user_token.go — write-through entry (create/update user) |
| `(*Engine) DeleteUserByID(id int)` | user_token.go |
| `(*Engine) PutTokenHash(r db.TokenHashRow)` | user_token.go — write-through entry (login / token mint) |
| `(*Engine) DeleteTokenByHash(hash string)` | user_token.go |
| `(*Engine) DeleteTokenByID(id int)` | user_token.go |
| `(*Engine) DeleteTokensByUserID(userID int)` | user_token.go — clears an account's tokens on password rotation / user delete |
| `(*DB) ListRBACUsers() ([]RBACUser, error)` | db/rbac.go — startup load source (credential columns included) |
| `(*DB) ListAllTokenHashes() ([]TokenHashRow, error)` | db/rbac.go — startup load source (hash+owner+expiry) |

Write-path contract: the server persists to the backend first (it owns identity
generation and write serialization), then refreshes/removes the resident row so
memory and backend stay in step. Out-of-band (CLI / second instance) users are
not resident → authentication falls back to the DB (same as cert OOB behavior).

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
  - private `userIndex` / `tokenIndex` (engine/user_token.go) — user/Token memory indexes; `Metrics` gained `UserIndexSize` / `TokenIndexSize`

## Metrics (Prometheus)

- `varwof_engine_certindex_size` / `varwof_engine_revokedset_size` / `varwof_engine_nonceset_size` / `varwof_engine_danonceset_size` / `varwof_engine_subca_size` / `varwof_engine_trustanchor_size` / `varwof_engine_aic_size` / `varwof_engine_window_evictions_total` / `varwof_engine_read_hit_total` / `varwof_engine_read_miss_total` / `varwof_engine_pipeline_pending` / `varwof_engine_flush_duration_seconds` (histogram)
- Added in R8/R10: **`varwof_engine_aic_pruned_total`** / **`varwof_engine_cert_issued_total`** / **`varwof_engine_cert_revoked_total`** / **`varwof_engine_cert_resident_bytes`** / **`varwof_engine_aic_resident_bytes`** / **`varwof_engine_wal_bytes`**
