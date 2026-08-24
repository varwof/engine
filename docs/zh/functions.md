# engine 函数索引

> 版本：v1（对应 `engine` 包实施完成）
> 由 `engine/*.go` 导出方法自动整理。全部导出函数均有 doc comment。

## 生命周期

| 函数 | 所在文件 |
|---|---|
| `NewEngine(d *db.DB, opts EngineOptions) (*Engine, error)` | engine.go |
| `(*Engine) Start()` | engine.go |
| `(*Engine) Stop()` | engine.go |
| `(*Engine) FlushAll() error` | engine.go |
| `(*Engine) Loading() bool` | engine.go |
| `(*Engine) DB() *db.DB` | engine.go |

## 证书读

| 函数 | 所在文件 |
|---|---|
| `(*Engine) GetCert(caName, serial string) (*db.CertRecord, error)` | reads.go |
| `(*Engine) GetCertStatus(caName, serial string) (*db.CertStatus, error)` | reads.go |
| `(*Engine) GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error)` | reads.go |
| `(*Engine) GetCertBySPKIHash(spkiHash, caName, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool, error)` | reads.go |
| `(*Engine) ListCertsByPrincipalUid(uid, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool, error)` | reads.go |
| `(*Engine) ListCertsByAgentID(agent, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool, error)` | reads.go |
| `(*Engine) CheckDuplicateCN(caName, cn string, notBefore, notAfter time.Time) error` | reads.go |

## 证书写

| 函数 | 所在文件 |
|---|---|
| `(*Engine) IssueCert(rec *db.CertRecord) error` | writes.go |
| `(*Engine) RevokeCert(caName, serial string, reason int) error` | writes.go |
| `(*Engine) RevokeCertsByPrincipalUid(uid string, reason int) (int, error)` | writes.go |
| `(*Engine) RevokeCertsBySubCA(caName string, reason int) (int, error)` | writes.go |

## CRL

| 函数 | 所在文件 |
|---|---|
| `(*Engine) GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)` | reads.go |
| `(*Engine) GetRevokedCerts(caName string) ([]*db.CertRecord, error)` | reads.go |

## nonce

| 函数 | 所在文件 |
|---|---|
| `(*Engine) StoreNonce(nonce []byte) error` | writes.go |
| `(*Engine) ConsumeNonce(nonce []byte) error` | writes.go |
| `(*Engine) IsNonceUsed(nonce []byte) (bool, error)` | reads.go |

## DA nonce（DelegationAuthorization 防重放）

| 函数 | 所在文件 |
|---|---|
| `(*Engine) StoreDANonce(nonce []byte) error` | writes.go |
| `(*Engine) IsDANonceUsed(nonce []byte) (bool, error)` | reads.go |

## 写管道（recordbuffer）

| 函数 | 所在文件 |
|---|---|
| `(*RecordBuffer) Add(rec *db.CertRecord) bool` | record_buffer.go |
| `(*RecordBuffer) AddDANonceSync(nonce []byte) error` | record_buffer.go — 返回前同步 fsync WAL（DA nonce 崩溃安全）；无 WAL 返回 `ErrWALDisabled` |
| `(*RecordBuffer) WALEnabled() bool` | record_buffer.go |
| `(*RecordBuffer) Pending() int32` / `IsFull() bool` / `FlushAll()` / `Stop()` | record_buffer.go |
| `Item` / `ItemKind`（`KindCert`、`KindDANonce`）/ `CertItem` / `DANonceItem` | record_buffer.go |

## 后端批量落库（db）

| 函数 | 所在文件 |
|---|---|
| `(*DB) BulkStoreDANonces(nonces [][]byte) (int, error)` | da_nonces.go — 多行 INSERT，重复忽略，强制 32 字节 |
| `(*DB) BulkRevokeCertificates(entries []RevokeBatchEntry) (int, error)` | bulk_revoke.go — 每约 199 条分块一条 CASE UPDATE，承载每行 reason |

## 子 CA / 信任锚 / AIC

| 函数 | 所在文件 |
|---|---|
| `(*Engine) GetSubCA(name string) (*db.SubCAMeta, error)` | reads.go |
| `(*Engine) GetTrustAnchor(id int) (*db.TrustAnchor, error)` | reads.go |
| `(*Engine) GetAICExtensionByCert(caName, serial string) (*db.AICExtension, error)` | reads.go |
| `(*Engine) ListAICExtensionsByAgentID(agentID string) ([]*db.AICExtension, error)` | reads.go |
| `(*Engine) ListAICExtensionsByPrincipalUid(uid string) ([]*db.AICExtension, error)` | reads.go |
| `(*Engine) UpsertSubCA(rec *db.SubCAMeta) error` | writes.go |
| `(*Engine) UpsertTrustAnchor(rec *db.TrustAnchor) error` | writes.go |
| `(*Engine) UpsertAICExtension(a *db.AICExtension) error` | writes.go |

## 可观测性

| 函数 | 所在文件 |
|---|---|
| `(*Engine) Metrics() Metrics` | engine.go |
| `(*Engine) PrometheusMetrics() string` | engine.go |

## 类型与错误

- `EngineOptions`（engine/options.go）→ 见 `docs/config.md`
- `Metrics`（engine/engine.go）— 含 `CertIssued` / `CertRevoked` / `AICPruned` 计数、`CertResidentBytes` / `AICResidentBytes`（R8）、`WalBytes`、`FlushDuration` 直方图（R10）
- `CertCursor`（engine/cert_index.go）— 高基数证书查询的不透明分页游标；编码最后返回记录（NotBefore 降序、serial 降序）的位置。作为 `after` 参数传回取下一页；nil 从头开始。
- 错误：`ErrNotFound`、`ErrDuplicate`、`ErrBackpressure`（engine.go）
- 索引类型（内部存储结构，导出构造函数供引擎自用）：
  - `NewCertIndex()`（engine/cert_index.go）— 另含 `ResidentBytes()`（驻留字节估算，R8）
  - `NewRevokedSet(maxPerCA int)`（engine/revoked_set.go）— `maxPerCA > 0` 时每 CA 超限逐出最旧吊销（状态仍 R，仅退出 CRL 窗口）
  - `NewNonceSet(max int)`（engine/nonce_set.go）— 16B RenewalToken nonce；DA nonce（32B）复用同一类型，语义为存在即已用（`has()` 查询），见 `engine/writes.go` `StoreDANonce`
  - `NewSubCAIndex()` / `NewTrustIndex()` / `NewAICIndex()`（engine/meta_index.go）— `AICIndex.ResidentBytes()`（R8）

## 指标（Prometheus）

- `varwof_engine_certindex_size` / `varwof_engine_revokedset_size` / `varwof_engine_nonceset_size` / **`varwof_engine_danonceset_size`** / `varwof_engine_window_evictions_total` / `varwof_engine_read_hit_total{op}` / `varwof_engine_pipeline_pending` / `varwof_engine_flush_duration_seconds`
- R8/R10 新增：`varwof_engine_aic_size` / **`varwof_engine_aic_pruned_total`** / **`varwof_engine_cert_issued_total`** / **`varwof_engine_cert_revoked_total`** / **`varwof_engine_cert_resident_bytes`** / **`varwof_engine_aic_resident_bytes`** / **`varwof_engine_wal_bytes`**
