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
| `(*Engine) SetDB(d *db.DB)` | engine.go |

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
| `(*Engine) RevokeCertsBatch(entries []RevokeBatchEntry) (int, []RevokeBatchEntry, error)` | writes.go |
| `(*Engine) RevokeCertsByPrincipalUid(uid string, reason int) (int, error)` | writes.go |
| `(*Engine) RevokeCertsBySubCA(caName string, reason int) (int, error)` | writes.go |

## CRL

| 函数 | 所在文件 |
|---|---|
| `(*Engine) GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)` | reads.go |
| `(*Engine) GetRevokedCertEntriesSince(caName string, since time.Time) ([]*db.RevokedCertEntry, error)` | reads.go |
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
| `(*RecordBuffer) AddDANonce(nonce []byte) error` | record_buffer.go — 无 WAL 批量路径：把 DA nonce 缓冲进写管道（经 `BulkStoreDANonces` 收敛）；永不拒绝（满则先强制 flush） |
| `(*RecordBuffer) AddDANonceSync(nonce []byte) error` | record_buffer.go — 返回前同步 fsync WAL（DA nonce 崩溃安全）；无 WAL 返回 `ErrWALDisabled` |
| `(*RecordBuffer) WALEnabled() bool` | record_buffer.go |
| `(*RecordBuffer) Pending() int32` / `IsFull() bool` / `FlushAll()` / `Stop()` | record_buffer.go |
| `(*RecordBuffer) WalBytes() int` | record_buffer.go — 当前 WAL 字节数（R10） |
| `(*RecordBuffer) FlushStats() (flushed int, bucketCounts []uint64)` | record_buffer.go — flush 延迟直方图分桶（R10） |
| `Item` / `ItemKind`（`KindCert`、`KindDANonce`）/ `CertItem` / `DANonceItem` | record_buffer.go |

## 后端批量落库（db）

| 函数 | 所在文件 |
|---|---|
| `(*DB) BulkStoreDANonces(nonces [][]byte) (int, error)` | da_nonces.go — 多行 INSERT，重复忽略，强制 32 字节 |
| `(*DB) BulkStoreDANoncesCtx(ctx context.Context, nonces [][]byte) (int, error)` | da_nonces.go — ctx 感知变体（recordbuffer 批量 flush 使用，包 `flushDBTimeout` 兜底）；旧入口委托 `context.Background()` |
| `(*DB) BulkInsertCertRecords(records []*CertRecord) (int, error)` / `BulkInsertCertRecordsCtx(ctx, records) (int, error)` | batch.go — 多行 INSERT（每块 `certChunkSize` 行）。PG/MySQL 块 = 500 行/条（往返降 ~13×），SQLite = 39 行/条（999 变量上限） |
| `(*DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)` | db.go — ctx 感知的 rebind+adapt 批量 Exec（分块 Ctx 变体底层） |
| `(*DB) BulkRevokeCertificates(entries []RevokeBatchEntry) (int, error)` | bulk_revoke.go — 每约 199 条分块一条 CASE UPDATE，承载每行 reason |

## RBAC 用户 / API Token（2026-08-27 新增，认证内存化）

内存即真相扩展：engine 启动时全量载入 rbac_users（全行）与 rbac_api_tokens
（仅 SHA-256 hash，永不含明文 token），serve 认证读路径（authByToken /
authByBasic / authFromAIC / gateway 委托）由 engine 优先、DB 回退。

| 函数 | 所在文件 |
|---|---|
| `(*Engine) GetUserByUsername(username string) (*db.RBACUser, error)` | user_token.go — miss 返回 `ErrNotFound` |
| `(*Engine) GetUserByID(id int) (*db.RBACUser, error)` | user_token.go — 写路径按 id 刷新驻留行 |
| `(*Engine) GetToken(token string) (*db.TokenInfo, error)` | user_token.go — 内存校验 expiry + 用户 enabled（等同 `db.GetToken` 的 JOIN+WHERE） |
| `(*Engine) PutUser(u *db.RBACUser)` | user_token.go — 写穿入口（创建/更新用户） |
| `(*Engine) DeleteUserByID(id int)` | user_token.go |
| `(*Engine) PutTokenHash(r db.TokenHashRow)` | user_token.go — 写穿入口（登录/建 token） |
| `(*Engine) DeleteTokenByHash(hash string)` | user_token.go |
| `(*Engine) DeleteTokenByID(id int)` | user_token.go |
| `(*Engine) DeleteTokensByUserID(userID int)` | user_token.go — 密码轮换/删用户时清该账户全部 token |
| `(*DB) ListRBACUsers() ([]RBACUser, error)` | db/rbac.go — 启动全量载入源（含凭据列） |
| `(*DB) ListAllTokenHashes() ([]TokenHashRow, error)` | db/rbac.go — 启动全量载入源（hash+owner+expiry） |

写路径约定：serve 先落 DB（拥有身份生成与写串行权），再刷新/删除驻留行，内存
与后端保持一致。OOB（CLI/第二实例）创建的用户不在内存 → 认证回退 DB（与证书
OOB 行为一致）。

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
  - `NewUserIndex` 对应私有 `userIndex` / `tokenIndex`（engine/user_token.go）— 用户/Token 内存索引；`Metrics` 新增 `UserIndexSize` / `TokenIndexSize`

## 指标（Prometheus）

- `varwof_engine_certindex_size` / `varwof_engine_revokedset_size` / `varwof_engine_nonceset_size` / `varwof_engine_danonceset_size` / `varwof_engine_subca_size` / `varwof_engine_trustanchor_size` / `varwof_engine_aic_size` / **`varwof_engine_userindex_size` / `varwof_engine_tokenindex_size`**（2026-08-27 新增，未渲染进 Prometheus 输出，仅 `Metrics()`）/ `varwof_engine_window_evictions_total` / `varwof_engine_read_hit_total` / `varwof_engine_read_miss_total` / `varwof_engine_pipeline_pending` / `varwof_engine_flush_duration_seconds`（直方图）
- R8/R10 新增：**`varwof_engine_aic_pruned_total`** / **`varwof_engine_cert_issued_total`** / **`varwof_engine_cert_revoked_total`** / **`varwof_engine_cert_resident_bytes`** / **`varwof_engine_aic_resident_bytes`** / **`varwof_engine_wal_bytes`**
