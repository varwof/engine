# engine API 参考

> 版本：v1（对应 `engine` 包实施完成，Phase A–F 落地）
> 文档与 `engine/` 实现同步更新。

`engine` 包是 varwof-engine 的内存引擎：热路径数据全部常驻内存，读零 SQL，写先内存后异步落库。

## 构造与生命周期

```go
func NewEngine(d *db.DB, opts EngineOptions) (*Engine, error)
func (e *Engine) Start()          // 启动后台 janitor（幂等）
func (e *Engine) Stop()           // 排空写管道并停止后台协程
func (e *Engine) FlushAll() error // 同步排空（运维/吊销兜底，常规无需调用）
func (e *Engine) Loading() bool   // 启动重建是否完成
func (e *Engine) DB() *db.DB      // 底层后端句柄
```

使用顺序：`NewEngine`（内部完成全量重建）→ `Start()`（可选，开启过期剪枝）→ 业务调用 → `Stop()`。

## 证书（读）

| 方法 | 说明 |
|---|---|
| `GetCert(caName, serial string) (*db.CertRecord, error)` | 全字段点查（含 CertDER） |
| `GetCertStatus(caName, serial string) (*db.CertStatus, error)` | OCSP / 握手吊销轻量状态 |
| `GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error)` | 按 issuer DN + serial 点查 |
| `GetCertBySPKIHash(spkiHash, caName, status string) ([]*db.CertRecord, error)` | SPKI 关联查询，可按 CA/状态过滤 |
| `ListCertsByPrincipalUid(uid, status string) ([]*db.CertRecord, error)` | 按人列举 |
| `ListCertsByAgentID(agent, status string) ([]*db.CertRecord, error)` | 按 agent 列举 |
| `CheckDuplicateCN(caName, cn string, nb, na time.Time) error` | 活跃证书重复 CN + 时间重叠检查 |

未命中返回 `engine.ErrNotFound`。OCSP 语义（V 且已过期 → Unknown）由调用方结合 `CertStatus.NotAfter` 应用；引擎仅保证 `not_after < now - grace` 的证书已移出热内存。

## 证书（写）— 内存优先

| 方法 | 说明 |
|---|---|
| `IssueCert(rec *db.CertRecord) error` | 先写内存（立即可读），再入 WAL 保护写管道。同 (ca,serial) 同 fingerprint 幂等；不同 fingerprint 返回 `db.ErrDuplicateSerial`；管道满返回 `engine.ErrBackpressure`（上层应回 503） |
| `RevokeCert(caName, serial string, reason int) error` | 内存原子置 R → 回调 `OnCertRevoked` → 内部先 flush 再排队 UPDATE（顺序保证，无需上层手动 flush） |
| `RevokeCertsByPrincipalUid(uid string, reason int) (int, error)` | 批量吊销，返回数量 |
| `RevokeCertsBySubCA(caName string, reason int) (int, error)` | 批量吊销某子 CA 签发的证书，返回数量 |

## CRL（纯内存）

| 方法 | 说明 |
|---|---|
| `GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)` | 有效窗口内吊销条目，按 revoked_at 倒序（CRL 生成） |
| `GetRevokedCerts(caName string) ([]*db.CertRecord, error)` | 同上，返回完整记录 |

## nonce（一次性防重放）

| 方法 | 说明 |
|---|---|
| `StoreNonce(nonce []byte) error` | 16 字节 RenewalToken nonce。失败：`db.ErrDuplicateNonce` / `engine.ErrBackpressure` |
| `ConsumeNonce(nonce []byte) error` | 原子 CAS；`db.ErrNonceAlreadyUsed` / `db.ErrNonceNotFound` |
| `IsNonceUsed(nonce []byte) (bool, error)` | 未知名 nonce 视为未使用 |

并发 double-spend 只有一个 goroutine 成功。

## DA nonce（DelegationAuthorization 防重放）

| 方法 | 说明 |
|---|---|
| `StoreDANonce(nonce []byte) error` | 32 字节 DA nonce（AIC 规范 SIZE(32)），CA 签发 AIC 时持久化，同一 nonce 无法二次签发。失败：`db.ErrDuplicateNonce`（重放）/ `engine.ErrBackpressure` |
| `IsDANonceUsed(nonce []byte) (bool, error)` | 已持久化（曾用于签发）返回 true |

与 `StoreNonce`（16 字节，`renewal_tokens` 表）完全隔离：DA nonce 落 `da_nonces` 表（MySQL `VARBINARY(32)`），语义是「存在即已用」，无需 consume 步骤。


## 子 CA / 信任锚 / AIC

| 方法 | 说明 |
|---|---|
| `GetSubCA(name string) (*db.SubCAMeta, error)` | 子 CA 点查 |
| `GetTrustAnchor(id int) (*db.TrustAnchor, error)` | 按 id 点查 |
| `GetAICExtensionByCert(caName, serial string) (*db.AICExtension, error)` | 按证书点查 |
| `ListAICExtensionsByAgentID(agentID string) ([]*db.AICExtension, error)` | 按 agent 列举 AIC 扩展 |
| `ListAICExtensionsByPrincipalUid(uid string) ([]*db.AICExtension, error)` | 按 principal 列举 AIC 扩展 |
| `UpsertSubCA(rec *db.SubCAMeta) error` | 写内存 + 异步落库 |
| `UpsertTrustAnchor(rec *db.TrustAnchor) error` | 写内存 + 异步落库 |
| `UpsertAICExtension(a *db.AICExtension) error` | 写内存 + 异步落库 |

## 可观测性

```go
func (e *Engine) Metrics() Metrics                       // 结构化快照
func (e *Engine) PrometheusMetrics() string              // Prometheus 文本格式（无第三方依赖）
```

指标项见 `Metrics` 结构：各索引 size、`WindowEvictions`、`ReadHits/ReadMisses`、`PipelinePending`。

## 错误汇总

| 错误 | 场景 |
|---|---|
| `engine.ErrNotFound` | 点查未命中 |
| `engine.ErrDuplicate` | 键冲突（预留，当前由 `db.ErrDuplicateSerial` 表达证书重复） |
| `engine.ErrBackpressure` | 写管道满 / 内存上限且无可逐出 |
| `db.ErrDuplicateSerial` | 证书同键不同指纹 |
| `db.ErrDuplicateNonce` / `db.ErrNonceAlreadyUsed` / `db.ErrNonceNotFound` | nonce 语义 |

## 一致性模型

- **内存即真相**：写后立即读命中内存，无 ≤500ms 可见性窗口。
- **并发安全**：`IssueCert` 的同键冲突判定与插入在索引锁内原子完成（并发同 (ca,serial) 不同指纹签发仅一个成功）；批量吊销（`RevokeCertsByPrincipalUid` / `RevokeCertsBySubCA`）的状态变更也在索引锁内进行，与并发点查无数据竞争，吊销集以单次排序合并（O(n log n)），避免逐条插入的 O(n²)。
- **吊销顺序保证**：`RevokeCert` 内部先排空写管道再排队 `UPDATE`，保证后端不会出现「已吊销但证书仍为 V」的竞态。上层不再需要手动 `FlushRecordBuffer()`。
- **崩溃恢复**：内存索引丢失 → 启动全量重建；`WalPath` 只保护写管道中未落库的证书批次。
- **后端收敛**：落库幂等（`INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` / `INSERT IGNORE`）。

## 写管道并发保证

`recordbuffer` 的 `flush()` / `FlushAll()` 由内部互斥串行化：后台 drain 与调用方 `FlushAll` 重叠时不再丢失批次（两个重叠 flush 曾可能跳过两次 copy 之间新追加的记录，导致落库丢失）。
