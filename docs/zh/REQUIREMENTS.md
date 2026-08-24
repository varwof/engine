# varwof-engine 需求规格（REQUIREMENTS）

> 版本：v0.2
> 状态：**已实施**（engine 包按本规格 Phase A–F 落地；Phase G 待 varwof-core 仓库接入）
> 实施负责人：AI 实施 agent（opencode）

## 1. 背景与目标

varwof-core 当前的数据层存在以下结构性矛盾（已在生产高并发压测中实测坐实）：

1. **写路径**：SQLite 全局 page-cache 锁 + 单写锁是吞吐瓶颈。现有 RecordBuffer 把「签名 + 写库」解耦，批量落库后吞吐从 33 TPS → 7142 TPS（同机 EC P-256，提升 52x），但仍是「异步落库 + 内存只做待刷缓冲」——内存层不参与读，读仍打 SQL。
2. **读路径**：mTLS 握手、OCSP、CRL、nonce 校验都是高频点查。当前靠 3 个独立的小缓存（`revocationCache`、`authScopesCache`、OCSP LRU）各自 TTL + 手动失效，散落在 `cmd/pki/serve.go` 与 `internal/serve`，没有统一内存数据面。
3. **可见性窗口**：RecordBuffer 下签发后 ≤500ms 内读不到新证书，吊销前必须手动 `FlushRecordBuffer()` 同步排空，否则出现「已签发但吊销 UPDATE 匹配 0 行」竞态。
4. **无时间维度**：OCSP/CRL 查询没有按证书有效时间窗口剪枝，过期证书常驻热路径，内存/查询无界。

**目标**：构建一个**以内存为中心的专用高速数据子系统**（varwof-engine）：

- 高频读写查询全部命中内存索引，**内存即真相**，读零 SQL、写先内存后异步落库。
- 批量落库到后端数据库（SQLite/PG/MySQL 三方言），崩溃安全（WAL）。
- 为 OCSP / CRL / nonce / cert 状态等热数据维护专用高效查询结构，并按证书有效时间窗口（validity window）优化。
- 单实例权威（多实例由上层共享后端 DB 自己处理，本库 v1 不做分布式一致）。
- 作为独立子项目 `github.com/varwof/engine`，varwof-core 通过**全新接口渐进迁移**接入。

## 2. 范围（Scope）

### 2.1 热路径数据（进内存存储，5 类）

| 数据 | 来源表 | 内存用途 |
|---|---|---|
| 证书 | `certificates` | 状态点查（OCSP/握手）、CRL 生成、SPKI/principal/AIC 关联查询、重复 CN 检查、计数 |
| 吊销集 | `certificates`（status='R'） | CRL 生成、吊销快速判定（不扫全表） |
| nonce | `renewal_tokens` | 一次性防重放（Store/Consume/IsUsed），TTL 自动清理 |
| 子 CA | `sub_cas` | 子 CA 状态/协议点查、CA 关系遍历 |
| 信任锚 | `trust_anchors` | 信任链校验热数据 |
| AIC 扩展 | `aic_extensions` | AIC 按 (ca,serial)/principal/agent 查询 |

> rbac_users / rbac_api_tokens / audit_log / audit_salts / acme_* / ra_* / webhook_subscriptions / key_escrow / ct_logs / gateway_registry / scep_requests / cross_certs / ca_meta 等**低频表保持纯 SQL**（经底层 `db` 包透传），不进内存存储。

### 2.2 后端持久化（写穿目标）

三方言全保留：SQLite（默认，文件 + WAL）/ PostgreSQL / MySQL。内存引擎只关心「增删改的批次语义」，具体 SQL 由底层 `db` 包（本目录 `db/`）负责，方言差异已全部封装在 `db.Dialect`。

### 2.3 非目标（v1 明确不做）

- 分布式一致性 / 多实例缓存同步（单实例权威）。
- 全部表进内存。
- 内存引擎自身的数据持久化（如 snapshot）；崩溃恢复依赖后端 WAL + 全量重建（见 §7）。

## 3. 架构概览

```
                    ┌──────────────────────────────────────────────┐
                    │  varwof-engine (memory-centric engine)        │
  varwof-core ──────► │                                              │
  (serve handlers)   │  ┌────────────────────────────────────────┐  │
                    │  │ Engine (内存即真相)                      │  │
                    │  │  CertIndex   — 证书状态/时间窗口索引      │  │
                    │  │  RevokedSet  — 吊销集合（CRL 快照）       │  │
                    │  │  NonceSet    — 一次性 nonce               │  │
                    │  │  SubCAIndex  — 子 CA                      │  │
                    │  │  TrustIndex  — 信任锚                     │  │
                    │  │  AICIndex    — AIC 扩展                   │  │
                    │  │  → 读：O(1)/区间查询                      │  │
                    │  │  → 写：先入内存索引（原子）                │  │
                    │  └────────────┬─────────────────────────────┘  │
                    │               │ 写事件流                        │
                    │               ▼                               │
                    │  ┌────────────────────────────────────────┐  │
                    │  │ WritePipeline (批量落库, 源自 RecordBuffer)│ │
                    │  │  WAL 预写日志 → 批量 BulkInsert          │  │
                    │  │  checkpoint / 背压 / FlushAll           │  │
                    │  └────────────┬─────────────────────────────┘  │
                    └───────────────┼──────────────────────────────┘
                                    ▼
                       ┌────────────────────────┐
                       │ db (SQL 后端, 三方言)   │
                       │  SQLite / PG / MySQL    │
                       └────────────────────────┘
```

## 4. 功能需求

### 4.1 内存索引（Engine）

**FR-1 证书索引 `CertIndex`**
- 主索引：`(ca_name, serial_number)` → `CertRecord`（含状态、NotBefore/NotAfter/RevokedAt/RevokeReason/DER 引用）。
- 辅助索引（二级映射，写时同步维护）：
  - `(issuer_dn, serial_number)` → status（握手吊销点查，`GetCertStatusByIssuer` 对应）。
  - `spki_hash` → `[]CertRecord`（按 SPKI 查证书）。
  - `principal_uid` → `[]CertRecord`（按人吊销 / 列举）。
  - `agent_id` → `[]CertRecord`。
  - `(ca_name, common_name, status='V')` → 活跃证书（重复 CN 检查）。
  - **`(ca_name, status)` 按 `not_before`/`not_after` 的时间窗口索引**（见 FR-3）。

**FR-2 吊销集合 `RevokedSet`**
- 每 CA 维护 `status='R'` 且 `not_after >= now` 的吊销条目集合，按 `revoked_at` 排序。
- 对应 `GetRevokedCertEntries`（CRL 生成）与 `GetRevokedCerts`，**生成 CRL 为纯内存遍历，零 SQL**。
- 吊销操作 `RevokeCert` / `RevokeCertsByPrincipalUid` / `RevokeCertsBySubCA`：内存中原子更新 `CertIndex` 状态 + 插入 `RevokedSet` + 触发写管道批量落库 + 触发缓存失效。

**FR-3 时间窗口优化（证书有效时间窗口，用户重点要求）**
- OCSP 点查：先按 `(ca, serial)` 命中 `CertIndex`，`NotAfter < now` 且 `status='V'` 直接返回 `Unknown`（不落库），与现状 handler 语义一致（`internal/ocsp/handler.go:239`）。
- **窗口索引**：按 CA 维护按 `not_after` 排序的结构（sorted slice / b-tree），支持：
  - 「某序列号是否落在任何有效窗口内」的快速判定；
  - 过期剪枝：后台 janitor 定期把 `not_after < now - grace` 的条目移出热内存（或置为只读冷区），保证内存有界；
  - CRL 生成只遍历 `not_after >= now` 的吊销条目（现状 SQL 已带 `AND not_after >= ?`，内存版继承该语义）。
- 度量：`evicted_expired`、`window_hit/miss`、`revokedset_size`、`certindex_size`。

**FR-4 nonce 一次性集合 `NonceSet`**
- `StoreNonce` / `ConsumeNonce` / `IsNonceUsed`：内存 map + TTL，原子。
- 并发安全：Consume 必须是「未用 → 已用」的原子 CAS 语义（并发 double-spend 只有一个成功）。
- 后台 TTL 清理（对应 `CleanupExpiredNonces`），批量删除后端 `renewal_tokens`。
- 注意 MySQL `VARBINARY(16)` / PG `BYTEA` / SQLite `BLOB` 的 nonce 主键方言差异由底层 db 包处理。
- **DA nonce（32B，`da_nonces`）** 防重放要求**确认前先持久化**：启用 WAL 时 nonce 同步 WAL fsync（`AddDANonceSync`）并批量收敛后端（`BulkStoreDANonces`）；无 WAL 时同步落库。见 `docs/RISKS.md` R1/R2。

**FR-5 子 CA / 信任锚 / AIC**
- `SubCAIndex`：`(name)` → SubCA 记录 + `parent_ca` 反向索引。
- `TrustIndex`：`(id)` → TrustAnchor 记录 + trusted/source 过滤。
- `AICIndex`：`(ca_name, serial)` → AICExtension，二级 `principal_uid` / `agent_id`。

### 4.2 写管道（WritePipeline，源自 RecordBuffer）

**FR-6 写管道能力（继承 RecordBuffer 全部机制）**
- `Add(rec)` 先写内存索引（不可失败，内存即真相），再追加到写管道。
- 攒批：`threshold` 条或 `max_latency` 到期触发批量落库（BulkInsert）。
- 背压：`max_pending` 硬上限，超限 `Add` 返回 false → 上层返回 503。
- WAL 预写日志：崩溃安全，重启回放。`<db>-records.wal`（file-backed SQLite 才有；`:memory:`/PG/MySQL 无 WAL）。
- WAL checkpoint：`pending==0` 时周期收敛，防止 WAL 无界增长。
- `drain()` 连续排空抗信号丢失限频。
- `FlushAll()`：读-改-写操作（吊销/续期）前同步排空，**但内存索引已经先行可见，varwof-core 不再需要手动 flush 约定**（见 FR-7 一致性）。
- **分片后端 writer（R4）**：吊销/nonce/元数据操作按 FNV-1a 键哈希分区到 `WriteWorkers` 个 goroutine——同 key 操作（nonce Store→Consume、证书签发→吊销、子 CA 重插）在单 goroutine 保序；不同 key 并行。`FlushAll` 对所有分片设屏障。证书批量插入仍在 RecordBuffer 路径（SQLite 单写锁）。

**FR-7 一致性模型：内存即真相**
- **写后读**：`IssueCert`（内存插入）→ 立即 `GetCertStatus` / `GetCertBySPKIHash` 命中内存，无 ≤500ms 可见性窗口，**废除吊销前手动 `FlushRecordBuffer()` 的约定**。
- **吊销**：`RevokeCert` 内存原子置 R + 通知 `OnCertRevoked` → 缓存精确失效；后端落库异步。
- **崩溃语义**：内存索引丢失 → 启动时全量从后端重建（见 §7）；WAL 只保护写管道中未落库的批次。

### 4.3 统一缓存失效

**FR-8 缓存（`cache` 包已提取）**
- 通用 TTL `Cache`（bounded，满时先清过期再丢新）：握手吊销缓存、authScopes。
- 通用 LRU `LRU`（serial 关联批量失效）：OCSP 响应缓存。
- `OnCertRevoked(serial)` 回调 → 精确失效（握手缓存 + OCSP LRU `PurgeSerial`）；bulk 吊销 → 全量失效。

### 4.4 外部接口（给 varwof-core 用的新 API）

**FR-9 建议的 Engine API（实施时按 varwof-core 调用点收敛，见 `docs/IMPLEMENTATION_PLAN.md`）**

```go
type Engine struct { ... }

// 构造：从后端 DB 全量加载 → 常驻内存索引
func NewEngine(d *db.DB, opts EngineOptions) (*Engine, error)

// 证书（读）
func (e *Engine) GetCert(caName, serial string) (*db.CertRecord, error)
func (e *Engine) GetCertStatus(caName, serial string) (*db.CertStatus, error)
func (e *Engine) GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error)
func (e *Engine) GetCertBySPKIHash(spkiHash, caName, status string) ([]*db.CertRecord, error)
func (e *Engine) ListCertsByPrincipalUid(uid, status string) ([]*db.CertRecord, error)
func (e *Engine) CheckDuplicateCN(caName, cn string, nb, na time.Time) error

// 证书（写）— 内存优先，落库异步
func (e *Engine) IssueCert(rec *db.CertRecord) error          // 写内存 + 入管道
func (e *Engine) RevokeCert(caName, serial string, reason int) error
func (e *Engine) RevokeCertsByPrincipalUid(uid string, reason int) (int, error)
func (e *Engine) RevokeCertsBySubCA(caName string, reason int) (int, error)

// CRL（纯内存生成）
func (e *Engine) GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error)
func (e *Engine) GetRevokedCerts(caName string) ([]*db.CertRecord, error)

// nonce
func (e *Engine) StoreNonce(nonce []byte) error
func (e *Engine) ConsumeNonce(nonce []byte) error
func (e *Engine) IsNonceUsed(nonce []byte) (bool, error)

// 子 CA / 信任锚 / AIC
func (e *Engine) GetSubCA(name string) (*db.SubCA, error)
func (e *Engine) GetTrustAnchor(id int) (*db.TrustAnchor, error)
func (e *Engine) GetAICExtensionByCert(caName, serial string) (*db.AICExtension, error)

// 生命周期
func (e *Engine) Start() error      // 启动重建 + janitor + 写管道
func (e *Engine) Stop() error       // FlushAll + 停 janitor
func (e *Engine) FlushAll() error   // 同步排空（运维/吊销兜底）
```

> 高频读取方法必须避开 `cert_der` 全量反序列化（沿用现有 `CertStatus` 轻量结构）。`ListCerts` / `ListCertsFilteredPage` / 分页等低频管理接口可先继续走底层 `db` 包透传。

## 5. 非功能需求

### NFR-1 性能（参考现有压测基线）
| 场景 | 现有基线（varwof-core, RecordBuffer 后） | 目标 |
|---|---|---|
| 单签发（顺序） | 1724 TPS | ≥ 1800 TPS |
| 单签发（并发 w16） | 16350 TPS | ≥ 20K TPS |
| mTLS 握手吊销点查 | SQLite 全局 pcache 锁主导 | 零 SQL（纯内存 map），P99 微秒级 |
| OCSP 点查 | SQL + LRU | 纯内存，命中零 SQL |
| CRL 生成 | SQL 全扫 + 过滤 | 纯内存遍历 `RevokedSet` |
| nonce Consume | SQL 两阶段 | 内存原子 CAS |

### NFR-2 内存有界
- 默认常驻：`certindex` 全量（证书记录数 × 每记录估 ~1KB 结构化引用）；过期证书按 FR-3 剪枝。
- 可配置上限：`max_certs`（超限逐出最旧过期）、`max_nonces`、`max_revoked_entries`。
- 提供 `Metrics()` Prometheus 输出（size / evicted / hit-rate）。

### NFR-3 崩溃安全
- 写管道 WAL 保证「内存已提交但未落库」的批次在重启后回放。
- 启动重建：后端全量加载 → 内存索引；加载期间服务可用性由上层决定（可先只读 fallback）。
- 幂等落库：`INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` / `INSERT IGNORE`（方言差异已在 db 层处理）。

### NFR-4 并发安全
- 索引读写用 RWMutex / sharded shard map；点查读锁。
- `ConsumeNonce` 必须原子 CAS。
- 无全局锁热点（沿用 RecordBuffer 已解决的 slog 锁竞争 / DB 连接池调优经验）。

### NFR-5 可观测性
- 指标：各索引 size / 命中率 / eviction / 写管道 pending / flush 时长 / WAL 大小。
- 结构化日志（slog），覆盖：重建耗时、flush 慢告警、背压触发、janitor 剪枝。

## 6. 现有实现与文档清单（本目录）

| 路径 | 内容 | 状态 |
|---|---|---|
| `db/` | SQL 后端层：三方言 Dialect、schema migration v1 (consolidated schema)、CertRecord CRUD、BulkInsert、nonce、AIC、sub_ca、trust_anchor、rbac/acme/ra 等全部表方法、分布式锁 | ✅ 从 `core/internal/db` 提取，测试全绿 |
| `recordbuffer/` | 写管道：批量缓冲 + WAL + 背压 + checkpoint + drain + FlushAll | ✅ 从 `core/internal/serve/record_buffer.go` 提取（`flushAll` 导出为 `FlushAll`），测试全绿 |
| `cache/` | 通用 TTL Cache + LRU（serial 关联失效） | ✅ 从 `internal/ocsp/cache.go` + `cmd/pki/serve.go` + `internal/serve/rbac.go` 提取合并，测试全绿 |
| `engine/` | 内存引擎：CertIndex/RevokedSet/NonceSet/SubCA/Trust/AIC 索引 + 写管道接线 + 启动重建 + janitor + Metrics | ✅ 按 IMPLEMENTATION_PLAN Phase A–F 实施，测试 + 基准全绿 |
| `docs/REQUIREMENTS.md` | 需求规格 | ✅ v0.2 已实施 |
| `docs/IMPLEMENTATION_PLAN.md` | 实施步骤 | ✅ Phase A–F 完成，Phase G 待 varwof-core |
| `docs/api.md` / `docs/config.md` / `docs/functions.md` | 面向用户的 API / 配置 / 函数文档（doc-driven 要求） | ✅ 与实现同步更新 |

## 7. 关键设计决策（已与用户确认）

| 决策点 | 结论 |
|---|---|
| 内存覆盖范围 | 热路径 5 类（certificates/吊销集/nonce/sub_cas/trust_anchors/aic_extensions） |
| 后端方言 | SQLite / PG / MySQL 三方言全保留 |
| 接入方式 | 全新 Engine API，varwof-core 渐进迁移（非签名兼容） |
| 一致性 | 内存即真相；写先内存，异步落库；废除手动 flush 约定 |
| 部署形态 | 单实例权威；v1 不做分布式一致 |
| 时间窗口 | OCSP/CRL 按证书有效时间窗口优化（FR-3） |
| 读写路径路由 | **读必走引擎内存，写路径内禁直连 DB**：写管道（RecordBuffer 落库）/吊销排队路径中的任何读都必须命中内存 primary；禁止在热路径加"读 DB 兜底"逻辑。内存同步更新无延迟，DB 只是持久化 sink。与 ShardingSphere `transactionalReadQueryStrategy=PRIMARY` 同理——弱一致下别引入 FIXED/DYNAMIC（读 DB 兜底） |
