# 风险清单 — 大规模 AIC 发证场景

> 识别时间：2026-08-20。针对内存即真相引擎（`engine` 包 + `recordbuffer`）在 AIC 大规模发证工作负载（海量签发 / 批量吊销 / 高频查询）下的风险评估。与 `docs/zh/IMPLEMENTATION_PLAN.md` 和 `docs/zh/NEXT_STEPS.md` 保持同步。

## 严重度图例

- 🔴 **高风险** — 安全、一致性或硬吞吐天花板。优先修复。
- 🟠 **中风险** — 规模化后的性能退化，或负载下的 OOM / 慢路径风险。
- 🟡 **低风险** — 运维 / 可观测性 / 容量规划缺口。

---

## 🔴 R1 — DA nonce 单条写入（AIC 特有写放大）

**位置：** `engine/writes.go` `StoreDANonce` / `ConsumeNonce`

每次 AIC 签发消耗一个 DelegationAuthorization nonce。`StoreDANonce` 将一条单行 INSERT 排入串行 writer 通道（`writerCh`），**不走批量写管道**。7K–11K TPS 发证时即每秒 7K 条单行 DB 写，全部串行在单个 worker 后面——隐藏瓶颈，随发证速率线性增长。

**修复：** 将 DA nonce 存储接入 RecordBuffer 批量路径（WAL 保护的批量 upsert），或将不同 nonce 合并为周期批量写入。

**状态：✅ 已修复（2026-08-20）** — `RecordBuffer` 改为带标记的 `Item` 管道（`KindCert` / `KindDANonce`）；`StoreDANonce` 将 nonce 写入 WAL，批量 flush 通过新增 `db.BulkStoreDANonces` 多行 INSERT 落库。测试：`TestBulkStoreDANonces`、`TestRecordBufferAddDANonceSyncPersistsBatch`、`TestStoreDANonceBatchConvergence`。

## 🔴 R2 — DA nonce 崩溃窗口（可重放漏洞）

**位置：** `engine/writes.go` `StoreDANonce` + `engine/load.go`

内存即真相：DA nonce 先在内存 `NonceSet` 标记已用，再排队异步落库。进程在内存标记与 enqueue 之间崩溃 → 重启后 nonce 丢失 → 同一 DA 签名可重放签发第二个 AIC。`da_nonces` 表是最终持久化目标，但在此窗口内无保护。

**修复：** 在 nonce 成为内存权威前先落库（或 WAL fsync），或在每次 AIC 签发确认成功前强制 WAL fsync。

**状态：✅ 已修复（2026-08-20）** — `RecordBuffer.AddDANonceSync` 返回前同步 fsync WAL；无 WAL 时 `StoreDANonce` 回退同步 DB 持久化。签发确认前 nonce 已持久化，重启恢复从 WAL 回放进 `da_nonces` 表 + 内存。测试：`TestStoreDANonceWALCrashRecovery`（kill -9 子进程）、`TestStoreDANonceNoWALFallbackSync`、`TestRecordBufferDANonceWALReplay`。

**更新（2026-08-27）** — 无 WAL（非文件后端：PostgreSQL/MySQL）时 `StoreDANonce` 改为把 nonce 缓冲进批量写管道（`RecordBuffer.AddDANonce` → `BulkStoreDANonces`），不再每请求同步单行 INSERT。旧路径是 AIC 每请求吞吐墙（~3,200 certs/s 上限，每个 nonce 都同步过 WAL fsync）。内存对重放校验即刻权威；后台 `da_nonces` 表在下次批量 flush 收敛。无 WAL 后端的未 flush 崩溃窗口改为**接受的取舍**（见 `StoreDANonce` 与 `AddDANonce` 注释）——flush 前崩溃可能丢失未落库 nonce，导致回放签名暂时可被接受直至 DB 收敛；WAL 后端仍保持完整崩溃安全。测试：`TestStoreDANonceNoWALBatchAndReplay`、`TestDANonceNoWALBatchConvergence`、`TestRecordBufferAddDANonceNoWALBatches`。

## 🔴 R3 — 批量吊销为 N 条串行 UPDATE

**位置：** `engine/writes.go` `RevokeCertsBatch` / `RevokeCertsByPrincipalUid` / `RevokeCertsBySubCA`

批量吊销 N 个证书在单个 writer goroutine 内逐条执行 N 条 UPDATE。吊销 10 万证书 ≈ 10 万次串行 UPDATE（每条约 1ms → 约 100 秒）。内存翻转已是单锁快速完成；DB 收敛成为瓶颈。

**修复：** 每次批量吊销用单条批量语句持久化（`UPDATE ... CASE WHEN` / 临时表 JOIN / 多行 VALUES），保持 writer 的有序性保证。

**状态：✅ 已修复（2026-08-20）** — 新增 `db.BulkRevokeCertificates`：每个约 199 条分块一条 `UPDATE ... revoke_reason=CASE ... WHERE (...) AND status='V'`（CASE 表达式承载每行 reason）；`Engine.RevokeCertsBatch` 改为调用它而非 N 条串行 UPDATE。测试：`TestBulkRevokeCertificates`（300 行跨 2 块、每行 reason、幂等重跑）、`TestRevokeCertsBatchBulkConvergence`。

---

## 🟠 R4 — 单写管道是硬天花板

**位置：** `engine/engine.go` `writerCh` + `recordbuffer.RecordBuffer`

单个 RecordBuffer（单 drain goroutine + 单 flush 互斥锁）+ 单个 writer goroutine 串行化所有持久化。实测 7K–11K TPS 已接近极限。超越后需要扩展写路径。

**修复：** 分片写管道（按键分区的多 worker）或提高 writer 并发并保持有序语义。

**状态：✅ 已修复（2026-08-20）** — 后端 writer 改为分片池（`EngineOptions.WriteWorkers`，默认 4）。操作经 `writerShardForKey`（FNV-1a 哈希）路由：同 key 操作（nonce Store→Consume、证书签发→吊销、子 CA 重插）在单个 goroutine 保序；不同 key 并行。`FlushAll` 对所有分片设置屏障。`RevokeCertsBatch`/`FlushAll` 有序保证保留（先 flush INSERT，批量操作幂等）。测试：`TestWriterShardForKeyStable`、`TestShardedWriterNonceOrdering`、`TestShardedWriterAllShardsActive`、`TestRevokeCertsBatchOrderingAcrossShards`。证书批量插入仍在 RecordBuffer 批量路径（SQLite 单写锁使并行 flush 反而低效）。

## 🟠 R5 — 单一证书索引锁

**位置：** `engine/cert_index.go` `CertIndex.mu`（单 RWMutex）

所有插入与吊销抢写锁；每次锁持有进行 5-6 次 map 写入 + 一次 heap push。50K+ TPS 时写锁串行化发证。

**修复：** 按 CA（或按 key 哈希）分片索引，每片独立锁。

## 🟠 R6 — 全量结果物化 + 无上限排序

**位置：** `engine/cert_index.go` `filterSortedSetPage` + `getBySPKI` / `getByUid` / `getByAgent`

查询原返回全部匹配集合并排序 O(n log n)。单 principal 10 万证书 = 每次查询全量复制 + 排序，阻塞调用 goroutine。

**修复：** 高基数查找分页 + 返回上限 + 游标。

**状态：✅ 已修复（2026-08-20）** — 新增 `CertCursor`（不透明游标：NotBefore 降序 + serial 降序位置）；`getBySPKI` / `getByUid` / `getByAgent` 现接受 `(limit, after)` 并通过 `filterSortedSetPage` 分页——用有界最小堆只保留最优 `limit+1` 候选（O(n) 扫描 + O(n log limit) 堆操作，仅物化 `limit+1` 条），返回精确 `hasMore`。`limit<=0` 保持旧全量契约。引擎层 `GetCertBySPKIHash` / `ListCertsByPrincipalUid` / `ListCertsByAgentID` 暴露相同签名（recs、下一游标、hasMore、error）。测试：`TestPagedGetCertBySPKIHash`（250 条共享 SPKI、NotBefore 聚簇）、`TestPagedListCertsByAgentID`（按状态过滤）、`TestPagedListCertsByPrincipalUid`——全部逐页遍历并断言唯一性 + 规范序。

## 🟠 R7 — 规模化后启动重建慢

**位置：** `engine/load.go`（分页 1000/步，逐条 put + 每次 heap push O(log n)）

加载 100 万证书 = 1000 次分页查询 + 100 万次 heap push + 索引构建。启动可达数十秒，期间引擎报告 `Loading()`。

**修复：** 并行加载（按 CA 分片）+ 进度指标 + 可选延迟建索引。

---

## 🟡 R8 — 内存驻留无字节预算

**位置：** `engine/options.go` `MaxCerts`（按数量，默认 20 万）

每条驻留 `CertRecord` 含 cert_der（1–4KB）+ AIC JSON + 5 个二级索引指针 ≈ 20 万条超 1GB。逐出只考虑 NotAfter，不考虑访问热度——长生命周期活跃 AIC 永久驻留。

**修复：** 字节预算 / 每 CA 上限 + 热/温分层。

**状态：✅ 已修复（2026-08-20）** — 新增 `EngineOptions.MaxResidentBytes`（默认 2 GiB），与 `MaxCerts` 一起在 `CertIndex.insertIfAbsent` 中执行：当驻留字节估算（基础开销 + cert_der + 字符串字段，put/remove/evict 时维护为 `CertIndex.residentBytes`）超预算时先逐出过期证书，否则 `IssueCert` 返回 `ErrBackpressure`。AIC 扩展同样记账（`AICIndex.residentBytes`）。两者经 `CertIndex.ResidentBytes()` / `AICIndex.ResidentBytes()` 及 `CertResidentBytes` / `AICResidentBytes` 指标暴露。测试：`TestByteBudgetRejectsOversizedInsert`、`TestByteBudgetEvictsExpiredFirst`、`TestAICResidentBytes`。

## 🟡 R9 — aic_extensions 表无限增长

**位置：** `engine/engine.go` janitor + `engine/load.go` AIC 分页

每个 AIC 一条记录；janitor 只清理 nonce 和证书，不清理已过期证书对应的 AIC 扩展 → 表无界增长，拖慢每次启动。

**修复：** janitor 清理已离开热窗口证书对应的 AIC 扩展。

**状态：✅ 已修复（2026-08-20）** — `CertIndex.evictExpired` 现返回被逐出证书的 `(ca, serial)` 键；janitor 级联调用新增 `AICIndex.removeByCert`（从 byCert / byAgent / byUid 三个 map 删除）并排队 `db.DeleteAICExtension`，使用与 `UpsertAICExtension` 相同的分片键（`ca/serial`），保证删除排在插入 / 同 serial 重发之后。热证书的 AIC 行保留。测试：`TestJanitorPrunesAICForEvicted`（内存 + 后端断言）、`TestJanitorSkipsAICForMissingCert`。

## 🟡 R10 — 缺少 AIC 专项指标

**位置：** `engine/engine.go` `Metrics` / `PrometheusMetrics`

缺少：发证/吊销速率、逐出细分、AIC 索引大小、驻留字节数、管道延迟直方图、WAL 大小。

**修复：** 增加 gauge/counter/histogram。

**状态：✅ 已修复（2026-08-20）** — `Metrics` 新增 `CertIssued` / `CertRevoked` 计数（接线 `IssueCert` + 全部 4 条吊销路径）、`AICPruned`（janitor AIC 清理）、`CertResidentBytes` / `AICResidentBytes`（R8 记账）、`WalBytes`（recordbuffer WAL 文件大小）、`FlushDuration` 直方图（4 桶，Prometheus 输出为累计）。`PrometheusMetrics` 全部渲染：`varwof_engine_cert_issued_total`、`varwof_engine_cert_revoked_total`、`varwof_engine_aic_pruned_total`、`varwof_engine_cert_resident_bytes`、`varwof_engine_aic_resident_bytes`、`varwof_engine_wal_bytes`、`varwof_engine_flush_duration_seconds`（histogram）。测试：`TestMetricsCounters`、`TestPrometheusMetricsNewFields`、`TestRevokeCountersBulk`。

---

## 修复顺序（2026-08-20 确认）

1. ~~R1 + R2 — DA nonce 批量管道 + 崩溃安全~~ ✅（2026-08-20）
2. ~~R3 — 单语句批量 UPDATE 吊销~~ ✅（2026-08-20）
3. ~~R4 — 写管道分片 / worker 池~~ ✅（2026-08-20）
4. ~~R6 + R9 — 查询分页 + AIC janitor 清理~~ ✅（2026-08-20）
5. ~~R8 + R10 — 内存预算 + 指标~~ ✅（2026-08-20）

## 🟡 R11 — RBAC 用户/Token 内存索引的一致性夹角（2026-08-27）

认证读路径（authByToken / authByBasic / authFromAIC / gateway 委托）与用户/
Token 管理写路径全部经 serve 包装方法（engine 优先、DB 回退；写穿先落 DB 再
刷新驻留行）。**剩余两个可接受的夹角**:

1. **OOB 新增不可见性**：CLI/第二实例绕过 serve 直接写库创建的用户/Token，
   engine 内存不知情 → 该账户认证回退 DB（可读，不丢功能），但**不享受内存
   快路径**，直至重启全量载入。
2. **OOB 删除残留（与证书相反方向）**：DB 里已删的用户/Token 若仍驻留内存，
   内存会继续认证它（内存即真相）——与证书 OOB 写"读回退 DB 可见"方向相反。
   缓解：serve 内删/改/密码轮换全部走写穿，内存与后端同步，这是唯一受支持的
   运维通道；纯 DB 外删需重启或以写穿通道执行。TPM 侧相同。

修复顺序（2026-08-27）：`R11` 无修复项 —— 为**接受的权衡**，方向与 `R2` 无
WAL 取舍一致（内存即真相 + OOB 退化为 DB 往返/重启收敛），已在
`docs/REQUIREMENTS.md` 与 serve 侧包装方法注释中记录。

## 🔴 R12 — 写管线在后端半开连接下永久阻塞（2026-08-27）

**位置：** `db/batch.go` / `db/da_nonces.go` / `recordbuffer/record_buffer.go`

MySQL 连接半开（对端挂死/重置）时，`bulkInsertChunk→Exec` 内层
`mysqlConn.readPacket` **无读超时地永久阻塞**，而 flush 全程持有 `flushMu`：
drain goroutine 卡死 → pending 钉在 maxPending（全请求 503）→
`Stop()→FlushAll()` 死锁等同一把锁 → 优雅停机挂死。此前文档记录
"MySQL+engine 写管线瘫：内存涨 21GB + connection reset by peer" 即此故障族
（其中 21GB 一项经 dmesg 实证为 OOM 击杀：`oom-kill bench-smoke anon-rss
~21GB`，现版本已有 2GiB `MaxResidentBytes` 预算兜底，不再复现）。

**修复：**
1. `db/db.go`：`OpenWithDialect` 的 mysql 分支注入 `ensureMySQLTimeouts`（缺省补
   `timeout=10s&readTimeout=30s&writeTimeout=30s`，已存在不覆盖，`@unix(` 跳过）；
   新增 `ExecContext`（ctx 感知的 rebind+adapt 批量 Exec）。
2. `db/batch.go` / `db/da_nonces.go`：新增 `BulkInsertCertRecordsCtx` /
   `BulkStoreDANoncesCtx` 及分块 ctx 变体，旧入口委托 `context.Background()`。
3. `recordbuffer/record_buffer.go`：`flushLocked` / `replayWAL` 的批量写统一包
   `context.WithTimeout(..., flushDBTimeout=2min)` —— 半开连接至多拖 2 分钟即
   返回错误走重试，不再无限阻塞。

**状态：✅ 已修复（2026-08-27）** — 顺带把 PG/MySQL 批量分块从 39 行/条提升到
500 行/条（`certChunkSize`，SQLite 仍守 999 变量上限）：写入往返次数降 ~13×，
MySQL AIC @100ms 从 4,325 → **6,034 certs/s**。真库验证：MySQL regular @100ms
（原崩溃场景）7,575 certs/s、AIC @100ms 6,034 certs/s、AIC @600ms 4,114/s，
全部 exit=0 且正常打印报告；PG AIC @600ms 4,054/s 无回归。`-race` 全绿。
新单测：`TestEnsureMySQLTimeouts`、`TestBulkInsertCertRecordsCtxCancelled`、
`TestBulkStoreDANoncesCtxCancelled`。

各项修复状态在 `docs/NEXT_STEPS.md` 和 `docs/zh/NEXT_STEPS.md` 中跟踪。

> **真库验证已完成（2026-08-20）**：`BulkStoreDANonces` / `BulkRevokeCertificates` 方言分支已在本机 PostgreSQL 15 与 MariaDB 10.11 上验证——新增 `TestPGBulkStoreDANonces` / `TestPGBulkRevokeCertificates` / `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates`（每次运行新建独立数据库，批量存储 + 重复忽略/幂等重跑 + 32 字节校验 + 跨分块每行 reason）。`go test -tags postgres` / `-tags mysql ./...` 全套件全绿。
## 🔴 R13 — 满缓冲 DA nonce 存储打雷群涌入 flushMu（2026-08-27）

**位置:** `recordbuffer/record_buffer.go`（`AddDANonce` / `AddDANonceSync`）

当 record buffer 达到 `maxPending` 时，`AddDANonce` 会在每个请求上执行同步
`FlushAll()`。`FlushAll` 在整个 flush pass 期间持有 `flushMu`（一次性批量插入
**全部** pending 记录，O(积压量)），因此一旦缓冲填满——持续 AIC 负载在默认 20k
pending 下约 18s 填满——每个请求 goroutine 都串行排在同一个 `flushMu` 后面：
整个服务器冻结，pending 钉在 maxPending。在 engine bench 下表现为硬吞吐塌缩：
40s AIC @100ms 运行在 ~108k 成功（与 20s 运行相同）处停滞，p99 涨到 ~22s，
约 2,000 个 goroutine 阻塞在 `FlushAll`，而 drain goroutine 仍在批量冲洗 8.5 万条
记录。

**修复:** 同步追加路径不再自行 flush。满时 `waitForCapacity()` 唤醒 drain 循环并
在 close-and-replace 广播通道（`capacitySignal`，drain 每次 flush pass 触发）上
睡眠；容量一释放全部 waiter 同时唤醒。若 drain 在 `fullWaitTimeout`（5s）内无法
腾出容量，`AddDANonce` 返回新的 `recordbuffer.ErrBackpressure`，
`Engine.StoreDANonce` 归一化为 `engine.ErrBackpressure`，serve 调用方返回 503
（签发失败、不产生证书、重放防护永不削弱）。这是真正的背压——缓冲满意味着后端
无法吸收写入——优雅降级而非全服务器死锁。

**状态: ✅ 已修复（2026-08-27）** — 40s AIC @100ms（MySQL、engine、2500 agents）
从 ~108k 平台恢复到 **~163k 成功（~4.1k certs/s）**，恰好等于 MySQL 批量插入
持续上限（含 DA nonce 约 8k records/s；独立测量：500 行 chunk ≈ 7.3k certs/s）；
不再有 goroutine 阻塞在 `FlushAll`；背压以干净的 503 呈现。20s 运行可突发到
~5.3k certs/s（缓冲吸收），随后稳定到 ~4k/s 持续。新增单测：
`TestRecordBufferAddDANonceWaitsForCapacity`、
`TestRecordBufferAddDANonceConcurrentWaits`、
`TestRecordBufferAddDANonceBackpressureTimeout`。`recordbuffer/`/`engine/`/`db/`
`-race` 全绿。
