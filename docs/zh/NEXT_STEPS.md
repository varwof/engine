# 剩余工作清单（NEXT_STEPS）

> 记录 varwof-engine 尚未完成 / 受环境阻塞 / 可选优化的事项。持续更新，与实现同步。

## 高风险修复（2026-08-20 确认）

跟踪于 `docs/RISKS.md` / `docs/zh/RISKS.md`。修复顺序：R1+R2（DA nonce 批量管道 + 崩溃安全）、R3（单语句批量吊销）、R4（写管道分片）、R6+R9（查询分页 + AIC janitor）、R8+R10（内存预算 + 指标）。

| 项目 | 状态 |
|---|---|
| R1+R2 — DA nonce 批量管道 + 崩溃安全 | ✅ 已完成（2026-08-20）：带标记的 RecordBuffer Item 管道 + `AddDANonceSync`（WAL fsync）+ `db.BulkStoreDANonces` |
| R3 — 单语句批量 UPDATE 吊销 | ✅ 已完成（2026-08-20）：`db.BulkRevokeCertificates` CASE UPDATE，`RevokeCertsBatch` 已接入 |
| R4 — 写管道分片 / worker 池 | ✅ 已完成（2026-08-20）：分片 writer（`WriteWorkers`，FNV-1a 按键路由，同 key 保序，`FlushAll` 全分片屏障） |
| R6+R9 — 查询分页 + AIC janitor 清理 | ✅ 已完成（2026-08-20）：`CertCursor` + SPKI/UID/agent 查询 `(limit, after)` 分页（`filterSortedSetPage`，有界 limit+1 堆，精确 hasMore）；janitor 对被逐出证书级联 `AICIndex.removeByCert` + `db.DeleteAICExtension` |
| R8+R10 — 内存预算 + AIC 指标 | ✅ 已完成（2026-08-20）：`MaxResidentBytes` 字节预算作用于 `CertIndex`/`AICIndex`（put/remove/evict 估算，过期优先逐出，否则 `ErrBackpressure`）；`Metrics` 新增签发/吊销/AIC 清理计数、证书+AIC 驻留字节、WAL 大小、flush 延迟直方图，全部经 `PrometheusMetrics` 渲染 |

### 真库验证已完成（2026-08-20）

`db.BulkStoreDANonces` / `db.BulkRevokeCertificates` 方言分支已在本机 PostgreSQL 15（localhost:5432，`PG_TEST_DSN`）与 MariaDB 10.11（localhost:3306，`MYSQL_TEST_DSN`）上验证：新增 `TestPGBulkStoreDANonces` / `TestPGBulkRevokeCertificates` / `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates`。SQLite 路径由 `TestBulkStoreDANonces` / `TestBulkRevokeCertificates` 覆盖。`-tags postgres` / `-tags mysql ./...` 全套件全绿。

注：文档此前记录的 127.0.0.1:3307 隔离 MariaDB 实例未运行，改用了 3306 本机系统 MariaDB（创建 `varwof`@`localhost` / `varwof`@`127.0.0.1` 用户并授全部权限）。PostgreSQL 创建了 `varwof` 登录角色 + `pki` 数据库 + `CREATEDB`。

### 吊销路径数据竞态已修复（2026-08-20）

`setRevokedLocked`（`engine/cert_index.go`）此前就地修改共享 `*db.CertRecord`（`Status` / `RevokedAt` / `RevokeReason`），而 `recordStatus`（`engine/reads.go`）与 recordbuffer drain 在索引锁外读取这些字段——`-race` 下 `TestConvergenceMemoryAuthoritative` / `TestConcurrentReadsDuringBulkRevoke` 偶发。修复方案 = 写时复制（copy-on-write）：record 一经发布即不可变；吊销时发布克隆（`setRevokedLocked` → `replaceLocked`）在主索引 + 全部二级索引中替换实例，`removeLocked` 按主键解析当前实例删除，保证逐出窗口堆持有的吊销前指针仍能正确删除。`RevokeCertsBatch` 现将每条 entry 的 reason 在发布前写入各自克隆（不再事后就地改）。两个测试 + engine 全套件 `-race` 全绿。

### WAL 并发加固（2026-08-20，R1/R2 跟进）

R6/R9 跑 `-race` 时暴露 `recordbuffer` 真实竞态：`bufio.Writer` + WAL `os.File` 被 drain goroutine（`flushLocked`）、`add()` 内周期 fsync、`AddDANonceSync` 共享且无共同锁。修复：新增 `RecordBuffer.walMu`，串行化所有 WAL 写 / flush / sync / truncate / seek / close。`TestStoreDANonceWALCrashRecovery` 也改为 `-race` 下确定（crash helper 在 `load()` 后关闭 DB 句柄，使 drain 失败而不落库/不截断 WAL，保持"重放前 DB 为空"断言可靠）。

## 阻塞项（需外部环境）

| 事项 | 阻塞原因 | 状态 |
|---|---|---|
| Phase G：varwof-core 渐进迁移（`IMPLEMENTATION_PLAN.md` Phase G 1-6） | varwof-core 仓库不存在 | 待接入 |
| 崩溃恢复端到端验证（kill -9 → 重启 → WAL 回放 → 内存索引完整） | 需 varwof-core 集成环境；engine 侧已由 `TestEngineRebuildFullState` / `TestConvergenceMemoryAuthoritative` 覆盖 | 待集成环境 |
| MySQL/MariaDB 真库验证 | 已完成（2026-08-10 + 2026-08-20）：本机 MariaDB 10.11。2026-08-20 改用 3306 系统实例（`varwof` 用户已建）跑 `-tags mysql`，新增 `TestMySQLBulkStoreDANonces` / `TestMySQLBulkRevokeCertificates`（R1/R3 方言分支真库验证），全套件全绿 | ✅ 已完成 |
| `go test -race ./...` | 本机 arm64 内核 ASLR 熵固定 39bit（TSan 需 ≤32，`vm.mmap_rnd_bits` sysctl 拒绝下调，需重编内核）；并发测试已设计为 CI 可跑 `-race`。此前的吊销竞态已修复（见「吊销路径数据竞态已修复」）；engine 套件本机 `-race` 全绿 | 待 CI |
| CI workflow（test + vet + race + 覆盖率门禁） | ✅ 已完成（2026-08-24）：`.github/workflows/ci.yml`（build/vet/test/race/覆盖率门禁 85%/PG 与 MariaDB 真库服务容器） | ✅ 已完成 |

> **PostgreSQL 已就绪**（2026-08-10 + 2026-08-20）：本机 PG 15 在线。2026-08-20 创建 `varwof` 角色（`$PASSWORD`）+ `pki` 数据库 + `CREATEDB`，`PG_TEST_DSN="postgres://varwof:$PASSWORD@localhost:5432/pki?sslmode=disable"`。
> PG 门控用例：`go test -tags postgres ./db/ -run 'TestPGConnect|TestPGAdvisoryLockReal|TestPGTransferToReal|TestCreatePGDatabaseReal|TestPGBulkStoreDANonces|TestPGBulkRevokeCertificates'`。
> 覆盖全量迁移、advisory lock 真库、`TransferTo` 的 pgx 序列更新分支、R1/R3 方言分支（db 覆盖率 85.6% → 86.5%）。
> 真库测试暴露并修复了 `NewDistLock` 类型断言 bug（`d.dialect.(pgDialect)` 匹配不到 `*pgDialectWithConfig`）。

> **MariaDB 已就绪**（2026-08-10 + 2026-08-20）：本机 3306 系统实例（2026-08-10 记录的 3307 隔离实例未运行）。
> `MYSQL_TEST_DSN="varwof:$PASSWORD@tcp(127.0.0.1:3306)/pki_mysql?charset=utf8mb4&parseTime=true" go test -tags mysql ./db/`。
> 覆盖全量迁移、证书 CRUD roundtrip、999 变量分块 bulk（2000 条）、`TransferTo` 通用路径、R1/R3 方言分支（db 覆盖率 85.6% → 86.1%）。
> 注意：MariaDB 的 `NewDistLock` 走文件锁（仅 PG 走 advisory lock）。

## 覆盖率剩余未覆盖（engine 99.0% / db 86.5%）

| 位置 | 说明 | 能否覆盖 |
|---|---|---|
| `engine/load.go:31-59` | ListNonces / ListSubCAs / ListTrustAnchors / ListAICExtensions 的错误分支（镜像于已覆盖的 certs 错误分支） | 需注入式查询失败，低价值 |
| `engine/load.go:66` | AIC 分页 offset 递增（`TestEngineRebuildAICPagination` 已覆盖同逻辑的 certs 路径） | 见上 |
| `engine/writes.go:39-44` | `!rb.Add(rec)` 分支（IsFull 前置检查之后的竞态窗口，实际不可达） | 竞态，无法确定性触发 |
| `db/transfer.go:51-55` | `TransferTo` 的 pgx 分支 —— **已由 `TestPGTransferToReal` 覆盖**（含序列更新） | ✅ 已覆盖 |
| `db/lock.go:77-82` | `pgAdvisoryLock.TryLock` 的 `acquired=true` 分支 —— **已由 `TestPGAdvisoryLockReal` 覆盖** | ✅ 已覆盖 |

## 可选优化 / 候选测试

- [ ] `BulkInsertAICExtensions` 批量插入（现 AIC 逐条写）
- [ ] `GetRevokedCertEntries` 转换池化（CRL 生成路径的对象复用）
- [ ] `UpsertSubCA` / `UpsertTrustAnchor` / `UpsertAICExtension` 方言覆盖测试
- [ ] 高并发下 `RecordBuffer.Add` 与 `IsFull` 竞态的确定性构造测试
- [ ] `TransferTo` 目标为非空库 / 幂等重入测试

## 环境注意事项（本机树莓派 4B）

- TF 卡慢：`go test -fuzz` 必须先跑完整包测试再 fuzz，db 包 ~60-90s 曾致 120s 超时。**fuzz 必须加 `-run='^$'`**。
- `go test -race` 不可用（见上）。
- 基准数字为硬件相关，重测需在同一环境下对比；README「基准」表定期重测更新（`go test ./... -bench . -benchmem` 直接运行）。

## 代码审查规则（写路径路由）

- [ ] 热路径读必须走引擎内存；PR 中禁止出现"先查 DB 兜底"的新增代码（决策见 `REQUIREMENTS.md` §7 读写路径路由）。
- [ ] 新写方法（IssueCert/Revoke/ConsumeNonce）不得在索引锁内发起同步 DB 调用；落库只能经 RecordBuffer/WAL 异步。
- [ ] 新增导出方法需带 doc comment（`docs/functions.md` 同步）。
- [ ] 改 dialect/迁移后，用 `-tags postgres` 与 `-tags mysql` 真库套件回归。
