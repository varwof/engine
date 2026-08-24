# varwof-engine 实施计划（IMPLEMENTATION_PLAN）

> 目标读者：负责实施内存引擎的 AI / 工程师。
> 前置：先读 `docs/REQUIREMENTS.md`（需求基线）与本目录提取的现状实现。
> 状态：**Phase A–F 已完成**（engine 包可编译可测）。Phase G 需 varwof-core 仓库接入，另行执行。

## 0. 现状盘点（已提取，可编译可测）

```
varwof-engine/
  db/             package db  — SQL 后端层（三方言 + schema v1 (consolidated) + 全部表方法）
  recordbuffer/   package recordbuffer — 写管道（WAL + 背压 + checkpoint + FlushAll）
  cache/          package cache — TTL Cache + serial 关联 LRU
  docs/
    REQUIREMENTS.md
    IMPLEMENTATION_PLAN.md
  go.mod
```

验证命令：
```bash
go test -count=1 ./...
```

## 1. 实施顺序（建议）

### Phase A — 内存索引核心（Engine 骨架） ✅ 完成
1. 新建 `engine/` 包，定义 `Engine` 结构 + `EngineOptions`（各索引容量上限、grace 窗口、janitor 间隔）。
2. 实现 `CertIndex`：
   - 主 map：`map[caName]map[serial]*db.CertRecord`（或复合 key string）。
   - 二级索引：issuerDN+serial、spki_hash、principal_uid、agent_id、（ca,cn,status='V'）。
   - **时间窗口索引**：每 CA 一个按 `not_after` 排序的 slice（或插入排序保持有序），支持二分「序列号是否在有效窗口内」「not_after >= t 的集合」。写操作后保持有序（可延迟排序 + dirty 标记，读前排序）。
3. 实现 `RevokedSet`：每 CA 一个 `map[serial]*db.RevokedCertEntry` + 按 revoked_at 排序的列表（CRL 生成序）。
4. 实现 `NonceSet`：`map[string]nonceEntry{used bool, exp time.Time}` + 原子 Consume（CAS）。
5. 实现 `SubCAIndex` / `TrustIndex` / `AICIndex`（低频，map 即可）。
6. 全部索引读写用 `sync.RWMutex`；高并发点查可后续升级 sharded map。

### Phase B — 写管道接线 ✅ 完成
1. `engine` 持有 `*recordbuffer.RecordBuffer`（写证书）+ 直接批量写（nonce/sub_ca/trust/aic 走各自 BulkInsert 或单写）。
2. `IssueCert`：先更新内存索引（成功才提交），再 `rb.Add(rec)`。内存索引是权威，落库失败不 rollback 内存（下次 flush 重试 / 启动重建收敛）。
3. `RevokeCert`：内存置 R + 入 `RevokedSet` + `OnCertRevoked(serial)` + 构造 UPDATE 批次入管道。
4. 崩溃安全：沿用 `recordbuffer` 的 WAL；若需 nonce/sub_ca 等也 crash-safe，扩展 WAL 记录类型（v2：带 `op` 字段的 JSONL）。
5. **一致性**：读方法全部走内存索引；`FlushAll()` 仅用于运维兜底，varwof-core 吊销前不再需要手动调用。

### Phase C — 启动重建（load） ✅ 完成
1. `NewEngine`：`d.ListCerts...` 全量加载（按 CA 分页，复用 `BulkInsert` 的反向 scan），构建全部索引；`GetRevokedCertEntries` 加载 `RevokedSet`；nonce 表加载未过期 nonce；sub_ca/trust/aic 全量。
2. 重建期间：提供 `Loading()` 状态，上层可拒绝写或只读降级。
3. 重建耗时打点（slog + metric）。

### Phase D — janitor 与内存有界 ✅ 完成
1. 后台 ticker（默认 60s）：
   - 剪枝 `not_after < now - grace` 的 V 状态证书出热区（可选保留冷 map 或丢弃——按需求 v1 直接丢弃，因为后端是权威）。
   - 清理过期 nonce。
   - 清理过期吊销条目（not_after < now 从 RevokedSet 移除）。
2. 上限逐出：`max_certs` 超限逐出最旧过期；否则拒绝新增（上层 503 或记录告警）。

### Phase E — 指标与日志 ✅ 完成
1. `Metrics()` 输出 Prometheus：`varwof_engine_certindex_size` / `varwof_engine_revokedset_size` / `varwof_engine_nonceset_size` / `varwof_engine_window_evictions_total` / `varwof_engine_read_hit_total{op}` / `varwof_engine_pipeline_pending` / `varwof_engine_flush_duration_seconds`。
2. slog：重建完成、慢 flush（>50ms）、背压触发、janitor 剪枝数量。

### Phase F — 单测 + 基准 ✅ 完成
- 单测：每个索引 CRUD、时间窗口剪枝、nonce CAS 并发、CRL 生成纯内存正确性、写管道 + 内存一致性（签发→立即可读→吊销→立即可见）。
- 基准（对比 varwof-core 基线，见 REQUIREMENTS NFR-1）：
  - `BenchmarkGetCertStatus`（命中/未命中/过期）。
  - `BenchmarkIssueCert`（内存写，不含落库）。
  - `BenchmarkGetRevokedCertEntries`（1K/10K/100K 吊销集）。
  - `BenchmarkConsumeNonce`（并发 CAS）。

### Phase G — varwof-core 接入（渐进迁移） ⏳ 待 varwof-core 仓库接入
> 关键：逐步替换，不一次性。每个替换点跑 varwof-core 全量回归（`go test -count=1 -short ./...`）。

1. `internal/serve`：`Server` 持有 `*engine.Engine`；`getDB()` 之外加 `getEngine()`。
2. 第一批替换（纯读，风险最低）：
   - `GetCertStatusByIssuer`（握手吊销）→ 引擎（替换 `revocationCache`）。
   - `GetCertStatus`（OCSP handler）→ 引擎。
   - `GetCert` / `GetCertStatus`（数据面 API）。
3. 第二批（写路径）：
   - `apiIssueCert`：`SkipDB=true` + 内存 `IssueCert`（替代 RecordBuffer.Add 到 DB，改为 Add 到引擎）。
   - 吊销 API：内存 `RevokeCert` + 移除入口 `FlushRecordBuffer()`。
   - nonce API（renew/token）→ 引擎 `ConsumeNonce`。
4. 第三批（CRL/管理）：
   - CRL 生成：`GetRevokedCertEntries` → 引擎。
   - 重复 CN 检查、SPKI 查询、principal 列举 → 引擎。
5. 清理：移除旧 `revocationCache` / `authScopesCache`（保留 `cache` 包用于 OCSP LRU）。
6. 全量回归 + 压测对比（NFR-1 表）。

## 2. 风险与对策

| 风险 | 对策 |
|---|---|
| 内存索引与后端漂移（落库失败） | 幂等落库 + 启动重建收敛；落库失败告警 + 重试队列 |
| 内存无界增长 | janitor 剪枝 + 上限逐出（Phase D）+ 指标监控 |
| 时间窗口索引排序开销 | 延迟排序 + dirty 标记；写路径只 O(log n) 插入有序 slice |
| 全量重建启动慢（大库） | 分页流式加载 + 进度日志；可选冷启动只建索引不载 DER |
| varwof-core 迁移回归 | 渐进替换 + 每步全量测试；新旧并存期用 feature flag 回退 |
| nonce CAS 竞态 | 内存单机权威，`ConsumeNonce` 单锁 CAS；无跨实例问题 |

## 3. 验收标准

- [x] `varwof-engine` 独立模块 build + vet + test 全绿（含并发测试）。
- [x] 全部 FR-1..FR-9 实现；REQUIREMENTS NFR-1 性能目标达成（基准对比，见 `engine_bench_test.go` 基线：GetCertStatus ~230ns、IssueCert 内存 ~7.2µs、ConsumeNonce 并发 CAS）。
- [x] 测试与覆盖率记录在 `docs/TESTING.md`（cache 99.1% / engine 97.0% / db 83.5% 含 PG 真库 86.5% / recordbuffer 81.6%）；剩余工作清单见 `docs/NEXT_STEPS.md`。
- [x] `OnCertRevoked` 精确失效路径生效（握手缓存 + OCSP LRU）——经 `EngineOptions.OnCertRevoked` 回调，varwof-core 接入后挂接。
- [ ] 崩溃恢复：kill -9 → 重启 → WAL 回放 → 内存索引完整（已由 `recordbuffer` WAL 承担；engine 全量重建由 `TestEngineRebuildFullState` 覆盖已吊销/已用 nonce/subCA/信任锚/AIC 路径，`TestConvergenceMemoryAuthoritative` 覆盖内存权威 + 后端有序收敛；端到端验证待 varwof-core 集成环境）。
- [ ] varwof-core 渐进迁移后全量 `go test -count=1 -short ./...` 全绿，无手动 flush 约定残留（待 Phase G）。
- [x] doc-driven：新增导出函数有 doc comment；`docs/api.md` / `docs/config.md` / `docs/functions.md` 与实现同步。
