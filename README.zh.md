# varwof-engine

以内存为中心的专用高速数据子系统，为 varwof-core 提供 OCSP / CRL / nonce / 证书状态的常驻内存查询与批量落库。

[English](README.md)

## 定位

- **内存即真相**：高频读写全部命中内存索引，读零 SQL，写先内存后异步落库。
- **批量落库**：继承 varwof-core RecordBuffer 机制（WAL 崩溃安全 / 背压 / checkpoint / FlushAll）。
- **时间窗口优化**：OCSP/CRL 按证书有效时间窗口剪枝，过期证书移出热内存。
- **三方言后端**：SQLite / PostgreSQL / MySQL（经 `db` 包 Dialect 抽象）。
- **单实例权威**：v1 不做分布式一致。

> ✅ **现状**：内存引擎（`engine` 包）已按 `docs/zh/IMPLEMENTATION_PLAN.md` Phase A–F 实施完成（内存索引 / 写管道 / 启动重建 / janitor / 指标 / 单测与基准）。`db` / `recordbuffer` / `cache` / `engine` 四包全部可编译可测。Phase G（varwof-core 渐进迁移）待 varwof-core 仓库存在后执行。

## Project Structure

```
varwof-engine/
├── db/                    # SQL 后端层（从 core/internal/db 提取）
│   ├── db.go              # DB wrapper + 三方言 rebind/adapt + 连接池调优
│   ├── dialect.go         # Dialect 接口（SQLite/PG/MySQL）
│   ├── schema.go          # migration v1 (consolidated schema) + 方言占位符适配
│   ├── certs.go           # CertRecord 全字段 CRUD + 状态点查 + SPKI/principal/CRL
│   ├── batch.go           # BulkInsertCertRecords（999 变量分块；本机 TF 卡实测 ~2K/s，SSD 更高）
│   ├── renewal_tokens.go  # nonce Store/Consume/IsUsed（一次性防重放）
│   ├── aic.go             # AIC 扩展（ca,serial / principal / agent）
│   ├── sub_ca.go          # 子 CA
│   ├── trust_anchor.go    # 信任锚
│   ├── ca_meta.go / cross.go / ct.go / escrow.go / gateway_registry.go
│   ├── rbac.go / ra.go / webhook.go / scep.go / acme.go / audit_salt.go / transfer.go
│   ├── lock.go            # 分布式锁（PG advisory + 平台文件锁）
│   └── lock_file_unix.go
├── recordbuffer/          # 写管道（从 core/internal/serve/record_buffer.go 提取）
│   └── record_buffer.go   # WAL 预写日志 + 背压 + checkpoint + drain + FlushAll
├── cache/                 # 统一读缓存（从 ocsp/serve/cmd 提取合并）
│   └── cache.go           # TTL Cache + serial 关联 LRU（PurgeSerial）
├── engine/                # ✅ 内存引擎（已实施，见 docs）
│   ├── engine.go          # Engine 生命周期 + 后端写 worker + Metrics
│   ├── options.go         # EngineOptions 配置
│   ├── cert_index.go      # CertIndex 主/二级索引 + 时间窗口
│   ├── revoked_set.go     # RevokedSet（CRL 纯内存生成）
│   ├── nonce_set.go       # NonceSet（一次性 CAS）
│   ├── meta_index.go      # SubCA / Trust / AIC 索引
│   ├── reads.go / writes.go / load.go / janitor.go
│   ├── engine_test.go / engine_coverage_test.go / convergence_test.go
│   ├── engine_edge_test.go / revoked_set_test.go / engine_bench_test.go
├── docs/
│   ├── zh/                # 中文文档
│   │   ├── REQUIREMENTS.md
│   │   ├── IMPLEMENTATION_PLAN.md
│   │   ├── api.md
│   │   ├── config.md
│   │   ├── functions.md
│   │   ├── TESTING.md
│   │   └── NEXT_STEPS.md
│   ├── REQUIREMENTS.md    # 英文需求规格
│   ├── IMPLEMENTATION_PLAN.md  # 英文实施计划
│   ├── api.md             # 英文 Engine API 参考
│   ├── config.md          # 英文 EngineOptions 配置
│   ├── functions.md       # 英文函数索引
│   ├── TESTING.md         # 英文测试清单
│   └── NEXT_STEPS.md      # 英文剩余工作清单
└── README.md
```

## Quick Start

```bash
# 验证提取的现状实现
cd engine && go test -count=1 ./...

# 本地 CI（build+vet+test+race+覆盖率门禁，等价于 CI 工作流）
./scripts/ci.sh

# 本模块独立构建（无 go.work / replace，varwof-core 接入后在其仓库根建 go.work 挂载）
cd engine && go build ./...
```

## 设计要点

- 写路径：`IssueCert` → 内存索引原子更新（立即可见）→ `recordbuffer.Add`（批量落库，WAL 保护）。吊销由引擎内部先排空写管道再排队 `UPDATE`，上层不再需要手动 flush 约定。
- 并发安全：`IssueCert` 同键冲突判定与插入在索引锁内原子完成；批量吊销的状态变更在索引锁内进行，与并发点查无数据竞争，吊销集以单次排序合并（O(n log n)）；`recordbuffer` 的 `flush`/`FlushAll` 由内部互斥串行化，重叠 flush 不丢批次。
- 读路径：OCSP / 握手吊销 / nonce / CRL 全命中内存，无 SQL。
- 时间窗口：`CertIndex` 维护按 `not_after` 的有序窗口，过期证书 janitor 剪枝；janitor 同步清理后端 `renewal_tokens` 中过期的 nonce 行，避免表无限增长。
- 后端幂等落库：`INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` / `INSERT IGNORE`，启动全量重建收敛漂移。

## 基准

全部基准共 19 个，位于 `engine/engine_bench_test.go`、`recordbuffer/recordbuffer_bench_test.go`、`cache/cache_bench_test.go`。

```bash
# 单次全量基准（recordbuffer/cache/engine，~2-3 分钟）
./scripts/bench.sh

# 加 db 包（TF 卡上很慢）
./scripts/bench.sh all

# 单个基准（-benchmem 输出每次分配的字节/对象数）
go test ./engine/ -bench '^BenchmarkGetCertStatus$' -benchmem -run '^$'
```

关键基线（树莓派 4B / ARM64 实测）：

| 基准 | 指标 |
| --- | --- |
| `BenchmarkGetCertStatus` | 命中 ~303ns / 未命中 ~160ns，零 SQL |
| `BenchmarkIssueCertMemory` | 内存写 ~14µs/次（不含落库） |
| `BenchmarkRevokedSetPutAll` vs `Put` | n=1000 时 1.06ms vs 2.20ms（~2.1x，O(n log n) 批量路径） |
| `BenchmarkRevokedSetPruneExpired` | n=1000 ~1.3ms / n=10000 ~14.2ms |
| `BenchmarkGetRevokedCertEntries` | 1K 吊销集 CRL 遍历 ~4ms，纯内存 |
| `BenchmarkConsumeNonce` | ~1ms/次，受 SQLite 单写队列限流 |
| `BenchmarkRecordBufferAdd` | 无 WAL ~356ns、0 alloc |
| `BenchmarkRecordBufferAddWAL` | ~430µs/条（每 100 条 fsync 一次） |
| `BenchmarkCacheGetHit` | 命中 ~313ns，读锁路径（并行命中不串行） |
| `BenchmarkCacheSetAtCapacity` | 容量满逐出 ~880ns/次 |

## License

[GNU Affero General Public License v3.0](LICENSE)（AGPL-3.0）

---

## 文档

| 中文 | English |
|---|---|
| [API 参考](docs/zh/api.md) | [API Reference](docs/api.md) |
| [配置参考](docs/zh/config.md) | [Configuration](docs/config.md) |
| [函数索引](docs/zh/functions.md) | [Function Index](docs/functions.md) |
| [需求规格](docs/zh/REQUIREMENTS.md) | [Requirements](docs/REQUIREMENTS.md) |
| [实施计划](docs/zh/IMPLEMENTATION_PLAN.md) | [Implementation Plan](docs/IMPLEMENTATION_PLAN.md) |
| [测试记录](docs/zh/TESTING.md) | [Testing](docs/TESTING.md) |
| [剩余工作](docs/zh/NEXT_STEPS.md) | [Next Steps](docs/NEXT_STEPS.md) |
| [风险清单](docs/zh/RISKS.md) | [Risk Register](docs/RISKS.md) |
