# 测试记录（TESTING）

> 各包测试清单、覆盖率、并发/Fuzz 测试与运行约定。覆盖率数字随实现变化，重跑后更新。

## 覆盖率（2026-08-24 实测，Intel Core Ultra 5 125H 桌面机 / x86_64）

| 包 | 覆盖率 |
|---|---|
| cache | 99.1% |
| engine | 97.0% |
| db | 83.5%（含 `-tags postgres` 真库用例为 86.5%） |
| recordbuffer | 81.6% |
| **合计** | **~87.3%** |

复现：
```bash
go test ./cache/ -cover -count=1
go test ./engine/ -cover -count=1
go test ./db/ -cover -count=1          # 本机 ~10s
go test ./recordbuffer/ -cover -count=1

# 含 PostgreSQL 真库分支（本机 PG 15，见 NEXT_STEPS）
PG_TEST_DSN="postgres://varwof:$PG_PASSWORD@localhost:5432/pki?sslmode=disable" \
  go test -tags postgres -cover -count=1 ./db/

# 含 MariaDB 真库分支（本机系统实例 127.0.0.1:3306，见 NEXT_STEPS）
MYSQL_TEST_DSN="varwof:$MYSQL_PASSWORD@tcp(127.0.0.1:3306)/pki_mysql?charset=utf8mb4&parseTime=true" \
  go test -tags mysql -cover -count=1 ./db/
```

> 注：`go test -race` 在本地与 CI（`.github/workflows/ci.yml`）均可正常运行。

## 测试文件清单

### engine（16 个测试文件）
- `engine_test.go` — 核心 CRUD / 时间窗口 / nonce CAS / 重建
- `engine_coverage_test.go` — 分支补充
- `convergence_test.go` — 内存权威 + 后端有序收敛、全状态重建
- `engine_edge_test.go` — 边界/错误路径（2026-08-10 新增，20 个用例）
- `revoked_set_test.go` — RevokedSet 专用
- `crash_recovery_test.go` — 崩溃后 WAL 回放 + 内存索引重建
- `da_nonces_test.go` — DA nonce 存储/消费 + WAL 崩溃安全
- `budget_metrics_test.go` — 内存预算 + 指标校验
- `risk_fix_test.go` — 已解决风险项的回归测试
- `sharded_writer_test.go` — 写管道分片行为
- `paging_janitor_test.go` — 分页 janitor 逐出
- `engine_bench_test.go` — 8 个基准
- `aic_sim_bench_test.go` / `evict_bench_test.go` / `multica_bench_test.go` / `scale_bench_test.go` — 规模/多 CA/逐出基准

### db（33 个测试文件）
- `db_test.go` / `batch_test.go` / `renewal_tokens_test.go` / `db_fuzz_test.go` 等原生用例
- `db_coverage_*_test.go` / `db_aic_coverage_test.go` / `db_notify_coverage_test.go` / `db_transfer_coverage_test.go` / `db_lock_coverage_test.go` — 覆盖率补充（含 2026-08-10 新增 transfer/lock 用例）
- `lock_test.go` / `lock_file_unix_test.go` / `pg_test.go` / `pg_extra_test.go` — 分布式锁与 PG 真库用例（`-tags postgres` + `PG_TEST_DSN`）
- `create_mysql_test.go` / `create_pg_test.go` / `create_test.go` — `CreateDatabaseIfNotExists` 各方言
- `crl_number_test.go` / `da_nonces_test.go` / `bulk_revoke_test.go` / `audit_salt_test.go` / `webhook_test.go` / `rbac_test.go` / `ra_test.go` / `gateway_registry_test.go` / `escrow_test.go` / `cross_test.go` / `ct_test.go` / `sub_ca_test.go` / `ca_meta_test.go` / `acme_test.go` — 各模块 CRUD
- `mysql_extra_test.go` — MariaDB 真库用例（`-tags mysql` + `MYSQL_TEST_DSN`，测试库每次重建幂等）

### recordbuffer（4 个测试文件）
- `record_buffer_test.go` — 管道/WAL/背压/checkpoint
- `recordbuffer_danonce_test.go` — DA nonce WAL 路径
- `recordbuffer_bench_test.go` — 3 个基准
- `recordbuffer_fuzz_test.go` — WAL 行解析 fuzz

### cache（2 个测试文件）
- `cache_test.go` — TTL + serial 关联 LRU
- `cache_bench_test.go` — 8 个基准

## 并发测试（CI 中以 `-race` 运行）

`go test -race` 在本地与 CI（`.github/workflows/ci.yml`）均正常。关键并发用例：
- engine：`TestIssueCertConcurrentSameKey`（同键并发签发/吊销）、`TestConcurrentReadsDuringBulkRevoke`（批量吊销期间并发读）、`TestRevokeCertsBatchConcurrent`（并发批量吊销）、`TestConsumeNonce_Concurrent`（nonce CAS 并发）
- cache：`TestCacheConcurrent`、`TestLRUConcurrent`
- db：`TestNoopLockConcurrent`、`TestFileLockBlocksConcurrentProcess`（文件锁竞争）；PG advisory lock 见 `-tags postgres`

## Fuzz 测试

3 个 fuzz 目标，seed corpus 已随测试文件入库：

| Fuzz | 覆盖 |
|---|---|
| `FuzzParseWALLines`（recordbuffer） | WAL 行解析不 panic / 长度一致 |
| `FuzzRebindAndAdapt`（db） | 三方言 rebind 不 panic |
| `FuzzBulkInsertSQL`（db） | 批量 SQL 分块不越界 |

运行约定：**必须先跑完整包测试再 fuzz**，并**必须加 `-run='^$'`**：
```bash
go test ./db/ -count=1 && go test ./db/ -run '^$' -fuzz FuzzBulkInsertSQL -fuzztime=30s
go test ./recordbuffer/ -count=1 && go test ./recordbuffer/ -run '^$' -fuzz FuzzParseWALLines -fuzztime=30s
```

## 回归命令

```bash
go build ./... && go vet ./... && go test -count=1 ./...
```
