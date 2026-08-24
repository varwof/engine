# 测试记录（TESTING）

> 各包测试清单、覆盖率、并发/Fuzz 测试与运行约定。覆盖率数字随实现变化，重跑后更新。

## 覆盖率（2026-08-10 实测，树莓派 4B / ARM64）

| 包 | 覆盖率 |
|---|---|
| cache | 99.1% |
| engine | 99.0% |
| db | 86.5%（含 `-tags postgres` 真库用例） |
| recordbuffer | 90.7% |
| **合计** | **~89.6%** |

复现：
```bash
go test ./cache/ -cover -count=1
go test ./engine/ -cover -count=1
go test ./db/ -cover -count=1          # 本机 TF 卡 ~75s
go test ./recordbuffer/ -cover -count=1

# 含 PostgreSQL 真库分支（本机 PG 15，见 NEXT_STEPS）
PG_TEST_DSN="postgres://varwof:$PG_PASSWORD@localhost:5432/pki?sslmode=disable" \
  go test -tags postgres -cover -count=1 ./db/

# 含 MariaDB 真库分支（隔离实例 127.0.0.1:3307，见 NEXT_STEPS）
MYSQL_TEST_DSN="varwof:$MYSQL_PASSWORD@tcp(127.0.0.1:3307)/pki_mysql?charset=utf8mb4&parseTime=true" \
  go test -tags mysql -cover -count=1 ./db/
```

## 测试文件清单

### engine（5 个测试文件）
- `engine_test.go` — 核心 CRUD / 时间窗口 / nonce CAS / 重建
- `engine_coverage_test.go` — 分支补充
- `convergence_test.go` — 内存权威 + 后端有序收敛、全状态重建
- `engine_edge_test.go` — 边界/错误路径（2026-08-10 新增，21 个用例）
- `revoked_set_test.go` — RevokedSet 专用
- `engine_bench_test.go` — 8 个基准

### db（22 个测试文件）
- `db_test.go` / `batch_test.go` / `renewal_tokens_test.go` / `db_fuzz_test.go` 等原生用例
- `db_coverage_*_test.go` / `db_aic_coverage_test.go` / `db_notify_coverage_test.go` / `db_transfer_coverage_test.go` / `db_lock_coverage_test.go` — 覆盖率补充（含 2026-08-10 新增 transfer/lock 用例）
- `lock_test.go` / `lock_file_unix_test.go` / `pg_test.go` / `pg_extra_test.go` — 分布式锁与 PG 真库用例（`-tags postgres` + `PG_TEST_DSN`）
- `mysql_extra_test.go` — MariaDB 真库用例（`-tags mysql` + `MYSQL_TEST_DSN`，测试库每次重建幂等）

### recordbuffer（3 个测试文件）
- `record_buffer_test.go` — 管道/WAL/背压/checkpoint
- `recordbuffer_bench_test.go` — 3 个基准
- `recordbuffer_fuzz_test.go` — WAL 行解析 fuzz

### cache（2 个测试文件）
- `cache_test.go` — TTL + serial 关联 LRU
- `cache_bench_test.go` — 8 个基准

## 并发测试（应纳入 CI `-race`）

本机内核 ASLR 限制导致 `-race` 不可用（TSan `unsupported VMA range`），以下用例已就绪，CI 应跑：
- engine：`TestEngineConcurrent`（并发签发/吊销/读）、`TestConsumeNonceConcurrent`（nonce CAS 并发）
- cache：`TestCacheConcurrent`、`TestLRUConcurrent`
- db：`TestPGLockConcurrent`（PG）、文件锁竞争

## Fuzz 测试

3 个 fuzz 目标，seed corpus 已随测试文件入库：

| Fuzz | 覆盖 |
|---|---|
| `FuzzParseWALLines`（recordbuffer） | WAL 行解析不 panic / 长度一致 |
| `FuzzRebindAndAdapt`（db） | 三方言 rebind 不 panic |
| `FuzzBulkInsertSQL`（db） | 批量 SQL 分块不越界 |

运行约定：**必须先跑完整包测试再 fuzz**（db 包本机 ~60-90s，曾致 120s 超时），并**必须加 `-run='^$'`**：
```bash
go test ./db/ -count=1 && go test ./db/ -run '^$' -fuzz FuzzBulkInsertSQL -fuzztime=30s
go test ./recordbuffer/ -count=1 && go test ./recordbuffer/ -run '^$' -fuzz FuzzParseWALLines -fuzztime=30s
```

## 回归命令

```bash
cd engine && go build ./... && go vet ./... && go test -count=1 ./...
```
