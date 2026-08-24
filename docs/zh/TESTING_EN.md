# Testing Records (TESTING)

> Per-package test inventory, coverage, concurrency/fuzz tests, and run conventions. Coverage numbers change with the implementation; refresh after reruns.

## Coverage (measured 2026-08-10, Raspberry Pi 4B / ARM64)

| Package | Coverage |
|---|---|
| cache | 99.1% |
| engine | 99.0% |
| db | 86.5% (incl. `-tags postgres` real-database cases) |
| recordbuffer | 90.7% |
| **Total** | **~89.6%** |

Reproduce:
```bash
go test ./cache/ -cover -count=1
go test ./engine/ -cover -count=1
go test ./db/ -cover -count=1          # ~75s on local TF card
go test ./recordbuffer/ -cover -count=1

# Including PostgreSQL real-database branches (local PG 15, see NEXT_STEPS)
PG_TEST_DSN="postgres://varwof:$PG_PASSWORD@localhost:5432/pki?sslmode=disable" \
  go test -tags postgres -cover -count=1 ./db/

# Including MariaDB real-database branches (isolated instance 127.0.0.1:3307, see NEXT_STEPS)
MYSQL_TEST_DSN="varwof:$MYSQL_PASSWORD@tcp(127.0.0.1:3307)/pki_mysql?charset=utf8mb4&parseTime=true" \
  go test -tags mysql -cover -count=1 ./db/
```

## Test File Inventory

### engine (5 test files)
- `engine_test.go` — core CRUD / time window / nonce CAS / rebuild
- `engine_coverage_test.go` — branch supplements
- `convergence_test.go` — memory-authoritative + ordered backend convergence, full-state rebuild
- `engine_edge_test.go` — boundary/error paths (added 2026-08-10, 21 cases)
- `revoked_set_test.go` — RevokedSet-specific
- `engine_bench_test.go` — 8 benchmarks

### db (22 test files)
- `db_test.go` / `batch_test.go` / `renewal_tokens_test.go` / `db_fuzz_test.go` and other native cases
- `db_coverage_*_test.go` / `db_aic_coverage_test.go` / `db_notify_coverage_test.go` / `db_transfer_coverage_test.go` / `db_lock_coverage_test.go` — coverage supplements (incl. transfer/lock cases added 2026-08-10)
- `lock_test.go` / `lock_file_unix_test.go` / `pg_test.go` / `pg_extra_test.go` — distributed lock + PG real-database cases (`-tags postgres` + `PG_TEST_DSN`)
- `mysql_extra_test.go` — MariaDB real-database cases (`-tags mysql` + `MYSQL_TEST_DSN`, test database rebuilt idempotently each run)

### recordbuffer (3 test files)
- `record_buffer_test.go` — pipeline/WAL/backpressure/checkpoint
- `recordbuffer_bench_test.go` — 3 benchmarks
- `recordbuffer_fuzz_test.go` — WAL line parsing fuzz

### cache (2 test files)
- `cache_test.go` — TTL + serial-associated LRU
- `cache_bench_test.go` — 8 benchmarks

## Concurrency Tests (should run in CI with `-race`)

Local kernel ASLR restrictions make `-race` unavailable (TSan `unsupported VMA range`); the following cases are ready and CI should run them:
- engine: `TestEngineConcurrent` (concurrent issue/revoke/read), `TestConsumeNonceConcurrent` (nonce CAS concurrency)
- cache: `TestCacheConcurrent`, `TestLRUConcurrent`
- db: `TestPGLockConcurrent` (PG), file-lock contention

## Fuzz Tests

3 fuzz targets; seed corpora committed with the test files:

| Fuzz | Covers |
|---|---|
| `FuzzParseWALLines` (recordbuffer) | WAL line parsing doesn't panic / length consistency |
| `FuzzRebindAndAdapt` (db) | Three-dialect rebind doesn't panic |
| `FuzzBulkInsertSQL` (db) | Bulk SQL chunking stays in bounds |

Run convention: **must run full package tests before fuzzing** (the db package takes ~60-90s locally, once causing a 120s timeout), and **must add `-run='^$'`**:
```bash
go test ./db/ -count=1 && go test ./db/ -run '^$' -fuzz FuzzBulkInsertSQL -fuzztime=30s
go test ./recordbuffer/ -count=1 && go test ./recordbuffer/ -run '^$' -fuzz FuzzParseWALLines -fuzztime=30s
```

## Regression Commands

```bash
cd engine && go build ./... && go vet ./... && go test -count=1 ./...
```
