# Testing Record (TESTING)

> Per-package test lists, coverage, concurrency/Fuzz tests, and run conventions. Coverage figures change with implementation; update after re-runs.

## Coverage (2026-08-10, Raspberry Pi 4B / ARM64)

| Package | Coverage |
|---|---|
| cache | 99.1% |
| engine | 99.0% |
| db | 86.5% (with `-tags postgres` real-DB cases) |
| recordbuffer | 90.7% |
| **Total** | **~89.6%** |

Reproduce:
```bash
go test ./cache/ -cover -count=1
go test ./engine/ -cover -count=1
go test ./db/ -cover -count=1          # local TF card ~75s
go test ./recordbuffer/ -cover -count=1

# With PostgreSQL real-DB branch (local PG 15, see NEXT_STEPS)
PG_TEST_DSN="postgres://varwof:$PASSWORD@localhost:5432/pki?sslmode=disable" \
  go test -tags postgres -cover -count=1 ./db/

# With MariaDB real-DB branch (local system MariaDB on 3306, see NEXT_STEPS)
MYSQL_TEST_DSN="varwof:$PASSWORD@tcp(127.0.0.1:3306)/pki_mysql?charset=utf8mb4&parseTime=true" \
  go test -tags mysql -cover -count=1 ./db/
```

## Test File Inventory

### engine (5 test files)
- `engine_test.go` — Core CRUD / time window / nonce CAS / rebuild
- `engine_coverage_test.go` — Branch supplements
- `convergence_test.go` — In-memory authority + backend ordered convergence, full-state rebuild
- `engine_edge_test.go` — Boundary/error paths (added 2026-08-10, 21 cases)
- `revoked_set_test.go` — RevokedSet dedicated
- `engine_bench_test.go` — 8 benchmarks

### db (22 test files)
- `db_test.go` / `batch_test.go` / `renewal_tokens_test.go` / `db_fuzz_test.go` etc. native cases
- `db_coverage_*_test.go` / `db_aic_coverage_test.go` / `db_notify_coverage_test.go` / `db_transfer_coverage_test.go` / `db_lock_coverage_test.go` — coverage supplements (including 2026-08-10 transfer/lock cases)
- `lock_test.go` / `lock_file_unix_test.go` / `pg_test.go` / `pg_extra_test.go` — distributed lock and PG real-DB cases (`-tags postgres` + `PG_TEST_DSN`)
- `mysql_extra_test.go` — MariaDB real-DB cases (`-tags mysql` + `MYSQL_TEST_DSN`, test DB rebuilt idempotently each run)

### recordbuffer (3 test files)
- `record_buffer_test.go` — Pipeline/WAL/backpressure/checkpoint
- `recordbuffer_bench_test.go` — 3 benchmarks
- `recordbuffer_fuzz_test.go` — WAL line parser fuzz

### cache (2 test files)
- `cache_test.go` — TTL + serial-associated LRU
- `cache_bench_test.go` — 8 benchmarks

## Concurrency Tests (should be run in CI with `-race`)

Local kernel ASLR restriction prevents `-race` from working (TSan `unsupported VMA range`); the following tests are ready and CI should run them:
- engine: `TestEngineConcurrent` (concurrent issue/revoke/read), `TestConsumeNonceConcurrent` (nonce CAS concurrency)
- cache: `TestCacheConcurrent`, `TestLRUConcurrent`
- db: `TestPGLockConcurrent` (PG), file lock contention

## Fuzz Tests

3 fuzz targets, seed corpus included with test files:

| Fuzz | Coverage |
|---|---|
| `FuzzParseWALLines` (recordbuffer) | WAL line parsing: no panic / length consistency |
| `FuzzRebindAndAdapt` (db) | 3-way dialect rebind: no panic |
| `FuzzBulkInsertSQL` (db) | Bulk SQL chunking: no out-of-bounds |

Run convention: **always run full package tests before fuzzing** (db package ~60-90s locally, has caused 120s timeout), and **always add `-run='^$'`**:
```bash
go test ./db/ -count=1 && go test ./db/ -run '^$' -fuzz FuzzBulkInsertSQL -fuzztime=30s
go test ./recordbuffer/ -count=1 && go test ./recordbuffer/ -run '^$' -fuzz FuzzParseWALLines -fuzztime=30s
```

## Regression Command

```bash
cd engine && go build ./... && go vet ./... && go test -count=1 ./...
```
