# Testing Record (TESTING)

> Per-package test lists, coverage, concurrency/Fuzz tests, and run conventions. Coverage figures change with implementation; update after re-runs.

## Coverage (measured 2026-08-24, Intel Core Ultra 5 125H desktop / x86_64)

| Package | Coverage |
|---|---|
| cache | 99.1% |
| engine | 97.0% |
| db | 83.5% (86.5% with `-tags postgres` real-DB cases) |
| recordbuffer | 81.6% |
| **Total** | **~87.3%** |

Reproduce:
```bash
go test ./cache/ -cover -count=1
go test ./engine/ -cover -count=1
go test ./db/ -cover -count=1          # local ~10s
go test ./recordbuffer/ -cover -count=1

# With PostgreSQL real-DB branch (local PG 15, see NEXT_STEPS)
PG_TEST_DSN="postgres://varwof:$PG_PASSWORD@localhost:5432/pki?sslmode=disable" \
  go test -tags postgres -cover -count=1 ./db/

# With MariaDB real-DB branch (local system MariaDB on 3306, see NEXT_STEPS)
MYSQL_TEST_DSN="varwof:$MYSQL_PASSWORD@tcp(127.0.0.1:3306)/pki_mysql?charset=utf8mb4&parseTime=true" \
  go test -tags mysql -cover -count=1 ./db/
```

> Note: `go test -race` runs clean locally and in CI (`.github/workflows/ci.yml` runs `-race`).

## Test File Inventory

### engine (16 test files)
- `engine_test.go` — Core CRUD / time window / nonce CAS / rebuild
- `engine_coverage_test.go` — Branch supplements
- `convergence_test.go` — In-memory authority + backend ordered convergence, full-state rebuild
- `engine_edge_test.go` — Boundary/error paths (added 2026-08-10, 20 cases)
- `revoked_set_test.go` — RevokedSet dedicated
- `crash_recovery_test.go` — WAL replay + memory index rebuild after crash
- `da_nonces_test.go` — DA nonce store/consume + WAL crash safety
- `budget_metrics_test.go` — Memory budget + metrics verification
- `risk_fix_test.go` — Regression tests for resolved risks
- `sharded_writer_test.go` — Write-pipeline sharding behavior
- `paging_janitor_test.go` — Paged janitor eviction
- `engine_bench_test.go` — 8 benchmarks
- `aic_sim_bench_test.go` / `evict_bench_test.go` / `multica_bench_test.go` / `scale_bench_test.go` — scale/multi-CA/eviction benchmarks

### db (33 test files)
- `db_test.go` / `batch_test.go` / `renewal_tokens_test.go` / `db_fuzz_test.go` etc. native cases
- `db_coverage_*_test.go` / `db_aic_coverage_test.go` / `db_notify_coverage_test.go` / `db_transfer_coverage_test.go` / `db_lock_coverage_test.go` — coverage supplements (including 2026-08-10 transfer/lock cases)
- `lock_test.go` / `lock_file_unix_test.go` / `pg_test.go` / `pg_extra_test.go` — distributed lock and PG real-DB cases (`-tags postgres` + `PG_TEST_DSN`)
- `create_mysql_test.go` / `create_pg_test.go` / `create_test.go` — `CreateDatabaseIfNotExists` per-dialect
- `crl_number_test.go` / `da_nonces_test.go` / `bulk_revoke_test.go` / `audit_salt_test.go` / `webhook_test.go` / `rbac_test.go` / `ra_test.go` / `gateway_registry_test.go` / `escrow_test.go` / `cross_test.go` / `ct_test.go` / `sub_ca_test.go` / `ca_meta_test.go` / `acme_test.go` — per-module CRUD
- `mysql_extra_test.go` — MariaDB real-DB cases (`-tags mysql` + `MYSQL_TEST_DSN`, test DB rebuilt idempotently each run)

### recordbuffer (4 test files)
- `record_buffer_test.go` — Pipeline/WAL/backpressure/checkpoint
- `recordbuffer_danonce_test.go` — DA nonce WAL path
- `recordbuffer_bench_test.go` — 3 benchmarks
- `recordbuffer_fuzz_test.go` — WAL line parser fuzz

### cache (2 test files)
- `cache_test.go` — TTL + serial-associated LRU
- `cache_bench_test.go` — 8 benchmarks

## Concurrency Tests (run in CI with `-race`)

`go test -race` runs clean locally and in CI (`.github/workflows/ci.yml`). Key concurrency tests:
- engine: `TestIssueCertConcurrentSameKey` (same-key issue/revoke), `TestConcurrentReadsDuringBulkRevoke` (reads during bulk revoke), `TestRevokeCertsBatchConcurrent` (concurrent batch revoke), `TestConsumeNonce_Concurrent` (nonce CAS concurrency)
- cache: `TestCacheConcurrent`, `TestLRUConcurrent`
- db: `TestNoopLockConcurrent`, `TestFileLockBlocksConcurrentProcess` (file lock contention); PG advisory lock under `-tags postgres`

## Fuzz Tests

3 fuzz targets, seed corpus included with test files:

| Fuzz | Coverage |
|---|---|
| `FuzzParseWALLines` (recordbuffer) | WAL line parsing: no panic / length consistency |
| `FuzzRebindAndAdapt` (db) | 3-way dialect rebind: no panic |
| `FuzzBulkInsertSQL` (db) | Bulk SQL chunking: no out-of-bounds |

Run convention: **always run full package tests before fuzzing** and **always add `-run='^$'`**:
```bash
go test ./db/ -count=1 && go test ./db/ -run '^$' -fuzz FuzzBulkInsertSQL -fuzztime=30s
go test ./recordbuffer/ -count=1 && go test ./recordbuffer/ -run '^$' -fuzz FuzzParseWALLines -fuzztime=30s
```

## Regression Command

```bash
go build ./... && go vet ./... && go test -count=1 ./...
```
