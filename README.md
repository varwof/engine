# varwof-engine

An in-memory-centric high-speed data subsystem for varwof-core, providing resident-memory queries and batch persistence for OCSP / CRL / nonce / certificate status.

[中文](README.zh.md)

## Overview

- **Memory is truth**: all high-frequency reads/writes hit in-memory indexes, zero SQL for reads, writes go to memory first then persist asynchronously.
- **Batch persistence**: inherits varwof-core RecordBuffer mechanism (WAL crash safety / backpressure / checkpoint / FlushAll).
- **Time-window optimization**: OCSP/CRL pruned by certificate validity window, expired certs evicted from hot memory.
- **3-way dialect backend**: SQLite / PostgreSQL / MySQL (abstracted via `db` package Dialect).
- **Single-instance authority**: v1 does not do distributed consensus.

> ✅ **Status**: the in-memory engine (`engine` package) is fully implemented per `docs/IMPLEMENTATION_PLAN.md` Phase A–F (in-memory indexes / write pipeline / startup rebuild / janitor / metrics / unit tests & benchmarks). All four packages (`db` / `recordbuffer` / `cache` / `engine`) compile and pass tests. Phase G (varwof-core gradual migration) pending varwof-core integration.

## Project Structure

```
engine/
├── db/                    # SQL backend (extracted from core/internal/db)
│   ├── db.go              # DB wrapper + 3-way dialect rebind/adapt + connection pool tuning
│   ├── dialect.go         # Dialect interface (SQLite/PG/MySQL)
│   ├── schema.go          # migration v1 (consolidated schema) + dialect placeholder adaptation
│   ├── certs.go           # CertRecord full-field CRUD + status lookup + SPKI/principal/CRL
│   ├── batch.go           # BulkInsertCertRecords (999-variable chunking; ~2K/s on SD card, higher on SSD)
│   ├── renewal_tokens.go  # nonce Store/Consume/IsUsed (one-time anti-replay)
│   ├── aic.go             # AIC extensions (ca,serial / principal / agent)
│   ├── sub_ca.go          # Sub-CA
│   ├── trust_anchor.go    # Trust anchor
│   ├── ca_meta.go / cross.go / ct.go / escrow.go / gateway_registry.go
│   ├── rbac.go / ra.go / webhook.go / scep.go / acme.go / audit_salt.go / transfer.go
│   ├── lock.go            # Distributed lock (PG advisory + platform file lock)
│   ├── lock_file_unix.go
│   ├── create.go          # CreateDatabaseIfNotExists (per-dialect)
│   ├── crl_number.go / da_nonces.go / bulk_revoke.go
│   └── ... (33 test files)
├── recordbuffer/          # Write pipeline (extracted from core/internal/serve/record_buffer.go)
│   └── record_buffer.go   # WAL pre-write log + backpressure + checkpoint + drain + FlushAll
├── cache/                 # Unified read cache (extracted from ocsp/serve/cmd)
│   └── cache.go           # TTL Cache + serial-associated LRU (PurgeSerial)
├── engine/                # ✅ In-memory engine (implemented, see docs)
│   ├── engine.go          # Engine lifecycle + backend write worker + Metrics
│   ├── options.go         # EngineOptions configuration
│   ├── cert_index.go      # CertIndex primary/secondary indexes + time window
│   ├── revoked_set.go     # RevokedSet (CRL pure in-memory generation)
│   ├── nonce_set.go       # NonceSet (one-time CAS)
│   ├── meta_index.go      # SubCA / Trust / AIC indexes
│   ├── reads.go / writes.go / load.go / janitor.go
│   └── ... (16 test files incl. bench/scale/fuzz)
├── docs/
│   ├── zh/                # 中文文档
│   │   ├── REQUIREMENTS.md
│   │   ├── IMPLEMENTATION_PLAN.md
│   │   ├── api.md
│   │   ├── config.md
│   │   ├── functions.md
│   │   ├── TESTING.md
│   │   └── NEXT_STEPS.md
│   ├── REQUIREMENTS.md    # Requirements specification
│   ├── IMPLEMENTATION_PLAN.md  # Implementation plan
│   ├── api.md             # Engine API reference
│   ├── config.md          # EngineOptions configuration
│   ├── functions.md       # Function index
│   ├── TESTING.md         # Test inventory / coverage / concurrency & fuzz conventions
│   ├── NEXT_STEPS.md      # Remaining work (blocked items / uncovered branches / candidate optimizations)
│   └── BENCHMARK_COMPARISON.md  # 3-machine benchmark comparison (desktop / Pi 5 / PN41)
└── README.md
```

## Quick Start

```bash
# Verify the extracted implementation
go test -count=1 ./...

# CI runs automatically on every push/PR via GitHub Actions
# (build / vet / race tests / coverage gate >=85% / real PostgreSQL & MariaDB integration)

# Standalone build (no go.work / replace; mount via go.work in varwof-core repo root after integration)
go build ./...
```

## Design Highlights

- **Write path**: `IssueCert` → atomic in-memory index update (immediately visible) → `recordbuffer.Add` (batch persistence, WAL-protected). Revocation internally flushes the write pipeline before queuing `UPDATE`; callers no longer need manual flush conventions.
- **Concurrency safe**: `IssueCert` conflict detection and insertion happen atomically under the index lock; bulk revocation state changes also occur under the index lock with no data races against concurrent point queries; revoked sets merge via single-sort (O(n log n)); `recordbuffer`'s `flush`/`FlushAll` serialized internally by mutex — overlapping flushes do not lose batches.
- **Read path**: OCSP / handshake revocation / nonce / CRL all hit memory, zero SQL.
- **Time window**: `CertIndex` maintains a sorted window by `not_after`, expired certificates pruned by janitor; janitor also cleans expired nonce rows from backend `renewal_tokens`, preventing unbounded table growth.
- **Idempotent backend persistence**: `INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` / `INSERT IGNORE`; startup full rebuild converges drift.

## Benchmarks

34 benchmarks total across `engine/` (including `engine_bench_test.go`, `aic_sim_bench_test.go`, `evict_bench_test.go`, `multica_bench_test.go`, `scale_bench_test.go`), `recordbuffer/recordbuffer_bench_test.go`, `cache/cache_bench_test.go`.

```bash
# Full benchmark run (recordbuffer/cache/engine, ~2-3 minutes)
go test ./recordbuffer/ ./cache/ ./engine/ -bench . -benchmem -benchtime=300ms -run '^$'

# Include db package (slow)
go test ./db/ -bench . -benchmem -benchtime=300ms -run '^$'

# Single benchmark (-benchmem outputs bytes/allocs per op)
go test ./engine/ -bench '^BenchmarkGetCertStatus$' -benchmem -run '^$'
```

Key baselines (Intel Core Ultra 5 125H / x86_64 / Go 1.26.7, `-benchtime=300ms`):

| Benchmark | Metric |
| --- | --- |
| `BenchmarkGetCertStatus` | Hit ~230ns / miss ~45ns, zero SQL |
| `BenchmarkIssueCertMemory` | Memory write ~7.2µs/op (excludes persistence) |
| `BenchmarkRevokedSetPutAll` vs `Put` | n=1000: 0.40ms vs 0.63ms (~1.6×, O(n log n) batch path) |
| `BenchmarkRevokedSetPruneExpired` | n=1000 ~0.50ms / n=10000 ~3.7ms |
| `BenchmarkGetRevokedCertEntries` | 1K revoked set CRL traversal ~0.86ms, pure memory |
| `BenchmarkConsumeNonce` | ~0.63µs/op, in-memory consume; DB write enqueued async |
| `BenchmarkRecordBufferAdd` | No WAL ~410ns, 0 allocs |
| `BenchmarkRecordBufferAddWAL` | ~18µs/op (fsync every 100 records) |
| `BenchmarkCacheGetHit` | Hit ~212ns, read-lock path (parallel hits don't serialize) |
| `BenchmarkCacheSetAtCapacity` | Capacity-full eviction ~336ns/op |

See [docs/BENCHMARK_COMPARISON.md](docs/BENCHMARK_COMPARISON.md) for a 3-machine comparison (desktop / Raspberry Pi 5 / PN41).

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0)

---

## Documentation

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
