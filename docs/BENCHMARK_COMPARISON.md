# Benchmark Comparison

Measured 2026-08-24, `-benchtime=300ms`, single run per package.

## Machines

| | Desktop (local) | Raspberry Pi 5 |
| --- | --- | --- |
| CPU | Intel Core Ultra 5 125H | BCM2712 (4 cores) |
| Architecture | x86_64 | aarch64 |
| RAM | — | 4 GB |
| OS | Linux 6.17.0-35-generic | Raspberry Pi OS bookworm, kernel 6.12.87+rpt-rpi-2712 |
| Go | 1.26.7 | 1.26.2 |

## Results

| Benchmark | Desktop | Pi 5 | Ratio (Pi/Desktop) |
| --- | --- | --- | --- |
| `BenchmarkGetCertStatus` (hit) | 230 ns/op | 118 ns/op | 0.51× |
| `BenchmarkGetCertStatus` (miss) | 45.5 ns/op | 58.2 ns/op | 1.28× |
| `BenchmarkIssueCertMemory` | 7.17 µs/op | 5.59 µs/op | 0.78× |
| `BenchmarkRevokedSetPut` n=1000 | 631 µs/op | 539 µs/op | 0.85× |
| `BenchmarkRevokedSetPutAll` n=1000 | 397 µs/op | 258 µs/op | 0.65× |
| `BenchmarkRevokedSetPruneExpired` n=1000 | 504 µs/op | 338 µs/op | 0.67× |
| `BenchmarkRevokedSetPruneExpired` n=10000 | 3.72 ms/op | 5.20 ms/op | 1.40× |
| `BenchmarkGetRevokedCertEntries` | 860 µs/op | 1.52 ms/op | 1.77× |
| `BenchmarkConsumeNonce` | 627 ns/op | 269 ns/op | 0.43× |
| `BenchmarkRecordBufferAdd` (no WAL) | 410 ns/op | 155 ns/op | 0.38× |
| `BenchmarkRecordBufferAddWAL` | 17.7 µs/op | 44.5 µs/op | 2.51× |
| `BenchmarkCacheGetHit` | 212 ns/op | 98.0 ns/op | 0.46× |
| `BenchmarkCacheSetAtCapacity` | 336 ns/op | 439 ns/op | 1.31× |

Ratio < 1 means the Pi 5 is faster than the desktop.

## Notes

- Pi 5 is faster on most pure-memory paths (record buffer, cache hits, nonce
  consume, cert-status hit) — its high clock speed beats the desktop's
  low-power mobile CPU on latency-sensitive single-threaded work.
- Desktop wins on disk-backed paths: `RecordBufferAddWAL` (fsync) and the
  large `PruneExpired` n=10000 (SD card vs SSD), plus the alloc-heavy
  `GetRevokedCertEntries` traversal.
- `PutAll` vs `Put` batch gain holds on both machines
  (Pi 5 n=1000: 0.26ms vs 0.54ms, ~2.1×).
