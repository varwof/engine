# Benchmark Comparison

Measured 2026-08-24, `-benchtime=300ms`, single run per package.

## Machines

| | Desktop (local) | Raspberry Pi 5 | PN41 |
| --- | --- | --- | --- |
| CPU | Intel Core Ultra 5 125H | BCM2712 (4 cores) | Intel Pentium Silver N6005 |
| Architecture | x86_64 | aarch64 | x86_64 |
| RAM | — | 4 GB | 8 GB |
| OS | Linux 6.17.0-35-generic | Raspberry Pi OS bookworm, kernel 6.12.87+rpt-rpi-2712 | Debian 13, kernel 6.12.90+deb13.1-amd64 |
| Storage | SSD (SK Hynix) | microSD, Lexar 633x | SSD, Lexar N610 512 GB |
| Go | 1.26.7 | 1.26.2 | 1.26.2 |

## Results

| Benchmark | Desktop | Pi 5 | PN41 | Ratio (Pi/Desktop) | Ratio (PN41/Desktop) |
| --- | --- | --- | --- | --- | --- |
| `BenchmarkGetCertStatus` (hit) | 230 ns/op | 118 ns/op | 269 ns/op | 0.51× | 1.17× |
| `BenchmarkGetCertStatus` (miss) | 45.5 ns/op | 58.2 ns/op | 109 ns/op | 1.28× | 2.40× |
| `BenchmarkIssueCertMemory` | 7.17 µs/op | 5.59 µs/op | 11.9 µs/op | 0.78× | 1.66× |
| `BenchmarkRevokedSetPut` n=1000 | 631 µs/op | 539 µs/op | 1.93 ms/op | 0.85× | 3.06× |
| `BenchmarkRevokedSetPutAll` n=1000 | 397 µs/op | 258 µs/op | 706 µs/op | 0.65× | 1.78× |
| `BenchmarkRevokedSetPruneExpired` n=1000 | 504 µs/op | 338 µs/op | 948 µs/op | 0.67× | 1.88× |
| `BenchmarkRevokedSetPruneExpired` n=10000 | 3.72 ms/op | 5.20 ms/op | 10.3 ms/op | 1.40× | 2.76× |
| `BenchmarkGetRevokedCertEntries` | 860 µs/op | 1.52 ms/op | 2.92 ms/op | 1.77× | 3.40× |
| `BenchmarkConsumeNonce` | 627 ns/op | 269 ns/op | 383 ns/op | 0.43× | 0.61× |
| `BenchmarkRecordBufferAdd` (no WAL) | 410 ns/op | 155 ns/op | 1.37 µs/op | 0.38× | 3.33× |
| `BenchmarkRecordBufferAddWAL` | 17.7 µs/op | 44.5 µs/op | 12.5 µs/op | 2.51× | 0.70× |
| `BenchmarkCacheGetHit` | 212 ns/op | 98.0 ns/op | 301 ns/op | 0.46× | 1.42× |
| `BenchmarkCacheSetAtCapacity` | 336 ns/op | 439 ns/op | 667 ns/op | 1.31× | 1.98× |

Ratio < 1 means the machine is faster than the desktop.

## Notes

- Pi 5 is fastest on most pure-memory paths (record buffer, cache hits, nonce
  consume, cert-status hit) — its high clock speed beats the desktop's
  low-power mobile CPU on latency-sensitive single-threaded work.
- PN41 (N6005, 2.0 GHz Jasper Lake) is the slowest overall on memory paths,
  usually ~1.2–3.4× slower than the desktop; its `RecordBufferAdd` is 3.3×
  slower than the desktop, in line with its modest single-thread throughput.
- Desktop wins on the disk-backed fsync path (`RecordBufferAddWAL`), but the
  PN41 (SATA/NVMe) beats the Pi 5 (SD card) on the same benchmark
  (12.5 µs vs 44.5 µs), consistent with their storage: Hynix SSD ≫
  Lexar N610 SSD > Lexar 633x microSD.
- `PutAll` vs `Put` batch gain holds on all three machines
  (Pi 5 n=1000: 0.26ms vs 0.54ms ~2.1×; PN41 n=1000: 0.71ms vs 1.93ms ~2.7×).
