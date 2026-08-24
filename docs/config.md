# engine Configuration Reference (EngineOptions)

> Version: v1 (engine package implementation complete)
> All fields default to zero values. Full definition in `engine/options.go`.

## Memory Limits

| Field | Default | Description |
|---|---|---|
| `MaxCerts` | 200000 | Max in-memory certificate records. On overflow, evicts oldest expired first; if nothing evictable, `IssueCert` returns `ErrBackpressure` |
| `MaxResidentBytes` | 2 GiB | Estimated resident-memory byte budget for the hot indexes (cert records + AIC extensions). Tracked as an estimate (base overhead + cert_der + string fields / AIC JSON) on put/remove/evict. On overflow, evicts expired first; if nothing evictable, `IssueCert` returns `ErrBackpressure` (R8) |
| `MaxNonces` | 100000 | 16-byte RenewalToken nonce set capacity. Full → clean expired first, still full → `StoreNonce` returns `ErrBackpressure` |
| `MaxDANonces` | 100000 | 32-byte DA nonce (DelegationAuthorization anti-replay) set capacity. Full → clean expired first, still full → `StoreDANonce` returns `ErrBackpressure` |
| `MaxRevoked` | 50000 | Per-CA revoked set (CRL window) capacity. Overflow evicts oldest revoked_at entry (certificate stays R, just exits CRL window); `<=0` = unlimited |

## Time Window & Janitor

| Field | Default | Description |
|---|---|---|
| `Grace` | 24h | How long after `not_after` before a certificate is evicted from hot memory (`not_after < now - grace` → pruned) |
| `JanitorInterval` | 60s | Background pruning period (expired certs / expired revocations / expired nonces / expired DA nonces), also cleans expired rows from backend `renewal_tokens` and `da_nonces` (by `NonceTTL`) |
| `NonceTTL` | 24h | Nonce lifetime; expired entries auto-cleaned (memory + backend `renewal_tokens` / `da_nonces`) |

## Write Pipeline (inherited from recordbuffer)

| Field | Default | Description |
|---|---|---|
| `WriteThreshold` | 100 | Batch size threshold; reaching it triggers bulk persistence |
| `WriteMaxPending` | 5000 | Pending-pipeline hard limit; exceeded → `IssueCert` returns `ErrBackpressure` (backpressure → 503) |
| `WriteMaxLatency` | 500ms | Max wait time; on expiry forces flush to disk |
| `WriteWorkers` | 4 | Number of backend writer goroutines. Ops partitioned by key hash: same-key ops keep ordering (nonce Store→Consume, cert issue→revoke), different keys run in parallel (R4) |
| `WalPath` | empty | WAL path for certificate batches **and DA nonces**. Empty = WAL disabled (crash-unsafe for unpersisted batches; DA nonce storage falls back to synchronous DB writes). Only meaningful for file-based SQLite; `:memory:` / PG / MySQL have no WAL |

## Lifecycle & Observability

| Field | Default | Description |
|---|---|---|
| `OnCertRevoked` | nil | Revocation callback `func(serial string)`. Empty serial means bulk revocation. Used by varwof-core to invalidate handshake revocation cache and OCSP LRU |
| `Logger` | `slog.Default()` | Structured logger (rebuild duration, janitor pruning, async persistence failures, slow flush, backpressure triggers) |

## Usage Example

```go
e, err := engine.NewEngine(d, engine.EngineOptions{
    MaxCerts:        500000,
    Grace:           7 * 24 * time.Hour,
    NonceTTL:        48 * time.Hour,
    WriteThreshold:  200,
    WriteMaxPending: 10000,
    WalPath:         "/var/lib/pki/pki.db-records.wal",
    OnCertRevoked:   func(serial string) { ocspLRU.PurgeSerial(serial); handshakeCache.Delete(serial) },
})
if err != nil {
    return err
}
defer e.Stop()
e.Start()
```
