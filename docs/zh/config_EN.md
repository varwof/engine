# engine Configuration Reference (EngineOptions)

> Version: v1 (corresponds to the completed `engine` package implementation)
> All zero-value fields mean "use default". Full definitions in `engine/options.go`.

## Memory Caps

| Field | Default | Description |
|---|---|---|
| `MaxCerts` | 200000 | In-memory certificate record cap. When exceeded, oldest expired certificates are evicted first; if none are expirable, `IssueCert` returns `ErrBackpressure` |
| `MaxResidentBytes` | 2 GiB | Resident-memory byte budget for hot indexes (certificate records + AIC extensions) (estimated: base overhead + cert_der + string fields / AIC JSON, accounted on put/remove/evict). When exceeded, expired entries are evicted first; if none are expirable, `IssueCert` returns `ErrBackpressure` (R8) |
| `MaxNonces` | 100000 | Cap for the 16-byte RenewalToken nonce set. When full, expired entries are cleaned first; if still full, `StoreNonce` returns `ErrBackpressure` |
| `MaxDANonces` | 100000 | Cap for the 32-byte DA nonce (DelegationAuthorization anti-replay) set. When full, expired entries are cleaned first; if still full, `StoreDANonce` returns `ErrBackpressure` |
| `MaxRevoked` | 50000 | Per-CA revoked set (CRL window) cap. When exceeded, the entry with the oldest revoked_at is evicted (certificate status remains R; it only leaves the CRL window); `<=0` means unlimited |

## Time Window & Janitor

| Field | Default | Description |
|---|---|---|
| `Grace` | 24h | How long after a certificate's `not_after` passes the current time before it is removed from hot memory (`not_after < now - grace` triggers pruning) |
| `JanitorInterval` | 60s | Background pruning period (expired certificates / expired revocations / expired nonces / expired DA nonces); also cleans expired rows from backend `renewal_tokens` and `da_nonces` (per `NonceTTL`) |
| `NonceTTL` | 24h | Nonce lifetime; automatically cleaned when expired (memory + backend `renewal_tokens` / `da_nonces`) |

## Write Pipeline (inherited from recordbuffer)

| Field | Default | Description |
|---|---|---|
| `WriteThreshold` | 100 | Batch size threshold that triggers bulk persistence |
| `WriteMaxPending` | 5000 | Hard cap on pending records; beyond it `IssueCert` returns `ErrBackpressure` (backpressure → 503) |
| `WriteMaxLatency` | 500ms | Maximum wait duration; force-flushes when reached |
| `WriteWorkers` | 4 | Number of backend writer goroutines. Operations are partitioned by key hash: same-key operations stay ordered (nonce Store→Consume, certificate issue→revoke), different keys execute in parallel (R4) |
| `WalPath` | empty | WAL pre-write log path for certificate batches **and DA nonces**. Empty = WAL disabled (crash of unpersisted batches not guaranteed; DA nonce storage falls back to synchronous DB writes). Only meaningful for file-based SQLite; `:memory:` / PG / MySQL have no WAL |

## Lifecycle & Observability

| Field | Default | Description |
|---|---|---|
| `OnCertRevoked` | nil | Revocation callback `func(serial string)`. Empty serial indicates bulk revocation. Core uses it to precisely invalidate the handshake revocation cache and OCSP LRU |
| `Logger` | `slog.Default()` | Structured logging (rebuild duration, janitor pruning, async persistence failures, slow flush, backpressure triggers) |

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
