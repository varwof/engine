# engine 配置参考（EngineOptions）

> 版本：v1（对应 `engine` 包实施完成）
> 所有字段零值表示使用默认值。完整定义见 `engine/options.go`。

## 内存上限

| 字段 | 默认 | 说明 |
|---|---|---|
| `MaxCerts` | 200000 | 内存证书记录上限。超限先逐出最旧过期证书；无过期可逐出时 `IssueCert` 返回 `ErrBackpressure` |
| `MaxResidentBytes` | 2 GiB | 热索引（证书记录 + AIC 扩展）驻留内存字节预算（估算值：基础开销 + cert_der + 字符串字段 / AIC JSON，put/remove/evict 时记账）。超限先逐出过期；无过期可逐出时 `IssueCert` 返回 `ErrBackpressure`（R8） |
| `MaxNonces` | 100000 | 16 字节 RenewalToken nonce 集合上限。满时先清理过期，仍满则 `StoreNonce` 返回 `ErrBackpressure` |
| `MaxDANonces` | 100000 | 32 字节 DA nonce（DelegationAuthorization 防重放）集合上限。满时先清理过期，仍满则 `StoreDANonce` 返回 `ErrBackpressure` |
| `MaxRevoked` | 50000 | 每 CA 吊销集（CRL 窗口）上限。超限时逐出 revoked_at 最旧的条目（证书状态仍为 R，仅退出 CRL 窗口）；`<=0` 不限制 |

## 时间窗口与 janitor

| 字段 | 默认 | 说明 |
|---|---|---|
| `Grace` | 24h | 证书 `not_after` 超过当前时间多久后移出热内存（`not_after < now - grace` 即剪枝） |
| `JanitorInterval` | 60s | 后台剪枝周期（过期证书 / 过期吊销 / 过期 nonce / 过期 DA nonce），并同步清理后端 `renewal_tokens` 与 `da_nonces` 中的过期行（按 `NonceTTL`） |
| `NonceTTL` | 24h | nonce 存活时长，过期自动清理（内存 + 后端 `renewal_tokens` / `da_nonces`） |

## 写管道（继承 recordbuffer）

| 字段 | 默认 | 说明 |
|---|---|---|
| `WriteThreshold` | 100 | 攒批条数，达到即触发批量落库 |
| `WriteMaxPending` | 5000 | 待落库硬上限，超过后 `IssueCert` 返回 `ErrBackpressure`（背压 → 503） |
| `WriteMaxLatency` | 500ms | 最大等待时长，到期强制刷盘 |
| `WriteWorkers` | 4 | 后端 writer goroutine 数量。操作按键哈希分区：同 key 操作保序（nonce Store→Consume、证书签发→吊销），不同 key 并行执行（R4） |
| `WalPath` | 空 | 证书批次 **与 DA nonce** 的 WAL 预写日志路径。空 = 不启用 WAL（未落库批次崩溃不保证；DA nonce 存储回退同步 DB 写入）。仅对文件型 SQLite 有意义；`:memory:` / PG / MySQL 无 WAL |

## 生命周期与可观测

| 字段 | 默认 | 说明 |
|---|---|---|
| `OnCertRevoked` | nil | 吊销回调 `func(serial string)`。serial 为空表示批量吊销。core 用于精确失效握手吊销缓存与 OCSP LRU |
| `Logger` | `slog.Default()` | 结构化日志（重建耗时、janitor 剪枝、异步落库失败、慢 flush、背压触发） |

## 使用示例

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
