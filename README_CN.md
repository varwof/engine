# varwof-engine

> 以内存为中心的高性能数据子系统，为 varwof-core 提供 OCSP / CRL / nonce / 证书状态的常驻内存查询与批量落库

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/engine)](https://pkg.go.dev/github.com/varwof/engine)

> ⚠️ **预览版** — 不可用于生产环境。API 和功能可能在正式发布前发生变更。

[English](README.md)

## 什么是 varwof-engine？

以内存为中心的专用高速数据子系统，为 varwof-core 提供常驻内存查询与批量落库。

- **内存即真相**：读零 SQL，写先内存后异步落库
- **批量落库**：WAL 崩溃安全 / 背压
- **时间窗口优化**：按证书有效时间窗口剪枝
- **三方言后端**：SQLite / PostgreSQL / MySQL

## 快速开始

```bash
go test -count=1 ./...
go build ./...
```

```go
import "github.com/varwof/engine/engine"
eng, _ := engine.New(engine.Options{...})
eng.IssueCert(record)
status, _ := eng.GetCertStatus(serial)
```

## 基准性能

| 基准 | 指标 |
|------|------|
| GetCertStatus | 命中 ~230ns / 未命中 ~45ns |
| IssueCertMemory | 内存写 ~7.2µs/次 |
| RecordBufferAdd | 无 WAL ~410ns |

engine 是 varwof 生态的**性能加速层**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | AGPL-3.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |
