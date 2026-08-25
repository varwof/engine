# varwof-engine

> In-memory-centric high-performance data subsystem for varwof-core: OCSP / CRL / nonce / certificate status with resident-memory queries and batch persistence.

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/engine)](https://pkg.go.dev/github.com/varwof/engine)

[中文](README_CN.md)

## What is varwof-engine?

An in-memory-centric high-speed data subsystem for varwof-core, providing resident-memory queries and batch persistence for OCSP / CRL / nonce / certificate status.

- **Memory is truth**: all high-frequency reads/writes hit in-memory indexes, zero SQL for reads
- **Batch persistence**: inherits varwof-core RecordBuffer (WAL crash safety / backpressure)
- **Time-window optimization**: OCSP/CRL pruned by certificate validity window
- **3-way dialect backend**: SQLite / PostgreSQL / MySQL
- **Single-instance authority**: v1 does not do distributed consensus

## Quick Start

```bash
go test -count=1 ./...
go build ./...
```

```go
import "github.com/varwof/engine/engine"

eng, _ := engine.New(engine.Options{...})
defer eng.Close()

// Memory write (immediately visible)
eng.IssueCert(record)

// Memory query (zero SQL)
status, _ := eng.GetCertStatus(serial)
```

## Installation

```bash
go get github.com/varwof/engine@v0.1.0
```

## Benchmark Performance

| Benchmark | Metric |
|-----------|--------|
| GetCertStatus | Hit ~230ns / miss ~45ns, zero SQL |
| IssueCertMemory | Memory write ~7.2µs/op |
| RecordBufferAdd | No WAL ~410ns, 0 allocs |
| CacheGetHit | Hit ~212ns, read-lock path |

## Ecosystem

```mermaid
graph TB
    subgraph varwof["varwof Ecosystem"]
        core["core<br/>PKI CA"]
        eng["engine<br/>In-Memory Engine"]
        db[(Database)]
    end
    core --> eng
    eng -->|batch persist| db
    eng -->|zero-SQL reads| core
```

engine is the **performance acceleration layer** of the varwof ecosystem. This project is a member of the [Open Invention Network](https://openinventionnetwork.com/).

## Links

| | |
|---|---|
| Homepage | https://varwof.com |
| Community | https://varwof.org |
| IETF Draft | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| License | AGPL-3.0 |
| Member | [Open Invention Network](https://openinventionnetwork.com/) |
