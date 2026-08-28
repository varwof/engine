// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/engine/db"
	"github.com/varwof/engine/recordbuffer"
)

// Sentinel errors returned by the engine.
var (
	// ErrNotFound is returned when a keyed lookup misses the in-memory index.
	// It maps to database/sql.ErrNoRows semantics for callers.
	ErrNotFound = errors.New("not found")

	// ErrDuplicate is returned when an insert collides with an existing key.
	ErrDuplicate = errors.New("duplicate")

	// ErrBackpressure is returned when the write pipeline is at capacity and
	// the caller should surface an HTTP 503.
	ErrBackpressure = errors.New("write pipeline backpressure")
)

// Metrics is a point-in-time snapshot of engine internals for observability.
type Metrics struct {
	CertIndexSize   int
	RevokedSetSize  int
	NonceSetSize    int
	DANonceSetSize  int
	SubCASize       int
	TrustAnchorSize int
	AICSize         int
	UserIndexSize   int
	TokenIndexSize  int

	CertResidentBytes int64
	AICResidentBytes  int64

	WindowEvictions uint64
	AICPruned       uint64
	CertIssued      uint64
	CertRevoked     uint64
	ReadHits        uint64
	ReadMisses      uint64
	PipelinePending int32
	WalBytes        int64

	FlushCount    uint64
	FlushDuration [4]uint64 // histogram buckets: <10ms, <100ms, <1s, >=1s
}

// Engine is the memory-centric data subsystem. Create it with NewEngine, call
// Start to begin janitor pruning, and Stop when shutting down.
type Engine struct {
	mu   sync.RWMutex
	db   atomic.Pointer[db.DB]
	opts EngineOptions

	certIdx   *CertIndex
	revoked   *RevokedSet
	nonces    *NonceSet
	daNonces  *NonceSet
	subCas    *SubCAIndex
	trust     *TrustIndex
	aic       *AICIndex
	users     *userIndex
	tokens    *tokenIndex
	rb        *recordbuffer.RecordBuffer
	loaded    atomic.Bool
	started   atomic.Bool
	startOnce sync.Once

	// writerShards partition low-frequency backend writes (revoke/nonce/meta).
	// Ops are routed by key hash so same-key operations keep their ordering
	// (e.g. nonce Store → Consume, cert issue → revoke); different keys run on
	// different goroutines in parallel, removing the single-writer ceiling.
	writerShards []chan func() error
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc

	evictions    atomic.Uint64
	readHits     atomic.Uint64
	readMiss     atomic.Uint64
	issued       atomic.Uint64
	revokedCount atomic.Uint64
	aicPruned    atomic.Uint64
}

// NewEngine builds the engine and performs a full in-memory rebuild from the
// backend database. It returns an error if the backend cannot be read.
func NewEngine(d *db.DB, opts EngineOptions) (*Engine, error) {
	if d == nil {
		return nil, errors.New("engine: nil db")
	}
	opts = opts.defaults()
	ctx, cancel := context.WithCancel(context.Background())

	shards := make([]chan func() error, opts.WriteWorkers)
	for i := range shards {
		shards[i] = make(chan func() error, 1024)
	}

	e := &Engine{
		opts:         opts,
		certIdx:      NewCertIndex(),
		revoked:      NewRevokedSet(opts.MaxRevoked),
		nonces:       NewNonceSet(opts.MaxNonces),
		daNonces:     NewNonceSet(opts.MaxDANonces),
		subCas:       NewSubCAIndex(),
		trust:        NewTrustIndex(),
		aic:          NewAICIndex(),
		users:        newUserIndex(),
		tokens:       newTokenIndex(),
		writerShards: shards,
		ctx:          ctx,
		cancel:       cancel,
	}
	e.db.Store(d)

	rb, err := recordbuffer.NewRecordBuffer(func() *db.DB { return e.DB() },
		opts.WriteThreshold, opts.WriteMaxPending, opts.WriteMaxLatency, opts.WalPath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("engine: record buffer: %w", err)
	}
	e.rb = rb

	start := time.Now()
	if err := e.load(); err != nil {
		rb.Stop()
		cancel()
		return nil, fmt.Errorf("engine: rebuild: %w", err)
	}
	opts.Logger.Info("engine: full rebuild complete",
		"certs", e.certIdx.Len(), "revoked", e.revoked.Len(),
		"nonces", e.nonces.Len(), "da_nonces", e.daNonces.Len(), "dur_ms", time.Since(start).Milliseconds())

	for i := range e.writerShards {
		e.wg.Add(1)
		go e.writerLoop(ctx, e.writerShards[i])
	}
	return e, nil
}

// DB returns the backend database handle.
func (e *Engine) DB() *db.DB { return e.db.Load() }

// NonceTTL returns the configured unused-nonce lifetime. It is the last-resort
// retention fallback for DA nonces when neither the timestamp-skew window nor
// the DA lifetime is available.
func (e *Engine) NonceTTL() time.Duration { return e.opts.NonceTTL }

// SetDB atomically swaps the backend database handle. It is used on config
// reload when the database connection changes but the engine's in-memory
// index remains valid (same underlying store): reads stay on the resident
// index while future writes go through the new handle. Safe to call while
// the engine is running. A nil handle is ignored.
func (e *Engine) SetDB(d *db.DB) {
	if d == nil {
		return
	}
	e.db.Store(d)
}

// Loading reports whether the startup rebuild has completed. While false, the
// engine indexes are not authoritative and callers may want to reject writes
// or serve reads in degraded mode.
func (e *Engine) Loading() bool { return !e.loaded.Load() }

// Start begins the background janitor. It is safe to call multiple times.
func (e *Engine) Start() {
	e.startOnce.Do(func() {
		e.started.Store(true)
		e.wg.Add(1)
		go e.janitorLoop(e.ctx)
	})
}

// FlushAll synchronously drains the cert write pipeline and all queued backend
// ops across every writer shard. It is an operations fallback; normal
// reads/writes need not call it because memory is authoritative and revocation
// already flushes internally.
func (e *Engine) FlushAll() error {
	e.rb.FlushAll()
	n := len(e.writerShards)
	barriers := make([]chan struct{}, n)
	for i, ch := range e.writerShards {
		barriers[i] = make(chan struct{})
		select {
		case ch <- func() error { close(barriers[i]); return nil }:
		case <-e.ctx.Done():
			return e.ctx.Err()
		}
	}
	for i := range barriers {
		select {
		case <-barriers[i]:
		case <-e.ctx.Done():
			return e.ctx.Err()
		}
	}
	return nil
}

// Stop flushes all pending work and shuts down background goroutines.
func (e *Engine) Stop() {
	// Push buffered certs to the DB first so queued revoke UPDATEs match.
	e.rb.FlushAll()
	e.cancel()
	e.wg.Wait()
	e.rb.Stop()
}

// enqueue submits an op to the backend writer shard that owns key. Same-key
// ops are serialized in order; a zero key routes to shard 0. Same-key ordering
// is what preserves nonce Store→Consume and cert issue→revoke semantics under
// sharded parallelism.
func (e *Engine) enqueue(key string, f func() error) {
	shard := e.writerShards[e.writerShardForKey(key)]
	select {
	case shard <- f:
	case <-e.ctx.Done():
	}
}

// writerShardForKey maps an ordering key to a shard index. Zero key → shard 0.
func (e *Engine) writerShardForKey(key string) int {
	if key == "" || len(e.writerShards) == 1 {
		return 0
	}
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return int(h % uint32(len(e.writerShards)))
}

// writerLoop drains one backend-op shard. On shutdown it drains the queue so
// ordering guarantees (e.g. revoke UPDATE after cert INSERT) are preserved.
func (e *Engine) writerLoop(ctx context.Context, ch chan func() error) {
	defer e.wg.Done()
	for {
		select {
		case op := <-ch:
			e.runOp(op)
		case <-ctx.Done():
			for {
				select {
				case op := <-ch:
					e.runOp(op)
				default:
					return
				}
			}
		}
	}
}

func (e *Engine) runOp(op func() error) {
	if err := op(); err != nil {
		e.opts.Logger.Warn("engine: async backend write failed", "error", err)
	}
}

// Metrics returns a point-in-time snapshot of engine internals.
func (e *Engine) Metrics() Metrics {
	flushCount, flushBuckets := e.rb.FlushStats()
	return Metrics{
		CertIndexSize:     e.certIdx.Len(),
		RevokedSetSize:    e.revoked.Len(),
		NonceSetSize:      e.nonces.Len(),
		DANonceSetSize:    e.daNonces.Len(),
		SubCASize:         e.subCas.Len(),
		TrustAnchorSize:   e.trust.Len(),
		AICSize:           e.aic.Len(),
		UserIndexSize:     e.users.len(),
		TokenIndexSize:    e.tokens.len(),
		CertResidentBytes: e.certIdx.ResidentBytes(),
		AICResidentBytes:  e.aic.ResidentBytes(),
		WindowEvictions:   e.evictions.Load(),
		AICPruned:         e.aicPruned.Load(),
		CertIssued:        e.issued.Load(),
		CertRevoked:       e.revokedCount.Load(),
		ReadHits:          e.readHits.Load(),
		ReadMisses:        e.readMiss.Load(),
		PipelinePending:   e.rb.Pending(),
		WalBytes:          e.rb.WalBytes(),
		FlushCount:        flushCount,
		FlushDuration:     flushBuckets,
	}
}

// PrometheusMetrics renders the engine metrics in Prometheus text exposition
// format (dependency-free).
func (e *Engine) PrometheusMetrics() string {
	m := e.Metrics()
	return fmt.Sprintf(`# TYPE varwof_engine_certindex_size gauge
varwof_engine_certindex_size %d
# TYPE varwof_engine_revokedset_size gauge
varwof_engine_revokedset_size %d
# TYPE varwof_engine_nonceset_size gauge
varwof_engine_nonceset_size %d
# TYPE varwof_engine_danonceset_size gauge
varwof_engine_danonceset_size %d
# TYPE varwof_engine_subca_size gauge
varwof_engine_subca_size %d
# TYPE varwof_engine_trustanchor_size gauge
varwof_engine_trustanchor_size %d
# TYPE varwof_engine_aic_size gauge
varwof_engine_aic_size %d
# TYPE varwof_engine_aic_resident_bytes gauge
varwof_engine_aic_resident_bytes %d
# TYPE varwof_engine_cert_resident_bytes gauge
varwof_engine_cert_resident_bytes %d
# TYPE varwof_engine_window_evictions_total counter
varwof_engine_window_evictions_total %d
# TYPE varwof_engine_aic_pruned_total counter
varwof_engine_aic_pruned_total %d
# TYPE varwof_engine_cert_issued_total counter
varwof_engine_cert_issued_total %d
# TYPE varwof_engine_cert_revoked_total counter
varwof_engine_cert_revoked_total %d
# TYPE varwof_engine_read_hit_total counter
varwof_engine_read_hit_total %d
# TYPE varwof_engine_read_miss_total counter
varwof_engine_read_miss_total %d
# TYPE varwof_engine_pipeline_pending gauge
varwof_engine_pipeline_pending %d
# TYPE varwof_engine_wal_bytes gauge
varwof_engine_wal_bytes %d
# TYPE varwof_engine_flush_duration_seconds histogram
varwof_engine_flush_duration_seconds_bucket{le="0.01"} %d
varwof_engine_flush_duration_seconds_bucket{le="0.1"} %d
varwof_engine_flush_duration_seconds_bucket{le="1"} %d
varwof_engine_flush_duration_seconds_bucket{le="+Inf"} %d
varwof_engine_flush_duration_seconds_count %d
`, m.CertIndexSize, m.RevokedSetSize, m.NonceSetSize, m.DANonceSetSize,
		m.SubCASize, m.TrustAnchorSize, m.AICSize,
		m.AICResidentBytes, m.CertResidentBytes,
		m.WindowEvictions, m.AICPruned, m.CertIssued, m.CertRevoked,
		m.ReadHits, m.ReadMisses, m.PipelinePending, m.WalBytes,
		m.FlushDuration[0],
		m.FlushDuration[0]+m.FlushDuration[1],
		m.FlushDuration[0]+m.FlushDuration[1]+m.FlushDuration[2],
		m.FlushDuration[0]+m.FlushDuration[1]+m.FlushDuration[2]+m.FlushDuration[3],
		m.FlushCount)
}

func (e *Engine) tickRead(hit bool) {
	if hit {
		e.readHits.Add(1)
	} else {
		e.readMiss.Add(1)
	}
}
