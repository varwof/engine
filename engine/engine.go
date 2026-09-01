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

	// sendMu serializes op submission against shutdown. Producers hold the read
	// lock while blocking-sending to a writer shard; Stop takes the write lock
	// only after the writer goroutines have drained and exited. A send is
	// therefore guaranteed to reach a live writer until shutdown completes, so
	// no security-critical op is dropped (finding 5). After Stop marks the
	// engine stopped, new ops run inline rather than being lost.
	sendMu sync.RWMutex
	// stopped is true once the writer goroutines have drained and exited; ops
	// submitted after this point execute inline on the caller's goroutine.
	stopped atomic.Bool
	// reconcileSince is the watermark for periodic out-of-band revocation
	// reconciliation. Written and read only by the janitor goroutine.
	reconcileSince time.Time

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
		opts:           opts,
		certIdx:        NewCertIndex(),
		revoked:        NewRevokedSet(opts.MaxRevoked),
		nonces:         NewNonceSet(opts.MaxNonces),
		daNonces:       NewNonceSet(opts.MaxDANonces),
		subCas:         NewSubCAIndex(),
		trust:          NewTrustIndex(),
		aic:            NewAICIndex(),
		users:          newUserIndex(),
		tokens:         newTokenIndex(),
		writerShards:   shards,
		ctx:            ctx,
		cancel:         cancel,
		reconcileSince: time.Now(),
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
	if err := e.rb.FlushAll(); err != nil {
		return err
	}
	n := len(e.writerShards)
	barriers := make([]chan struct{}, n)
	for i, ch := range e.writerShards {
		barriers[i] = make(chan struct{})
		e.sendMu.RLock()
		if e.stopped.Load() {
			e.sendMu.RUnlock()
			close(barriers[i])
			continue
		}
		ch <- func() error { close(barriers[i]); return nil }
		e.sendMu.RUnlock()
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

// Stop flushes all pending work and shuts down background goroutines. Writer
// goroutines drain their queues before exiting, and the engine marks itself
// stopped only after that drain completes, so an op submitted concurrently
// with Stop is executed rather than dropped (finding 5).
func (e *Engine) Stop() {
	// Push buffered certs to the DB first so queued revoke UPDATEs match.
	_ = e.rb.FlushAll()
	e.cancel()
	e.wg.Wait()
	e.sendMu.Lock()
	e.stopped.Store(true)
	e.sendMu.Unlock()
	e.rb.Stop()
}

// enqueue submits an op to the backend writer shard that owns key. Same-key
// ops are serialized in order; a zero key routes to shard 0. Same-key ordering
// is what preserves nonce Store→Consume and cert issue→revoke semantics under
// sharded parallelism.
//
// The op is never dropped: the blocking send is guaranteed to reach a live
// writer until Stop has drained and shut down the shards; after that the op
// runs inline (finding 5).
func (e *Engine) enqueue(key string, f func() error) {
	e.sendMu.RLock()
	defer e.sendMu.RUnlock()
	if e.stopped.Load() {
		if err := f(); err != nil {
			e.opts.Logger.Warn("engine: backend write failed during shutdown", "error", err)
		}
		return
	}
	e.writerShards[e.writerShardForKey(key)] <- f
}

// enqueueSync submits an op to the backend writer shard that owns key and
// waits for it to run, returning its error. It is the durable variant of
// enqueue for security-critical transitions (revocation, nonce consumption /
// insertion): a persistence failure is returned to the caller instead of being
// swallowed, and the op is never dropped on shutdown (findings 1/4/5).
func (e *Engine) enqueueSync(key string, f func() error) error {
	e.sendMu.RLock()
	if e.stopped.Load() {
		e.sendMu.RUnlock()
		return f()
	}
	ch := e.writerShards[e.writerShardForKey(key)]
	done := make(chan error, 1)
	wrapped := func() error {
		err := f()
		done <- err
		return err
	}
	ch <- wrapped
	e.sendMu.RUnlock()
	// The writer runs wrapped during normal operation or the shutdown drain, so
	// done always receives a value before the writer for that shard exits.
	return <-done
}

// persistDurable runs a durability-critical backend op synchronously through
// the writer pipeline, retrying transient failures with a short backoff. It
// returns the op's error so callers surface a revocation that did not reach
// the backend instead of acknowledging it in memory only (findings 1/4).
func (e *Engine) persistDurable(key string, op func() error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = e.enqueueSync(key, op); err == nil {
			return nil
		}
		select {
		case <-e.ctx.Done():
			return err
		case <-time.After(time.Duration(attempt+1) * 50 * time.Millisecond):
		}
	}
	return err
}

// flushDurable synchronously drains the record buffer, retrying transient
// backend failures, so a caller's dependent write (e.g. a revocation UPDATE)
// can rely on the preceding certificate INSERTs having landed.
func (e *Engine) flushDurable() error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = e.rb.FlushAll(); err == nil {
			return nil
		}
		select {
		case <-e.ctx.Done():
			return err
		case <-time.After(time.Duration(attempt+1) * 50 * time.Millisecond):
		}
	}
	return err
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
