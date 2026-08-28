// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package recordbuffer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/engine/db"
)

const (
	defaultMaxPending  = 20000
	defaultMaxLatency  = 500 * time.Millisecond
	defaultFlushBatch  = 500
	fsyncEveryNRecords = 100
	fsyncMaxInterval   = 100 * time.Millisecond
	// checkpointInterval is the minimum interval between WAL checkpoints. SQLite's
	// auto-checkpoint is suppressed when concurrent readers are present (auto-checkpoint
	// requires exclusive access); high-throughput issuance can let pki.db-wal grow
	// unboundedly. This interval forces a periodic convergence to avoid the lock
	// overhead of checkpointing on every flush.
	checkpointInterval = 2 * time.Second
	// flushDBTimeout bounds each backend bulk write issued by the flush and WAL
	// replay paths. A MySQL connection that goes half-open mid-INSERT has no
	// intrinsic read deadline (see db.ensureMySQLTimeouts for the driver-level
	// backstop) — without this context the drain goroutine would block forever in
	// readPacket while holding flushMu, wedging the whole write pipeline (pending
	// pinned at maxPending → every issuance returns 503) and deadlocking Stop().
	// 2 minutes is generous for real 200K-record flush passes (thousands of
	// 39-row chunk statements) yet still bounds a genuine hang.
	flushDBTimeout = 2 * time.Minute
)

// ItemKind discriminates the record kinds a RecordBuffer can carry.
type ItemKind uint8

const (
	// KindCert is a certificate record persisted via BulkInsertCertRecords.
	KindCert ItemKind = iota
	// KindDANonce is a DelegationAuthorization nonce (32 bytes) persisted via
	// BulkStoreDANonces.
	KindDANonce
)

// Item is a single buffered write. Exactly one of Cert / Nonce is set
// depending on Kind.
type Item struct {
	Kind  ItemKind
	Cert  *db.CertRecord
	Nonce []byte
}

// CertItem wraps a certificate record as a buffer Item.
func CertItem(rec *db.CertRecord) Item { return Item{Kind: KindCert, Cert: rec} }

// DANonceItem wraps a DA nonce as a buffer Item.
func DANonceItem(nonce []byte) Item { return Item{Kind: KindDANonce, Nonce: nonce} }

// RecordBuffer batches certificate records and flushes them to the DB once the
// threshold count or maxLatency is reached. Includes a WAL write-ahead log
// (crash safe), MaxPending hard limit (backpressure), and MaxLatency (maximum delay).
type RecordBuffer struct {
	mu sync.Mutex
	// flushMu serializes flush passes. Without it, a caller's FlushAll can
	// overlap the background drain goroutine's flush(): both copy the same
	// snapshot and both advance rb.records, so records appended between the
	// two copies are skipped and lost (and pending goes negative). Holding it
	// across copy→insert→advance makes a flush pass atomic.
	flushMu sync.Mutex
	// walMu serializes every operation on the WAL file and its bufio writer.
	// The drain goroutine (flushLocked), the periodic fsync inside add(), and
	// the synchronous DA nonce path (AddDANonceSync) all touch the same
	// bufio.Writer / *os.File; bufio.Writer is not safe for concurrent use, so
	// write + flush + sync + truncate + seek all take walMu. walMu is always
	// acquired leaf-last (never held while another mutex is held), so it cannot
	// deadlock with rb.mu or flushMu.
	walMu      sync.Mutex
	records    []Item
	pending    atomic.Int32
	threshold  int
	maxPending int32
	maxLatency time.Duration
	flushCh    chan struct{}

	walPath   string
	walFile   *os.File
	walBuf    *bufio.Writer
	fsyncCnt  int
	lastFsync time.Time

	// flushStatsMu guards the flush latency histogram, read by FlushStats and
	// written by flushLocked. Kept separate from flushMu so a metrics reader
	// never contends with an in-flight flush.
	flushStatsMu sync.Mutex
	flushCount   uint64
	flushBuckets [4]uint64

	cancel context.CancelFunc
	db     func() *db.DB
	wg     sync.WaitGroup

	// capacity signals waiters in waitForCapacity whenever the drain loop frees
	// buffer capacity. It uses a close-and-replace broadcast so every waiter
	// wakes at once — a full buffer never thundering-herds request goroutines
	// onto flushMu, and waiters do not burn CPU polling.
	capacity *capacitySignal
}

// capacitySignal is a close-and-replace broadcast: signal() wakes every goroutine
// currently waiting on channel() and arms a fresh channel for the next pass.
type capacitySignal struct {
	mu sync.Mutex
	ch chan struct{}
}

func newCapacitySignal() *capacitySignal { return &capacitySignal{ch: make(chan struct{})} }

// signal wakes all current waiters and prepares the next generation channel.
func (s *capacitySignal) signal() {
	s.mu.Lock()
	close(s.ch)
	s.ch = make(chan struct{})
	s.mu.Unlock()
}

// channel returns the channel to select on for the next capacity signal.
func (s *capacitySignal) channel() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ch
}

// NewRecordBuffer creates a record buffer.
// getDB: returns the current DB pointer (supports hot reload)
// threshold: record count that triggers a flush (recommended: 100)
// maxPending: hard upper bound on pending records; Add returns false when exceeded (recommended: 5000)
// maxLatency: maximum wait time before a forced flush (recommended: 500ms)
// walPath: WAL file path; empty string = WAL disabled (crash unsafe)
func NewRecordBuffer(getDB func() *db.DB, threshold int, maxPending int32, maxLatency time.Duration, walPath string) (*RecordBuffer, error) {
	// Replay existing WAL first (restart recovery).
	if walPath != "" {
		if err := replayWAL(getDB, walPath); err != nil {
			slog.Warn("record_buffer: WAL replay failed, continuing", "path", walPath, "error", err)
		}
	}

	f, err := openWAL(walPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Only create a WAL buffer when walPath is non-empty. bufio.NewWriterSize
	// returns a non-nil *bufio.Writer even when the underlying writer is nil;
	// unconditional creation would cause the empty-walPath "WAL disabled" path
	// to still perform JSON marshal + bufio buffering + periodic fsync.
	var walBuf *bufio.Writer
	if f != nil {
		walBuf = bufio.NewWriterSize(f, 64*1024)
	}
	rb := &RecordBuffer{
		threshold:  threshold,
		maxPending: maxPending,
		maxLatency: maxLatency,
		flushCh:    make(chan struct{}, 1),
		walPath:    walPath,
		walFile:    f,
		// 64KB bufio: each JSON line is ~2KB, so about 32 lines accumulate before
		// triggering a lock-holding write() syscall (with the default 4KB buffer,
		// every 2 lines trigger one syscall, making rb.mu a hot spot under concurrency).
		walBuf:    walBuf,
		lastFsync: time.Now(),
		cancel:    cancel,
		db:        getDB,
	}
	rb.capacity = newCapacitySignal()
	rb.wg.Add(1)
	go func() {
		defer rb.wg.Done()
		rb.run(ctx)
	}()
	return rb, nil
}

// walLine is the tagged JSON envelope written to the WAL. Legacy lines
// (raw CertRecord JSON without a "kind" field) are still accepted.
type walLine struct {
	Kind  string         `json:"kind"`
	Cert  *db.CertRecord `json:"cert,omitempty"`
	Nonce []byte         `json:"nonce,omitempty"`
}

// parseWALLines parses WAL file contents into a list of items, skipping corrupt lines.
func parseWALLines(data []byte) []Item {
	var items []Item
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		var wl walLine
		if err := json.Unmarshal([]byte(line), &wl); err != nil {
			slog.Warn("record_buffer: skip corrupt WAL line", "error", err)
			continue
		}
		switch wl.Kind {
		case "da_nonce":
			if len(wl.Nonce) == 32 {
				items = append(items, DANonceItem(wl.Nonce))
			} else {
				slog.Warn("record_buffer: skip DA nonce WAL line with wrong length", "len", len(wl.Nonce))
			}
		case "cert":
			if wl.Cert != nil {
				items = append(items, CertItem(wl.Cert))
			}
		default:
			// Legacy WAL line: raw CertRecord JSON without a kind tag.
			var rec db.CertRecord
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				slog.Warn("record_buffer: skip corrupt WAL line", "error", err)
				continue
			}
			items = append(items, CertItem(&rec))
		}
	}
	return items
}

// replayWAL reads the WAL file, bulk-persists the items not yet in the
// database (certificates and DA nonces), and clears the WAL upon completion.
func replayWAL(getDB func() *db.DB, walPath string) error {
	data, err := os.ReadFile(walPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}

	items := parseWALLines(data)
	if len(items) == 0 {
		return nil
	}

	d := getDB()
	if d == nil {
		return nil
	}

	var certs []*db.CertRecord
	var nonces [][]byte
	for _, it := range items {
		switch it.Kind {
		case KindCert:
			certs = append(certs, it.Cert)
		case KindDANonce:
			nonces = append(nonces, it.Nonce)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), flushDBTimeout)
	defer cancel()

	var inserted int
	if len(certs) > 0 {
		inserted, err = d.BulkInsertCertRecordsCtx(ctx, certs)
		if err != nil {
			return err
		}
	}
	if len(nonces) > 0 {
		n, err := d.BulkStoreDANoncesCtx(ctx, nonces)
		if err != nil {
			return err
		}
		slog.Info("record_buffer: WAL replayed", "inserted", inserted, "da_nonces", n, "total", len(items))
		return nil
	}
	slog.Info("record_buffer: WAL replayed", "inserted", inserted, "total", len(items))
	return nil
}

// openWAL opens the WAL file in truncate mode and acquires an exclusive process
// lock. Returns (nil, nil) when walPath is empty. Returns ErrWALLocked if
// another process already holds the write pipeline for the same WAL.
func openWAL(walPath string) (*os.File, error) {
	if walPath == "" {
		return nil, nil
	}
	f, err := os.OpenFile(walPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return nil, err
	}
	if err := tryFlockWAL(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("record buffer WAL %s: %w", walPath, err)
	}
	return f, nil
}

// IsFull returns whether the buffer is full (used for upfront backpressure checks).
// maxPending<=0 disables backpressure (never returns true).
func (rb *RecordBuffer) IsFull() bool {
	return rb.maxPending > 0 && rb.pending.Load() >= rb.maxPending
}

// fullWaitTimeout bounds how long a synchronous DA-nonce append waits for the
// drain loop to free capacity before giving up and returning ErrBackpressure.
var fullWaitTimeout = 5 * time.Second

// waitForCapacity blocks until the buffer has room for one more record or the
// wait times out. It never performs a synchronous flush itself: when the buffer
// is full the drain loop is already flushing (every add signals flushCh), and a
// request-path FlushAll would serialize every caller behind a single flushMu
// hold — a thundering herd that freezes the whole server under sustained load.
// Waiters sleep on the capacity broadcast instead of polling, so all wake the
// moment the drain frees capacity. Returns ErrBackpressure when capacity cannot
// be freed within fullWaitTimeout; callers should respond 503 so the client
// retries.
func (rb *RecordBuffer) waitForCapacity() error {
	if !rb.IsFull() {
		return nil
	}
	// Wake the drain loop so pending actually decreases while we wait.
	select {
	case rb.flushCh <- struct{}{}:
	default:
	}
	timer := time.NewTimer(fullWaitTimeout)
	defer timer.Stop()
	for rb.IsFull() {
		select {
		case <-rb.capacity.channel():
			// The drain freed (or refilled) capacity: re-signal it and re-check.
			select {
			case rb.flushCh <- struct{}{}:
			default:
			}
		case <-timer.C:
			return ErrBackpressure
		}
	}
	return nil
}

// Pending returns the current number of records waiting to be flushed to the DB.
func (rb *RecordBuffer) Pending() int32 {
	return rb.pending.Load()
}

// WALEnabled reports whether the buffer has an active write-ahead log.
// When false, unflushed data is not crash-safe; DA nonces are buffered through
// the batch pipeline (AddDANonce) and converge on the next bulk flush.
func (rb *RecordBuffer) WALEnabled() bool { return rb.walFile != nil }

// WalBytes returns the current size of the WAL file in bytes, or 0 when WAL is
// disabled. Used for the engine's WAL-size metric.
func (rb *RecordBuffer) WalBytes() int64 {
	rb.walMu.Lock()
	defer rb.walMu.Unlock()
	if rb.walFile == nil {
		return 0
	}
	fi, err := rb.walFile.Stat()
	if err != nil {
		return 0
	}
	return fi.Size()
}

// FlushStats returns the cumulative flush histogram (buckets: <10ms, <100ms,
// <1s, >=1s) and the total flush count since startup.
func (rb *RecordBuffer) FlushStats() (count uint64, buckets [4]uint64) {
	rb.flushStatsMu.Lock()
	defer rb.flushStatsMu.Unlock()
	return rb.flushCount, rb.flushBuckets
}

// recordFlushStats updates the flush latency histogram. Called once per
// successful flush pass.
func (rb *RecordBuffer) recordFlushStats(dur time.Duration) {
	bucket := 3
	switch {
	case dur < 10*time.Millisecond:
		bucket = 0
	case dur < 100*time.Millisecond:
		bucket = 1
	case dur < time.Second:
		bucket = 2
	}
	rb.flushStatsMu.Lock()
	rb.flushCount++
	rb.flushBuckets[bucket]++
	rb.flushStatsMu.Unlock()
}

// Add appends a certificate record to the buffer.
// Returns false when the buffer is full; the caller should return HTTP 503.
// When maxPending<=0, backpressure is disabled and it always returns true.
func (rb *RecordBuffer) Add(rec *db.CertRecord) bool {
	return rb.add(CertItem(rec))
}

// add appends a single item to the buffer.
// Returns false when the buffer is full; the caller should return HTTP 503.
// When maxPending<=0, backpressure is disabled and it always returns true.
func (rb *RecordBuffer) add(item Item) bool {
	if rb.maxPending > 0 && rb.pending.Load() >= rb.maxPending {
		return false
	}

	// json.Marshal outside the lock (reduces lock hold time)
	var line []byte
	if rb.walBuf != nil {
		line, _ = json.Marshal(walLine{Kind: kindOf(item), Cert: item.Cert, Nonce: item.Nonce})
	}

	rb.mu.Lock()
	rb.records = append(rb.records, item)
	n := len(rb.records)
	rb.mu.Unlock()
	rb.pending.Add(1)

	// Periodic fsync (outside rb.mu, guarded by walMu so it never overlaps the
	// drain goroutine's flushLocked or AddDANonceSync on the same bufio/file).
	if rb.walBuf != nil {
		rb.walMu.Lock()
		if line != nil {
			rb.walBuf.Write(line)
			rb.walBuf.WriteByte('\n')
		}
		rb.fsyncCnt++
		if rb.fsyncCnt%fsyncEveryNRecords == 0 || time.Since(rb.lastFsync) > fsyncMaxInterval {
			rb.walBuf.Flush()
			rb.walFile.Sync()
			rb.lastFsync = time.Now()
		}
		rb.walMu.Unlock()
	}

	if n >= rb.threshold {
		select {
		case rb.flushCh <- struct{}{}:
		default:
		}
	}
	return true
}

func kindOf(item Item) string {
	switch item.Kind {
	case KindDANonce:
		return "da_nonce"
	default:
		return "cert"
	}
}

// AddDANonce buffers a DelegationAuthorization nonce into the batch write
// pipeline for batched persistence (BulkStoreDANonces on the next flush), the
// convergence model used by certificates and one-time nonces. Memory is
// authoritative for replay checks, so a nonce stored here is immediately
// visible to the engine even before the backend catches up.
//
// Unlike AddDANonceSync this performs no synchronous WAL/DB I/O: use it only
// when the buffer has no WAL (non-file backends such as PostgreSQL/MySQL),
// where a synchronous per-nonce INSERT was the per-request throughput wall
// under AIC load. A full buffer is force-flushed first so the security-critical
// nonce is never rejected (same guarantee as AddDANonceSync). Crash safety for
// unflushed nonces is sacrificed by design on WAL-less backends — the backend
// table converges on the next bulk flush.
func (rb *RecordBuffer) AddDANonce(nonce []byte) error {
	if len(nonce) != 32 {
		return fmt.Errorf("add_da_nonce: nonce must be 32 bytes, got %d", len(nonce))
	}
	// Wait for the drain loop to free capacity instead of force-flushing
	// synchronously: a request-path FlushAll under a full buffer thundering-herds
	// every caller onto flushMu and freezes the server. A bounded wait keeps the
	// nonce accepted whenever capacity can be freed in time; otherwise
	// ErrBackpressure propagates so the caller returns 503 (issuance fails, so no
	// certificate is minted and replay protection is never weakened).
	if err := rb.waitForCapacity(); err != nil {
		return err
	}

	rb.mu.Lock()
	rb.records = append(rb.records, DANonceItem(nonce))
	rb.mu.Unlock()
	rb.pending.Add(1)

	// Signal the drain loop so the batch converges to the DB promptly.
	select {
	case rb.flushCh <- struct{}{}:
	default:
	}
	return nil
}

// AddDANonceSync buffers a DelegationAuthorization nonce and synchronously
// fsyncs the WAL before returning. DA nonce replay protection requires the
// nonce to be durable once the caller's AIC issuance is acknowledged; the
// periodic fsync (every N records) is not sufficient for that guarantee.
//
// The backend da_nonces table converges via the same batch pipeline on the
// next flush. When the buffer is full, it waits for the drain loop to free
// capacity (bounded) instead of force-flushing, so a full buffer never
// thundering-herds request goroutines onto flushMu. Returns ErrWALDisabled when
// the buffer has no WAL (use AddDANonce for the WAL-less batch path instead).
func (rb *RecordBuffer) AddDANonceSync(nonce []byte) error {
	if rb.walFile == nil {
		return ErrWALDisabled
	}
	if len(nonce) != 32 {
		return fmt.Errorf("add_da_nonce: nonce must be 32 bytes, got %d", len(nonce))
	}
	if err := rb.waitForCapacity(); err != nil {
		return err
	}

	line, err := json.Marshal(walLine{Kind: "da_nonce", Nonce: nonce})
	if err != nil {
		return err
	}

	rb.mu.Lock()
	rb.records = append(rb.records, DANonceItem(nonce))
	rb.mu.Unlock()
	rb.pending.Add(1)

	// Append to the WAL and sync it before returning, all under walMu so this
	// never overlaps the drain goroutine's flushLocked or another writer on the
	// same bufio/file. On failure, roll back the in-memory entry so the
	// caller's engine can drop its memory reservation.
	rb.walMu.Lock()
	rb.walBuf.Write(line)
	rb.walBuf.WriteByte('\n')
	if err := rb.walBuf.Flush(); err != nil {
		rb.walMu.Unlock()
		rb.rollbackLast()
		return err
	}
	if err := rb.walFile.Sync(); err != nil {
		rb.walMu.Unlock()
		rb.rollbackLast()
		return err
	}
	rb.walMu.Unlock()

	// Signal the drain loop so the batch converges to the DB promptly.
	select {
	case rb.flushCh <- struct{}{}:
	default:
	}
	return nil
}

// rollbackLast removes the most recently appended item (used when a
// synchronous WAL fsync fails).
func (rb *RecordBuffer) rollbackLast() {
	rb.mu.Lock()
	if len(rb.records) > 0 {
		rb.records = rb.records[:len(rb.records)-1]
	}
	rb.mu.Unlock()
	rb.pending.Add(-1)
	rb.capacity.signal()
}

func (rb *RecordBuffer) flush() {
	rb.flushMu.Lock()
	defer rb.flushMu.Unlock()
	rb.flushLocked()
}

// flushLocked performs one flush pass. Callers must hold flushMu.
func (rb *RecordBuffer) flushLocked() {
	flushStart := time.Now()
	rb.mu.Lock()
	if len(rb.records) == 0 {
		rb.mu.Unlock()
		return
	}
	n := len(rb.records)
	batch := make([]Item, n)
	copy(batch, rb.records)
	rb.mu.Unlock()

	d := rb.db()
	if d == nil {
		return
	}

	// Split the snapshot into per-kind groups; each group persists in one
	// batched statement (certificates + DA nonces).
	var certs []*db.CertRecord
	var nonces [][]byte
	for _, it := range batch {
		switch it.Kind {
		case KindCert:
			certs = append(certs, it.Cert)
		case KindDANonce:
			nonces = append(nonces, it.Nonce)
		}
	}

	// Bound the backend writes by a context so a hung connection (half-open
	// socket during a chunk INSERT) surfaces as an error that the drain loop
	// retries on a fresh connection instead of holding flushMu forever.
	ctx, cancel := context.WithTimeout(context.Background(), flushDBTimeout)
	defer cancel()

	var err error
	if len(certs) > 0 {
		_, err = d.BulkInsertCertRecordsCtx(ctx, certs)
	}
	if err == nil && len(nonces) > 0 {
		_, err = d.BulkStoreDANoncesCtx(ctx, nonces)
	}
	if err != nil {
		slog.Warn("record_buffer: bulk write failed", "n", len(batch), "error", err)
		return
	}
	if dur := time.Since(flushStart); dur > 50*time.Millisecond {
		slog.Info("record_buffer: slow flush", "n", n, "dur_ms", dur.Milliseconds(), "pending", rb.pending.Load())
	}
	rb.recordFlushStats(time.Since(flushStart))

	// Flush succeeded: remove flushed records from the in-memory buffer.
	rb.mu.Lock()
	if len(rb.records) >= n {
		rb.records = rb.records[n:]
	} else {
		rb.records = nil
	}
	rb.mu.Unlock()
	rb.pending.Add(-int32(n))
	rb.capacity.signal()

	// Truncate the WAL when all records have been flushed to prevent unbounded WAL
	// growth (on crash restart the entire file would be replayed, and a huge history
	// would slow startup). Concurrent Add only writes to the bufio in-memory buffer
	// (unless periodic fsync triggers), so truncating the file does not affect
	// unflushed records: they are rewritten from offset 0 on the next flush.
	// All WAL file/bufio ops take walMu (Add/AddDANonceSync too).
	if rb.pending.Load() == 0 && rb.walFile != nil {
		rb.walMu.Lock()
		rb.walBuf.Flush()
		rb.walFile.Truncate(0)
		rb.walFile.Seek(0, io.SeekStart)
		rb.walMu.Unlock()
	}
	slog.Debug("record_buffer: flushed", "n", n)
}

// FlushAll synchronously flushes all buffered records to the DB and fsyncs
// the WAL. Used before read-modify-write operations (e.g. revocation) so
// that recently issued-but-unflushed certificates are visible to the DB,
// avoiding the ≤500ms visibility window between issue and bulk insert.
func (rb *RecordBuffer) FlushAll() {
	rb.flushMu.Lock()
	defer rb.flushMu.Unlock()
	rb.flushLocked()
	if rb.walBuf != nil {
		rb.walMu.Lock()
		rb.walBuf.Flush()
		rb.walFile.Sync()
		rb.walMu.Unlock()
	}
}

func (rb *RecordBuffer) run(ctx context.Context) {
	flushTicker := time.NewTicker(rb.maxLatency)
	defer flushTicker.Stop()
	// Checkpoint runs on its own independent cycle: under high throughput, the WAL
	// grows quickly, but checkpoint blocks all writes when the WAL is large (merging
	// hundreds of MB into the main database file). Running it under load would stall
	// the drain loop → 503 storm. Checkpoint only when the buffer is idle (pending==0):
	// at that point there are no pending records, so merging the WAL does not block
	// any requests.
	ckptTicker := time.NewTicker(checkpointInterval)
	defer ckptTicker.Stop()
	for {
		select {
		case <-rb.flushCh:
			rb.drain()
		case <-flushTicker.C:
			rb.drain()
		case <-ckptTicker.C:
			if rb.pending.Load() == 0 {
				if d := rb.db(); d != nil {
					d.CheckpointWAL()
				}
			}
		case <-ctx.Done():
			rb.FlushAll()
			if rb.walFile != nil {
				rb.walMu.Lock()
				rb.walFile.Close()
				rb.walMu.Unlock()
			}
			return
		}
	}
}

// drain continuously flushes until the pending record count drops below threshold.
// flushCh is a capacity-1 channel; under high throughput, signals are lost (during
// an ongoing flush). If only one flush is triggered before waiting for the maxLatency
// ticker, the drain frequency is capped at ~2/s with a few hundred records per batch,
// throttling throughput to ~1K/s — far below BulkInsert's actual capability (~30K/s).
// Continuous draining eliminates this rate limit.
func (rb *RecordBuffer) drain() {
	for {
		rb.flush()
		if rb.pending.Load() < int32(rb.threshold) {
			return
		}
	}
}

// Stop stops the background goroutine, flushes remaining records, and closes the
// WAL. It synchronously waits for the background goroutine to exit before returning,
// ensuring the WAL lock has been released (engine/recordbuffer are mutually exclusive
// across processes).
func (rb *RecordBuffer) Stop() {
	rb.cancel()
	rb.wg.Wait()
}
