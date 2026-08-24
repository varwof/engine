// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package recordbuffer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func testDB(t *testing.T) *db.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func rec(serial, cn string) *db.CertRecord {
	return &db.CertRecord{
		SerialNumber: serial,
		CAName:       "test",
		Status:       "V",
		Subject:      "CN=" + cn,
		CommonName:   cn,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		CertDER:      []byte("der-" + serial),
		Fingerprint:  "fp",
	}
}

// TestRecordBufferWALLockedCrossProcess verifies E02: a second process sharing
// the same DB directory must not be able to enable the engine/recordbuffer on
// the same WAL file (two writers truncating the same WAL corrupt it). The
// second open fails with ErrWALLocked, and releasing the first frees it.
func TestRecordBufferWALLockedCrossProcess(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "records.wal")
	d := testDB(t)

	first, err := NewRecordBuffer(func() *db.DB { return d }, 100, 1000, time.Second, walPath)
	if err != nil {
		t.Fatalf("first buffer: %v", err)
	}
	defer first.Stop()

	second, err := NewRecordBuffer(func() *db.DB { return d }, 100, 1000, time.Second, walPath)
	if err == nil {
		second.Stop()
		t.Fatal("second buffer on the same WAL should fail with ErrWALLocked")
	}
	if !errors.Is(err, ErrWALLocked) {
		t.Fatalf("second open error = %v, want ErrWALLocked", err)
	}

	// After releasing the first one, the WAL lock should be acquirable again (lock released with file close).
	first.Stop()
	third, err := NewRecordBuffer(func() *db.DB { return d }, 100, 1000, time.Second, walPath)
	if err != nil {
		t.Fatalf("third buffer after release: %v", err)
	}
	third.Stop()
}

func TestRecordBufferFlushByThreshold(t *testing.T) {
	d := testDB(t)
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 10, 1000, time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	for i := 0; i < 10; i++ {
		serial := "0000000000000000000000000000000000000" + fmt.Sprintf("%X", i)
		if !rb.Add(rec(serial, "alice")) {
			t.Fatal("Add rejected")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := d.CountCertsByCA("test", "")
		if n >= 10 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("records not flushed within 3s")
}

func TestRecordBufferBackpressure(t *testing.T) {
	d := testDB(t)
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 10, 1, 50*time.Millisecond, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()
	if !rb.Add(rec("1", "alice")) {
		t.Fatal("first Add should succeed")
	}
	if rb.Add(rec("2", "bob")) {
		t.Fatal("second Add should be rejected when maxPending is reached")
	}
	if !rb.IsFull() {
		t.Fatal("IsFull should be true at maxPending")
	}
}

func TestRecordBufferFlushAll(t *testing.T) {
	d := testDB(t)
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 100, 1000, time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()
	if !rb.Add(rec("00000000000000000000000000000000000000B2", "bob")) {
		t.Fatal("Add rejected")
	}
	rb.FlushAll()
	n, err := d.CountCertsByCA("test", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("FlushAll should persist immediately, got %d", n)
	}
}

// TestRecordBufferConcurrentFlushNoLoss verifies that overlapping flush()
// calls (from the background drain goroutine and a caller invoking FlushAll)
// never drop records from the buffer. Two concurrent flushes copy the same
// snapshot; without serialization the second may advance past records that
// were appended between the two copies, losing them before they reach the DB.
func TestRecordBufferConcurrentFlushNoLoss(t *testing.T) {
	d := testDB(t)
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 1000, 10000, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	const base = 200
	for iter := 0; iter < 30; iter++ {
		for i := 0; i < base; i++ {
			serial := fmt.Sprintf("conc%04d%04d", iter, i)
			if !rb.Add(rec(serial, "alice")) {
				t.Fatal("Add rejected")
			}
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			<-start
			rb.flush()
			wg.Done()
		}()
		go func() {
			<-start
			rb.flush()
			wg.Done()
		}()
		close(start)

		// Land a new record between the two copies and their re-advance.
		rb.Add(rec(fmt.Sprintf("conc%04dNEW", iter), "alice"))
		wg.Wait()
	}

	rb.FlushAll()
	rb.Stop()
	expected := 30 * (base + 1)
	got, err := d.CountCertsByCA("test", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Fatalf("concurrent flushes lost records: got %d, want %d", got, expected)
	}
}

func TestRecordBufferWALReplay(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "records.wal")
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Simulate a crash: write a record to the WAL file directly, as if the
	// buffer had been Add()ed but the process died before the graceful flush.
	rec := rec("00000000000000000000000000000000000000C3", "carol")
	line, _ := json.Marshal(rec)
	if err := os.WriteFile(walPath, append(line, '\n'), 0640); err != nil {
		t.Fatal(err)
	}

	rb, err := NewRecordBuffer(func() *db.DB { return d }, 100, 1000, time.Second, walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	// WAL replay runs during NewRecordBuffer → the record is already persisted
	n, err := d.CountCertsByCA("test", "")
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("WAL replay did not persist the record")
	}
}

// TestRecordBufferWALWritesAndTruncate exercises the live WAL write path:
// JSON buffering + periodic fsync in Add (every 100 records) and WAL truncation
// once the whole batch is flushed, keeping the WAL file bounded.
func TestRecordBufferWALWritesAndTruncate(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "records.wal")
	d := testDB(t)

	rb, err := NewRecordBuffer(func() *db.DB { return d }, 100, 10000, time.Hour, walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	// 250 records crosses the fsyncEveryNRecords boundary (fsync at 100, 200).
	for i := 0; i < 250; i++ {
		if !rb.Add(rec(fmt.Sprintf("%039X", i), fmt.Sprintf("host%d.example.com", i))) {
			t.Fatal("buffer full")
		}
	}
	rb.FlushAll()
	if rb.Pending() != 0 {
		t.Fatalf("expected empty buffer after FlushAll, pending=%d", rb.Pending())
	}

	n, err := d.CountCertsByCA("test", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 250 {
		t.Fatalf("expected 250 persisted, got %d", n)
	}
	fi, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Fatalf("WAL not truncated after flush, size=%d", fi.Size())
	}
}

// TestRecordBufferFlushByMaxLatency verifies the background goroutine's
// maxLatency ticker drains the buffer even when the threshold is never
// reached, enforcing the worst-case persistence delay.
func TestRecordBufferFlushByMaxLatency(t *testing.T) {
	d := testDB(t)
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 1<<30, 10000, 50*time.Millisecond, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	for i := 0; i < 10; i++ {
		serial := fmt.Sprintf("lat%04d", i)
		if !rb.Add(rec(serial, fmt.Sprintf("host%d.example.com", i))) {
			t.Fatal("Add rejected")
		}
	}
	if rb.Pending() != 10 {
		t.Fatalf("expected 10 pending, got %d", rb.Pending())
	}

	// Threshold (1<<30) can never be reached; only the latency ticker can drain.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rb.Pending() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if rb.Pending() != 0 {
		t.Fatal("maxLatency ticker did not drain the buffer")
	}
	n, err := d.CountCertsByCA("test", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("expected 10 persisted via maxLatency flush, got %d", n)
	}
}
