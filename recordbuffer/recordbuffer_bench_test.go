// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package recordbuffer

import (
	"fmt"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func benchRecord(serial int) *db.CertRecord {
	now := time.Now()
	rec := &db.CertRecord{
		SerialNumber: fmt.Sprintf("%X", serial),
		CAName:       "issuing",
		Status:       "V",
		Subject:      "CN=bench.example.com,O=test",
		CommonName:   "bench.example.com",
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		IssuerDN:     "CN=Bench CA,O=Test",
		SPKIHash:     "spki-bench",
		CertDER:      []byte("fake-der"),
	}
	rec.Fingerprint = db.Fingerprint(rec.CertDER)
	return rec
}

// BenchmarkRecordBufferAdd measures the pure in-memory buffering path (no WAL,
// no flush): pending check + append under mutex. Threshold/maxPending are set
// high and the db getter returns nil so nothing flushes during the timed loop.
func BenchmarkRecordBufferAdd(b *testing.B) {
	rb, err := NewRecordBuffer(func() *db.DB { return nil }, 1<<30, 1<<30, time.Hour, "")
	if err != nil {
		b.Fatal(err)
	}
	defer rb.Stop()
	rec := benchRecord(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !rb.Add(rec) {
			b.Fatal("buffer full")
		}
	}
}

// BenchmarkRecordBufferAddWAL measures the buffering path with the WAL pre-write
// log enabled: JSON marshal outside the lock + bufio write + periodic fsync
// (every 100 records) under load.
func BenchmarkRecordBufferAddWAL(b *testing.B) {
	rb, err := NewRecordBuffer(func() *db.DB { return nil },
		1<<30, 1<<30, time.Hour, b.TempDir()+"/bench.wal")
	if err != nil {
		b.Fatal(err)
	}
	defer rb.Stop()
	rec := benchRecord(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !rb.Add(rec) {
			b.Fatal("buffer full")
		}
	}
}

// BenchmarkRecordBufferFlushBatch measures the end-to-end path for a typical
// batch: add threshold (100) records, then FlushAll to a real SQLite backend.
func BenchmarkRecordBufferFlushBatch(b *testing.B) {
	d, err := db.Open(b.TempDir() + "/test.db")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { d.Close() })
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 100, 1<<20, time.Hour, "")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(rb.Stop)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			if !rb.Add(benchRecord(i*100 + j)) {
				b.Fatal("buffer full")
			}
		}
		rb.FlushAll()
	}
	if rb.Pending() != 0 {
		b.Fatalf("expected empty buffer after FlushAll, pending=%d", rb.Pending())
	}
}
