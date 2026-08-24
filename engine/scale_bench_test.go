// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// benchScaleIndex pre-fills n certs into a bare CertIndex and measures
// insertIfAbsent throughput at that resident size (parallel=1 serial, else
// parallel goroutines). This isolates the index write-lock cost from the
// record-buffer / DB flush path.
func benchScaleIndex(b *testing.B, n, parallel int) {
	b.Helper()
	idx := NewCertIndex()
	now := time.Now()
	for i := 0; i < n; i++ {
		idx.put(&db.CertRecord{
			SerialNumber: fmt.Sprintf("%X", i),
			CAName:       "issuing",
			Status:       "V",
			CommonName:   "prefill.example.com",
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			IssuerDN:     "CN=Bench CA,O=Test",
			SPKIHash:     "spki-bench",
		})
	}
	b.ResetTimer()
	var counter atomic.Int64
	run := func() {
		i := counter.Add(1)
		rec := &db.CertRecord{
			SerialNumber: fmt.Sprintf("%X", i),
			CAName:       "issuing",
			Status:       "V",
			CommonName:   "bench.example.com",
			NotBefore:    now,
			NotAfter:     now.Add(365 * 24 * time.Hour),
			IssuerDN:     "CN=Bench CA,O=Test",
			SPKIHash:     "spki-bench",
		}
		idx.insertIfAbsent(rec, 50_000_000, 0, now)
	}
	if parallel > 1 {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				run()
			}
		})
		return
	}
	for i := 0; i < b.N; i++ {
		run()
	}
}

func BenchmarkIndexInsert_0(t *testing.B)        { benchScaleIndex(t, 0, 1) }
func BenchmarkIndexInsert_10K(t *testing.B)      { benchScaleIndex(t, 10000, 1) }
func BenchmarkIndexInsert_100K(t *testing.B)     { benchScaleIndex(t, 100000, 1) }
func BenchmarkIndexInsert_0_p16(t *testing.B)    { benchScaleIndex(t, 0, 16) }
func BenchmarkIndexInsert_10K_p16(t *testing.B)  { benchScaleIndex(t, 10000, 16) }
func BenchmarkIndexInsert_100K_p16(t *testing.B) { benchScaleIndex(t, 100000, 16) }
