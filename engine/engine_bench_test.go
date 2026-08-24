// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func benchEngine(b *testing.B, n int) *Engine {
	b.Helper()
	d, err := db.Open(b.TempDir() + "/test.db")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { d.Close() })
	e, err := NewEngine(d, EngineOptions{
		Logger:          slog.New(slog.DiscardHandler),
		WriteThreshold:  100000, // keep writes buffered so benchmarks measure memory only
		WriteMaxPending: 1 << 30,
		WriteMaxLatency: time.Hour, // only flush on Stop so the timed loop is pure memory
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(e.Stop)
	now := time.Now()
	for i := 0; i < n; i++ {
		rec := &db.CertRecord{
			SerialNumber: fmt.Sprintf("%X", i),
			CAName:       "issuing",
			Status:       "V",
			Subject:      "CN=bench.example.com,O=test",
			CommonName:   "bench.example.com",
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			IssuerDN:     "CN=Bench CA,O=Test",
			SPKIHash:     "spki-bench",
			CertDER:      []byte("der"),
		}
		rec.Fingerprint = db.Fingerprint(rec.CertDER)
		if err := e.IssueCert(rec); err != nil {
			b.Fatal(err)
		}
	}
	return e
}

func BenchmarkGetCertStatus(b *testing.B) {
	e := benchEngine(b, 10000)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := e.GetCertStatus("issuing", "1"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkGetCertStatusMiss(b *testing.B) {
	e := benchEngine(b, 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.GetCertStatus("issuing", "nope")
	}
}

func BenchmarkIssueCertMemory(b *testing.B) {
	e := benchEngine(b, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := makeCert(1, "bench.example.com", time.Time{})
		rec.SerialNumber = fmt.Sprintf("%X", i)
		rec.Fingerprint = db.Fingerprint(rec.CertDER)
		if err := e.IssueCert(rec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetRevokedCertEntries(b *testing.B) {
	e := benchEngine(b, 0)
	for i := 0; i < 10000; i++ {
		rec := makeCert(1, "rev.example.com", time.Time{})
		rec.SerialNumber = fmt.Sprintf("%X", i)
		rec.Fingerprint = db.Fingerprint(rec.CertDER)
		if err := e.IssueCert(rec); err != nil {
			b.Fatal(err)
		}
	}
	for i := 0; i < 10000; i++ {
		if err := e.RevokeCert("issuing", fmt.Sprintf("%X", i), 1); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.GetRevokedCertEntries("issuing"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConsumeNonce(b *testing.B) {
	e := benchEngine(b, 0)
	nonces := make([][]byte, 1024)
	for i := range nonces {
		nonces[i] = make([]byte, 16)
		for j := 0; j < 8; j++ {
			nonces[i][j] = byte((i >> (8 * j)) & 0xff)
		}
		if err := e.StoreNonce(nonces[i]); err != nil {
			b.Fatal(err)
		}
	}
	var idx int64
	var mu sync.Mutex
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			n := nonces[idx%int64(len(nonces))]
			idx++
			mu.Unlock()
			e.ConsumeNonce(n)
		}
	})
}

// BenchmarkRevokedSetPut vs PutAll shows the O(n²) → O(n log n) improvement
// for bulk revocations on the per-CA revoked_at-desc order slice.
func BenchmarkRevokedSetPut(b *testing.B) {
	for _, n := range []int{100, 1000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			recs := revokeBenchRecords(n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s := NewRevokedSet(0)
				for _, r := range recs {
					s.put(r)
				}
			}
		})
	}
}

func BenchmarkRevokedSetPutAll(b *testing.B) {
	for _, n := range []int{100, 1000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			recs := revokeBenchRecords(n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s := NewRevokedSet(0)
				s.putAll(recs)
			}
		})
	}
}

// BenchmarkRevokedSetPruneExpired measures a janitor cycle that expires every
// entry of a CA: the per-CA order slice is rebuilt in one O(n) pass.
func BenchmarkRevokedSetPruneExpired(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			now := time.Now()
			recs := make([]*db.CertRecord, 0, n)
			for i := 0; i < n; i++ {
				recs = append(recs, revokedCert(i, "issuing", now.Add(-time.Hour), now.Add(2*time.Hour)))
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s := NewRevokedSet(0)
				s.putAll(recs)
				s.pruneExpired(now.Add(time.Hour))
			}
		})
	}
}

func revokeBenchRecords(n int) []*db.CertRecord {
	now := time.Now()
	recs := make([]*db.CertRecord, 0, n)
	for i := 0; i < n; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		recs = append(recs, &db.CertRecord{
			SerialNumber: fmt.Sprintf("%d", i),
			CAName:       "ca",
			Status:       "R",
			RevokedAt:    &at,
			NotAfter:     now.Add(time.Hour),
		})
	}
	return recs
}
