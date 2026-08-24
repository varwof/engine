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

// benchScaleMultiCA simulates a large enterprise with N departments, each with
// its own sub-CA and perDept resident certs. It measures insertIfAbsent into a
// randomly chosen department's CA. The per-CA heap makes per-issue cost depend
// on ONE department's size, not the global total — this bench proves it.
func benchScaleMultiCA(b *testing.B, nCA, perDept, parallel int) {
	b.Helper()
	idx := NewCertIndex()
	now := time.Now()
	for d := 0; d < nCA; d++ {
		ca := fmt.Sprintf("Dept %02d CA", d)
		for i := 0; i < perDept; i++ {
			idx.put(&db.CertRecord{
				SerialNumber: fmt.Sprintf("%X", i),
				CAName:       ca,
				Status:       "V",
				CommonName:   "prefill.example.com",
				NotBefore:    now.Add(-time.Hour),
				NotAfter:     now.Add(365 * 24 * time.Hour),
				IssuerDN:     "CN=Bench CA,O=Test",
				SPKIHash:     "spki-bench",
			})
		}
	}
	b.ResetTimer()
	var counter atomic.Int64
	run := func() {
		i := counter.Add(1)
		d := int(i) % nCA
		ca := fmt.Sprintf("Dept %02d CA", d)
		rec := &db.CertRecord{
			SerialNumber: fmt.Sprintf("%X", i),
			CAName:       ca,
			Status:       "V",
			CommonName:   "bench.example.com",
			NotBefore:    now,
			NotAfter:     now.Add(365 * 24 * time.Hour),
			IssuerDN:     "CN=Bench CA,O=Test",
			SPKIHash:     "spki-bench",
		}
		idx.insertIfAbsent(rec, 500_000_000, 0, now)
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

// 40 departments, each 10K certs (400K global) — dept size is the workload.
func BenchmarkMultiCA_40x10K(t *testing.B)     { benchScaleMultiCA(t, 40, 10000, 1) }
func BenchmarkMultiCA_40x10K_p16(t *testing.B) { benchScaleMultiCA(t, 40, 10000, 16) }
func BenchmarkMultiCA_40x100K(t *testing.B)    { benchScaleMultiCA(t, 40, 100000, 1) }

// 200 departments, each 2.5K certs (500K global) — many small depts.
func BenchmarkMultiCA_200x2500(t *testing.B) { benchScaleMultiCA(t, 200, 2500, 1) }
