// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// benchEvictMultiCA measures how long one janitor eviction pass holds the
// global write lock when a fraction of many departments' certs expire at once
// (e.g. all issued on the same day by a periodic provisioning job).
func benchEvictMultiCA(b *testing.B, nCA, perDept, expired int) {
	b.Helper()
	idx := NewCertIndex()
	now := time.Now()
	expiredTime := now.Add(-48 * time.Hour)
	for d := 0; d < nCA; d++ {
		ca := fmt.Sprintf("Dept %02d CA", d)
		for i := 0; i < perDept; i++ {
			notAfter := now.Add(365 * 24 * time.Hour)
			if i < expired {
				notAfter = expiredTime // this cert is already past its expiry window
			}
			idx.put(&db.CertRecord{
				SerialNumber: fmt.Sprintf("%X", i),
				CAName:       ca,
				Status:       "V",
				CommonName:   "prefill.example.com",
				NotBefore:    now.Add(-time.Hour),
				NotAfter:     notAfter,
				IssuerDN:     "CN=Bench CA,O=Test",
				SPKIHash:     "spki-bench",
			})
		}
	}
	cutoff := now.Add(-24 * time.Hour) // grace 24h
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx.evictExpired(cutoff)
	}
}

// 40 depts × 10K, 1K expired per dept → 40K evicted in one pass.
func BenchmarkEvict_40x10K_1Kexpired(t *testing.B) { benchEvictMultiCA(t, 40, 10000, 1000) }

// 40 depts × 10K, 10K expired per dept (all of one dept's batch) → 400K evicted.
func BenchmarkEvict_40x10K_10Kexpired(t *testing.B) { benchEvictMultiCA(t, 40, 10000, 10000) }
