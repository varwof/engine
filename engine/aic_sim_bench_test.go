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

// benchAICSim simulates the steady state of short-lived AIC certs under a
// large enterprise workload: a resident set at MaxCerts where roughly half
// have already expired past grace, plus continuous re-issue that keeps the
// index pinned at capacity and forces periodic eviction of the expired.
// This exercises the exact hot path a fleet of agents with minutes-to-hours
// certs hits: every insert near capacity triggers evictExpiredLocked.
func benchAICSim(b *testing.B, resident int) {
	b.Helper()
	idx := NewCertIndex()
	now := time.Now()
	cutoff := now.Add(-time.Hour) // grace = 1h, tuned for short-lived AIC
	for i := 0; i < resident; i++ {
		na := now.Add(time.Hour) // live short-lived cert
		if i%2 == 0 {
			na = now.Add(-2 * time.Hour) // expired beyond grace, awaiting eviction
		}
		idx.put(&db.CertRecord{
			SerialNumber: fmt.Sprintf("%X", i), CAName: "dept1", Status: "V",
			CommonName: "agent-aic.example.com", NotBefore: now.Add(-time.Hour),
			NotAfter: na, IssuerDN: "CN=Dept1,O=Bench", SPKIHash: "aic-spki",
		})
	}
	b.ResetTimer()
	var c atomic.Int64
	for i := 0; i < b.N; i++ {
		j := c.Add(1)
		rec := &db.CertRecord{
			SerialNumber: fmt.Sprintf("new-%X", j), CAName: "dept1", Status: "V",
			CommonName: "agent-aic.example.com", NotBefore: now,
			NotAfter: now.Add(time.Hour), IssuerDN: "CN=Dept1,O=Bench", SPKIHash: "aic-spki",
		}
		if _, _, _, err := idx.insertIfAbsent(rec, resident, 0, cutoff); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAICSim_200K(t *testing.B) { benchAICSim(t, 200_000) }
func BenchmarkAICSim_1M(t *testing.B)   { benchAICSim(t, 1_000_000) }
func BenchmarkAICSim_2M(t *testing.B)   { benchAICSim(t, 2_000_000) }
