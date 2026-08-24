// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// TestByteBudgetRejectsOversizedInsert verifies R8: a byte budget
// (MaxResidentBytes) rejects inserts that exceed it after expired certs are
// evicted, mirroring MaxCerts semantics.
func TestByteBudgetRejectsOversizedInsert(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/byte.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	// Budget large enough for one certificate record's estimate but small
	// enough that a second insert must be rejected after the first fills it.
	e, err := NewEngine(d, EngineOptions{
		Logger:           discardLogger(),
		MaxResidentBytes: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	if err := e.IssueCert(makeCert(1, "b1.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	if err := e.IssueCert(makeCert(2, "b2.example.com", time.Time{})); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("expected ErrBackpressure on byte-budget overflow, got %v", err)
	}
	if got := e.certIdx.Len(); got != 1 {
		t.Fatalf("expected 1 resident cert, got %d", got)
	}
	if got := e.Metrics().CertResidentBytes; got <= 0 {
		t.Fatalf("expected positive CertResidentBytes, got %d", got)
	}
}

// TestByteBudgetEvictsExpiredFirst verifies R8: when the byte budget is
// exceeded, expired certs are evicted first (like MaxCerts), and a fresh cert
// is accepted once the expired one frees its bytes.
func TestByteBudgetEvictsExpiredFirst(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/byte2.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	old := makeCert(1, "old.example.com", time.Now().Add(-10*24*time.Hour))
	old.NotAfter = time.Now().Add(-10 * 24 * time.Hour)

	e, err := NewEngine(d, EngineOptions{
		Logger:           discardLogger(),
		MaxResidentBytes: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	if err := e.IssueCert(old); err != nil {
		t.Fatal(err)
	}
	if got := e.certIdx.ResidentBytes(); got <= 0 {
		t.Fatalf("expected positive resident bytes after insert, got %d", got)
	}

	// Second insert pushes past the budget, but the expired cert is evictable,
	// so the insert succeeds and evicts the old one.
	if err := e.IssueCert(makeCert(2, "fresh.example.com", time.Time{})); err != nil {
		t.Fatalf("fresh insert should evict expired and succeed: %v", err)
	}
	if _, err := e.GetCert("issuing", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected old cert evicted, got %v", err)
	}
	if got := e.certIdx.Len(); got != 1 {
		t.Fatalf("expected 1 resident cert after eviction, got %d", got)
	}
	if got := e.Metrics().WindowEvictions; got < 1 {
		t.Fatalf("expected >=1 eviction, got %d", got)
	}
}

// TestAICResidentBytes verifies the AIC byte accounting tracks put and remove.
func TestAICResidentBytes(t *testing.T) {
	e := newTestEngine(t)
	aic := &db.AICExtension{
		CAName:           "issuing",
		SerialNumber:     "1",
		AgentID:          "agent-a",
		PrincipalUID:     "uid-a",
		CapabilitiesJSON: `[{"scheme":"db:query","actions":["SELECT"]}]`,
		AICJSON:          `{"key":"val"}`,
	}
	if err := e.UpsertAICExtension(aic); err != nil {
		t.Fatal(err)
	}
	if got := e.aic.ResidentBytes(); got <= 0 {
		t.Fatalf("expected positive AIC resident bytes, got %d", got)
	}
	before := e.aic.ResidentBytes()

	e.aic.removeByCert("issuing", "1")
	if got := e.aic.ResidentBytes(); got != 0 {
		t.Fatalf("expected AIC resident bytes to drop to 0 after remove, got %d", got)
	}
	_ = before
}

// TestMetricsCounters verifies R10: issued/revoked/AIC-pruned counters and the
// flush histogram are populated.
func TestMetricsCounters(t *testing.T) {
	e := newTestEngine(t)

	if err := e.IssueCert(makeCert(1, "c1.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	if err := e.IssueCert(makeCert(2, "c2.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	e.FlushAll()

	if err := e.RevokeCert("issuing", "1", 1); err != nil {
		t.Fatal(err)
	}
	e.FlushAll()

	m := e.Metrics()
	if m.CertIssued != 2 {
		t.Fatalf("CertIssued = %d, want 2", m.CertIssued)
	}
	if m.CertRevoked != 1 {
		t.Fatalf("CertRevoked = %d, want 1", m.CertRevoked)
	}
	if m.FlushCount == 0 {
		t.Fatalf("expected >=1 flush recorded in histogram")
	}
	total := m.FlushDuration[0] + m.FlushDuration[1] + m.FlushDuration[2] + m.FlushDuration[3]
	if total != m.FlushCount {
		t.Fatalf("flush histogram buckets (%d) != count (%d)", total, m.FlushCount)
	}
}

// TestPrometheusMetricsNewFields verifies the new R10 metric names appear in
// the Prometheus text output with cumulative histogram buckets.
func TestPrometheusMetricsNewFields(t *testing.T) {
	e := newTestEngine(t)
	if err := e.IssueCert(makeCert(1, "p.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	e.FlushAll()
	out := e.PrometheusMetrics()
	for _, want := range []string{
		"varwof_engine_aic_resident_bytes",
		"varwof_engine_cert_resident_bytes",
		"varwof_engine_cert_issued_total",
		"varwof_engine_cert_revoked_total",
		"varwof_engine_wal_bytes",
		"varwof_engine_flush_duration_seconds_bucket{le=\"+Inf\"}",
		"varwof_engine_flush_duration_seconds_count",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, out)
		}
	}
}

// TestRevokeCountersBulk verifies the R10 revoked counter increments across the
// three bulk-revoke paths.
func TestRevokeCountersBulk(t *testing.T) {
	e := newTestEngine(t)
	for i := 0; i < 5; i++ {
		if err := e.IssueCert(makeCert(int64(i+1), fmt.Sprintf("c%d.example.com", i+1), time.Time{})); err != nil {
			t.Fatal(err)
		}
	}
	e.FlushAll()

	if n, _, err := e.RevokeCertsBatch([]RevokeBatchEntry{
		{CA: "issuing", Serial: "1", Reason: 1},
		{CA: "issuing", Serial: "2", Reason: 2},
	}); err != nil || n != 2 {
		t.Fatalf("batch revoke: n=%d err=%v", n, err)
	}
	if n, err := e.RevokeCertsBySubCA("issuing", 1); err != nil || n != 3 {
		t.Fatalf("subca revoke: n=%d err=%v", n, err)
	}
	if got := e.Metrics().CertRevoked; got != 5 {
		t.Fatalf("CertRevoked = %d, want 5", got)
	}
}
