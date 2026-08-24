// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func revokedCert(serial int, ca string, revokedAt time.Time, notAfter time.Time) *db.CertRecord {
	r := makeCert(int64(serial), fmt.Sprintf("rev%d.example.com", serial), notAfter)
	r.Status = "R"
	r.CAName = ca
	ra := revokedAt
	r.RevokedAt = &ra
	return r
}

func TestRevokedSetMaxPerCAEviction(t *testing.T) {
	now := time.Now()
	s := NewRevokedSet(3)
	recs := make([]*db.CertRecord, 0, 5)
	for i := 1; i <= 5; i++ {
		recs = append(recs, revokedCert(i, "issuing", now.Add(-time.Duration(i)*time.Hour), now.Add(time.Hour)))
	}
	for _, r := range recs {
		s.put(r)
	}
	if s.Len() != 3 {
		t.Fatalf("expected 3 entries after eviction, got %d", s.Len())
	}
	entries := s.entries("issuing")
	if len(entries) != 3 {
		t.Fatalf("expected 3 order entries, got %d", len(entries))
	}
	// Newest-revoked (serial 1, revoked_at most recent) survive; oldest
	// (serial 4, 5) are evicted from the CRL window.
	for _, r := range entries {
		if r.SerialNumber == "4" || r.SerialNumber == "5" {
			t.Fatalf("oldest-revoked %s should have been evicted", r.SerialNumber)
		}
	}
	// Descending order is preserved after eviction.
	for i := 1; i < len(entries); i++ {
		if entries[i-1].RevokedAt.Before(*entries[i].RevokedAt) {
			t.Fatal("order not descending after eviction")
		}
	}
}

func TestRevokedSetPutAllMaxPerCAEviction(t *testing.T) {
	now := time.Now()
	s := NewRevokedSet(2)
	recs := make([]*db.CertRecord, 0, 5)
	for i := 1; i <= 5; i++ {
		recs = append(recs, revokedCert(i, "issuing", now.Add(-time.Duration(i)*time.Hour), now.Add(time.Hour)))
	}
	s.putAll(recs)
	if s.Len() != 2 {
		t.Fatalf("expected 2 entries after putAll eviction, got %d", s.Len())
	}
	entries := s.entries("issuing")
	if len(entries) != 2 || entries[0].SerialNumber != "1" || entries[1].SerialNumber != "2" {
		t.Fatalf("unexpected survivors: %v %v", entries[0].SerialNumber, entries[1].SerialNumber)
	}
}

func TestRevokedSetPruneExpiredRebuildOrder(t *testing.T) {
	now := time.Now()
	s := NewRevokedSet(0)
	// All valid at insert time; some expire when the janitor clock advances.
	recs := []*db.CertRecord{
		revokedCert(1, "issuing", now.Add(-5*time.Hour), now.Add(30*time.Minute)),
		revokedCert(2, "issuing", now.Add(-4*time.Hour), now.Add(3*time.Hour)),
		revokedCert(3, "issuing", now.Add(-3*time.Hour), now.Add(45*time.Minute)),
		revokedCert(4, "issuing", now.Add(-2*time.Hour), now.Add(2*time.Hour)),
		revokedCert(5, "other", now.Add(-time.Hour), now.Add(4*time.Hour)),
	}
	s.putAll(recs)
	if s.Len() != 5 {
		t.Fatalf("setup: expected 5, got %d", s.Len())
	}
	if n := s.pruneExpired(now.Add(time.Hour)); n != 2 {
		t.Fatalf("expected 2 pruned, got %d", n)
	}
	if s.Len() != 3 {
		t.Fatalf("expected 3 after prune, got %d", s.Len())
	}
	// Surviving order must stay revoked_at-desc and consistent with byCA.
	for _, ca := range []string{"issuing", "other"} {
		entries := s.entries(ca)
		for i := 1; i < len(entries); i++ {
			if entries[i-1].RevokedAt.Before(*entries[i].RevokedAt) {
				t.Fatalf("%s order not descending after prune", ca)
			}
		}
	}
	if _, ok := s.byCA["issuing"]; !ok {
		t.Fatal("issuing CA entry missing after prune")
	}
	if len(s.byCA["issuing"]) != 2 {
		t.Fatalf("expected 2 issuing survivors, got %d", len(s.byCA["issuing"]))
	}
}
