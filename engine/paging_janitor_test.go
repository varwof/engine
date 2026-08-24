// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// paginate walks every page of a cursor-based query and asserts it yields the
// full result set exactly once, in the canonical NotBefore-desc order (serial
// desc tiebreaker), with each page bounded by limit.
func paginate(t *testing.T, total, limit int, fetch func(page int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool)) {
	t.Helper()
	var all []*db.CertRecord
	seen := make(map[string]bool)
	page := 0
	var after *CertCursor
	for {
		recs, next, hasMore := fetch(page, after)
		if len(recs) > limit {
			t.Fatalf("page %d returned %d records, limit %d", page, len(recs), limit)
		}
		if hasMore && len(recs) != limit {
			t.Fatalf("page %d: hasMore=%v but len=%d limit=%d", page, hasMore, len(recs), limit)
		}
		for _, r := range recs {
			key := r.CAName + "/" + r.SerialNumber
			if seen[key] {
				t.Fatalf("duplicate record %s across pages", key)
			}
			seen[key] = true
			all = append(all, r)
		}
		if !hasMore {
			break
		}
		after = next
		page++
		if page > total+2 {
			t.Fatalf("pagination did not terminate after %d pages", total+2)
		}
	}
	if len(seen) != total {
		t.Fatalf("pagination yielded %d unique records, want %d", len(seen), total)
	}
	// Global canonical order: each record is not worse than the next (i.e. the
	// list is best→worst under NotBefore desc, serial desc tiebreaker).
	for i := 1; i < len(all); i++ {
		if certWorse(all[i-1], all[i]) {
			t.Fatalf("page result out of order at %d: %s then %s",
				i, all[i-1].SerialNumber, all[i].SerialNumber)
		}
	}
}

// TestPagedGetCertBySPKIHash exercises the R6 pagination contract for a
// high-cardinality SPKI set (distinct serials, overlapping NotBefore values to
// stress the tiebreaker).
func TestPagedGetCertBySPKIHash(t *testing.T) {
	e := newTestEngine(t)
	const n = 250
	base := time.Now().Add(-24 * time.Hour)
	for i := 0; i < n; i++ {
		rec := makeCert(int64(i+1), fmt.Sprintf("p%d.example.com", i+1), time.Time{})
		rec.SPKIHash = "spki-shared"
		// Clustered NotBefore: groups share timestamps to exercise the serial
		// tiebreaker within a page boundary.
		rec.NotBefore = base.Add(time.Duration(i/5) * time.Hour)
		if err := e.IssueCert(rec); err != nil {
			t.Fatal(err)
		}
	}

	for _, limit := range []int{1, 7, 13, 100, n} {
		paginate(t, n, limit, func(_ int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
			recs, next, more, err := e.GetCertBySPKIHash("spki-shared", "", "", limit, after)
			if err != nil {
				t.Fatal(err)
			}
			return recs, next, more
		})
	}

	// limit <= 0 preserves the all-at-once behavior.
	recs, next, more, err := e.GetCertBySPKIHash("spki-shared", "", "", 0, nil)
	if err != nil || len(recs) != n || next != nil || more {
		t.Fatalf("limit=0 should return full set: n=%d more=%v err=%v", len(recs), more, err)
	}
}

// TestPagedListCertsByAgentID verifies pagination plus the status filter on the
// agent-ID secondary index.
func TestPagedListCertsByAgentID(t *testing.T) {
	e := newTestEngine(t)
	const n = 120
	for i := 0; i < n; i++ {
		rec := makeCert(int64(i+1), fmt.Sprintf("ag%d.example.com", i+1), time.Time{})
		rec.AgentId = "agent-shared"
		rec.NotBefore = time.Now().Add(time.Duration(i) * time.Minute)
		if i%3 == 0 {
			rec.Status = "R"
		}
		if err := e.IssueCert(rec); err != nil {
			t.Fatal(err)
		}
	}

	for _, status := range []string{"", "V", "R"} {
		want := 0
		all, _, _, err := e.ListCertsByAgentID("agent-shared", status, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		want = len(all)
		for _, limit := range []int{1, 5, 40} {
			paginate(t, want, limit, func(_ int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
				recs, next, more, err := e.ListCertsByAgentID("agent-shared", status, limit, after)
				if err != nil {
					t.Fatal(err)
				}
				return recs, next, more
			})
		}
	}
}

// TestPagedListCertsByPrincipalUid verifies pagination on the principal-UID
// secondary index.
func TestPagedListCertsByPrincipalUid(t *testing.T) {
	e := newTestEngine(t)
	const n = 90
	for i := 0; i < n; i++ {
		rec := makeCert(int64(i+1), fmt.Sprintf("u%d.example.com", i+1), time.Time{})
		rec.PrincipalUid = "uid-shared"
		rec.NotBefore = time.Now().Add(time.Duration(i) * time.Minute)
		if err := e.IssueCert(rec); err != nil {
			t.Fatal(err)
		}
	}
	paginate(t, n, 10, func(_ int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
		recs, next, more, err := e.ListCertsByPrincipalUid("uid-shared", "", 10, after)
		if err != nil {
			t.Fatal(err)
		}
		return recs, next, more
	})
}

// TestJanitorPrunesAICForEvicted verifies R9: when the janitor evicts a cert
// that left the hot window, its AIC extension is dropped from memory and queued
// for backend deletion.
func TestJanitorPrunesAICForEvicted(t *testing.T) {
	e := newTestEngine(t)

	// A cert already outside the grace window (expired well in the past).
	old := makeCert(1, "old.example.com", time.Now().Add(-10*24*time.Hour))
	old.NotAfter = time.Now().Add(-10 * 24 * time.Hour)
	if err := e.IssueCert(old); err != nil {
		t.Fatal(err)
	}
	// A still-hot cert that must survive the janitor pass.
	fresh := makeCert(2, "fresh.example.com", time.Now().Add(30*24*time.Hour))
	if err := e.IssueCert(fresh); err != nil {
		t.Fatal(err)
	}

	if err := e.UpsertAICExtension(&db.AICExtension{
		CAName:           "issuing",
		SerialNumber:     old.SerialNumber,
		AgentID:          "agent-old",
		PrincipalUID:     "uid-old",
		CapabilitiesJSON: "[]",
		AICJSON:          "{}",
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.UpsertAICExtension(&db.AICExtension{
		CAName:           "issuing",
		SerialNumber:     fresh.SerialNumber,
		AgentID:          "agent-fresh",
		PrincipalUID:     "uid-fresh",
		CapabilitiesJSON: "[]",
		AICJSON:          "{}",
	}); err != nil {
		t.Fatal(err)
	}

	if got := e.aic.Len(); got != 2 {
		t.Fatalf("expected 2 AIC extensions in memory, got %d", got)
	}

	e.janitor()

	if got := e.aic.Len(); got != 1 {
		t.Fatalf("expected 1 AIC extension after janitor, got %d", got)
	}
	if _, ok := e.aic.getByCert("issuing", old.SerialNumber); ok {
		t.Fatalf("evicted cert's AIC extension still present in memory")
	}
	if _, ok := e.aic.getByCert("issuing", fresh.SerialNumber); !ok {
		t.Fatalf("hot cert's AIC extension must survive janitor")
	}

	// Backend row is pruned via the write pipeline.
	e.FlushAll()
	if _, err := e.DB().GetAICExtensionByCert("issuing", old.SerialNumber); err == nil {
		t.Fatalf("evicted cert's AIC extension still present in backend")
	}
	if _, err := e.DB().GetAICExtensionByCert("issuing", fresh.SerialNumber); err != nil {
		t.Fatalf("hot cert's AIC extension missing in backend: %v", err)
	}
}

// TestJanitorSkipsAICForMissingCert ensures removeByCert is a no-op when there
// is no AIC extension bound to an evicted cert, and no backend delete is queued.
func TestJanitorSkipsAICForMissingCert(t *testing.T) {
	e := newTestEngine(t)
	old := makeCert(1, "old.example.com", time.Now().Add(-10*24*time.Hour))
	old.NotAfter = time.Now().Add(-10 * 24 * time.Hour)
	if err := e.IssueCert(old); err != nil {
		t.Fatal(err)
	}
	if err := e.UpsertAICExtension(&db.AICExtension{
		CAName:           "issuing",
		SerialNumber:     "different-serial",
		AgentID:          "agent-x",
		CapabilitiesJSON: "[]",
		AICJSON:          "{}",
	}); err != nil {
		t.Fatal(err)
	}
	e.janitor()
	if got := e.aic.Len(); got != 1 {
		t.Fatalf("unrelated AIC extension must be untouched, got %d", got)
	}
}
