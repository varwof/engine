// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// TestIssueCertNilRecord covers the nil-record guard in IssueCert.
func TestIssueCertNilRecord(t *testing.T) {
	e := newTestEngine(t)
	if err := e.IssueCert(nil); err == nil {
		t.Fatal("expected error for nil record")
	}
}

// TestIssueCertCapacityBackpressure covers insertIfAbsent rejecting an insert
// when the index is at capacity and nothing is evictable.
func TestIssueCertCapacityBackpressure(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	e, err := NewEngine(d, EngineOptions{MaxCerts: 3, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	for i := int64(1); i <= 3; i++ {
		if err := e.IssueCert(makeCert(i, fmt.Sprintf("cap%d.example.com", i), time.Time{})); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	if err := e.IssueCert(makeCert(4, "overflow.example.com", time.Time{})); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("expected ErrBackpressure at capacity, got %v", err)
	}
	if m := e.Metrics(); m.WindowEvictions != 0 {
		t.Fatalf("no expired certs should be evictable, got %d evictions", m.WindowEvictions)
	}
}

// TestIssueCertEvictsExpiredAtCapacity covers the insert path that evicts an
// expired certificate to make room (the evicted>0 branch of IssueCert).
func TestIssueCertEvictsExpiredAtCapacity(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	e, err := NewEngine(d, EngineOptions{
		MaxCerts: 2,
		// Grace=0 would be replaced by the 24h default; a tiny positive value
		// keeps the eviction cutoff at ~now so a past NotAfter is evictable.
		Grace:  time.Nanosecond,
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	expired := makeCert(1, "expired.example.com", time.Now().Add(-2*time.Hour))
	if err := e.IssueCert(expired); err != nil {
		t.Fatal(err)
	}
	if err := e.IssueCert(makeCert(2, "fresh.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	// Third insert must evict the expired cert and succeed.
	if err := e.IssueCert(makeCert(3, "third.example.com", time.Time{})); err != nil {
		t.Fatalf("insert after eviction: %v", err)
	}
	if m := e.Metrics(); m.WindowEvictions != 1 {
		t.Fatalf("expected 1 eviction, got %d", m.WindowEvictions)
	}
	if _, err := e.GetCert("issuing", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired cert should have been evicted, got %v", err)
	}
	if _, err := e.GetCert("issuing", "3"); err != nil {
		t.Fatalf("new cert missing: %v", err)
	}
}

// TestRevokeCertCallback covers the OnCertRevoked callback for single and bulk
// revocations.
func TestRevokeCertCallback(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	var mu sync.Mutex
	var got []string
	e, err := NewEngine(d, EngineOptions{
		Logger: discardLogger(),
		OnCertRevoked: func(serial string) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, serial)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	if err := e.IssueCert(makeCert(1, "one.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeCert("issuing", "1", 1); err != nil {
		t.Fatal(err)
	}
	if got := callbackList(&mu, &got); len(got) != 1 || got[0] != "1" {
		t.Fatalf("single revoke callback = %v, want [1]", got)
	}

	// Bulk by principal UID: callback receives the empty-string marker.
	uidCert := makeCert(2, "uid.example.com", time.Time{})
	uidCert.PrincipalUid = "uid-bulk-cb"
	if err := e.IssueCert(uidCert); err != nil {
		t.Fatal(err)
	}
	if n, err := e.RevokeCertsByPrincipalUid("uid-bulk-cb", 1); err != nil || n != 1 {
		t.Fatalf("bulk uid: n=%d err=%v", n, err)
	}
	got = callbackList(&mu, &got)
	if len(got) != 2 || got[1] != "" {
		t.Fatalf("bulk uid callback = %v, want trailing empty marker", got)
	}

	// Bulk by sub-CA.
	if err := e.IssueCert(makeCert(3, "ca.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	if n, err := e.RevokeCertsBySubCA("issuing", 1); err != nil || n != 1 {
		t.Fatalf("bulk ca: n=%d err=%v", n, err)
	}
	got = callbackList(&mu, &got)
	if len(got) != 3 || got[2] != "" {
		t.Fatalf("bulk ca callback = %v, want trailing empty marker", got)
	}
}

func callbackList(mu *sync.Mutex, got *[]string) []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, len(*got))
	copy(out, *got)
	return out
}

// TestBulkRevokeNoMatches covers the zero-match paths of the bulk revocations.
func TestBulkRevokeNoMatches(t *testing.T) {
	e := newTestEngine(t)
	if n, err := e.RevokeCertsByPrincipalUid("no-such-uid", 1); err != nil || n != 0 {
		t.Fatalf("uid no-match: n=%d err=%v", n, err)
	}
	if n, err := e.RevokeCertsBySubCA("no-such-ca", 1); err != nil || n != 0 {
		t.Fatalf("ca no-match: n=%d err=%v", n, err)
	}
}

// TestNewEngineNilDB covers the nil-backend guard in NewEngine.
func TestNewEngineNilDB(t *testing.T) {
	if _, err := NewEngine(nil, EngineOptions{}); err == nil {
		t.Fatal("expected error for nil db")
	}
}

// TestNewEngineBadWalPath covers the record-buffer construction failure path.
func TestNewEngineBadWalPath(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	_, err = NewEngine(d, EngineOptions{WalPath: t.TempDir(), Logger: discardLogger()})
	if err == nil {
		t.Fatal("expected error when WAL path is a directory")
	}
}

// TestNewEngineClosedDB covers the rebuild failure path (backend unreadable).
func TestNewEngineClosedDB(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(d, EngineOptions{Logger: discardLogger()}); err == nil {
		t.Fatal("expected error when backend is closed")
	}
}

// TestIsNonceUsedWrongLength covers the length guard in IsNonceUsed.
func TestIsNonceUsedWrongLength(t *testing.T) {
	e := newTestEngine(t)
	if _, err := e.IsNonceUsed([]byte("short")); err == nil {
		t.Fatal("expected error for non-16-byte nonce")
	}
}

// TestZeroOptionsDefaultsLogger verifies a nil Logger falls back to slog.Default.
func TestZeroOptionsDefaultsLogger(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	e, err := NewEngine(d, EngineOptions{})
	if err != nil {
		t.Fatal(err)
	}
	e.Stop()
}

// TestUpsertSubCADedupChildren covers the children reverse-index dedup on
// repeated puts of the same sub-CA.
func TestUpsertSubCADedupChildren(t *testing.T) {
	e := newTestEngine(t)
	rec := &db.SubCAMeta{Name: "sub-a", ParentCA: "issuing"}
	for i := 0; i < 2; i++ {
		if err := e.UpsertSubCA(rec); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(e.subCas.children["issuing"]); n != 1 {
		t.Fatalf("expected 1 child entry after dedup, got %d", n)
	}
}

// TestJanitorBackendCleanupError covers the janitor's backend nonce-cleanup
// failure path (warning only, no panic).
func TestJanitorBackendCleanupError(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(d, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	e.janitor() // must not panic; backend cleanup error is swallowed
	e.Stop()
}

// TestNonceStoreDuplicate covers the in-memory duplicate-nonce rejection.
func TestNonceStoreDuplicate(t *testing.T) {
	e := newTestEngine(t)
	n := []byte("aaaaaaaaaaaaaaaa")
	if err := e.StoreNonce(n); err != nil {
		t.Fatal(err)
	}
	if err := e.StoreNonce(n); !errors.Is(err, db.ErrDuplicateNonce) {
		t.Fatalf("expected ErrDuplicateNonce, got %v", err)
	}
}

// TestNonceSetLoadExpiredSkipped covers the startup-rebuild skip of expired
// nonces.
func TestNonceSetLoadExpiredSkipped(t *testing.T) {
	s := NewNonceSet(0)
	s.load([]byte("aaaaaaaaaaaaaaaa"), false, time.Now().Add(-time.Minute))
	if s.Len() != 0 {
		t.Fatalf("expired nonce must not be loaded, len=%d", s.Len())
	}
}

// TestRevokedSetPutFiltering covers the validity filters in RevokedSet.put.
func TestRevokedSetPutFiltering(t *testing.T) {
	s := NewRevokedSet(0)
	now := time.Now()

	// Status not R → skipped.
	s.put(makeCert(1, "x.example.com", now.Add(time.Hour)))
	if s.Len() != 0 {
		t.Fatalf("non-R record must be skipped, len=%d", s.Len())
	}
	// R but no RevokedAt → skipped.
	r := revokedCert(2, "issuing", now.Add(-time.Hour), now.Add(time.Hour))
	r.RevokedAt = nil
	s.put(r)
	if s.Len() != 0 {
		t.Fatalf("nil RevokedAt record must be skipped, len=%d", s.Len())
	}
	// R but validity window closed → skipped.
	s.put(revokedCert(3, "issuing", now.Add(-time.Hour), now.Add(-time.Hour)))
	if s.Len() != 0 {
		t.Fatalf("expired-window record must be skipped, len=%d", s.Len())
	}
}

// TestRevokedSetPutAllEdgeCases covers the skip/duplicate paths of putAll.
func TestRevokedSetPutAllEdgeCases(t *testing.T) {
	s := NewRevokedSet(0)
	now := time.Now()

	s.putAll(nil) // no-op
	if s.Len() != 0 {
		t.Fatalf("empty putAll must be a no-op, len=%d", s.Len())
	}

	valid := revokedCert(1, "ca", now.Add(-time.Hour), now.Add(time.Hour))
	dup := revokedCert(1, "ca", now.Add(-time.Hour), now.Add(time.Hour))
	notRevoked := makeCert(2, "x.example.com", now.Add(time.Hour))
	noTimestamp := revokedCert(3, "ca", now.Add(-time.Hour), now.Add(time.Hour))
	noTimestamp.RevokedAt = nil
	expired := revokedCert(4, "ca", now.Add(-time.Hour), now.Add(-time.Hour))

	s.putAll([]*db.CertRecord{valid, dup, notRevoked, noTimestamp, expired})
	if s.Len() != 1 {
		t.Fatalf("expected 1 entry after filtering, got %d", s.Len())
	}
}

// TestRevokedSetEvictOverflowEmptiesCA covers the defensive cleanup when
// eviction drains a CA's window entirely.
func TestRevokedSetEvictOverflowEmptiesCA(t *testing.T) {
	s := NewRevokedSet(1)
	now := time.Now()
	r := revokedCert(1, "ca", now.Add(-time.Hour), now.Add(time.Hour))
	// White-box: a CA whose map is empty while its order slice overflows.
	s.byCA["ca"] = map[string]*db.CertRecord{}
	s.order["ca"] = []*db.CertRecord{r}
	s.evictOverflowLocked("ca")
	if _, ok := s.byCA["ca"]; ok {
		t.Fatal("empty CA map should be deleted after eviction")
	}
	if _, ok := s.order["ca"]; ok {
		t.Fatal("empty CA order should be deleted after eviction")
	}
}

// TestFilterSortedSortsMultipleResults covers the NotBefore-descending sort
// when a secondary-index filter returns multiple records.
func TestFilterSortedSortsMultipleResults(t *testing.T) {
	e := newTestEngine(t)
	base := time.Now()
	for i := 0; i < 3; i++ {
		r := makeCert(int64(i), fmt.Sprintf("s%d.example.com", i), time.Time{})
		r.PrincipalUid = "shared-uid"
		r.NotBefore = base.Add(time.Duration(i) * time.Hour)
		if err := e.IssueCert(r); err != nil {
			t.Fatal(err)
		}
	}
	recs, _, _, err := e.ListCertsByPrincipalUid("shared-uid", "", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 records, got %d", len(recs))
	}
	for i := 1; i < len(recs); i++ {
		if recs[i-1].NotBefore.Before(recs[i].NotBefore) {
			t.Fatalf("records not sorted by NotBefore desc: %v then %v", recs[i-1].NotBefore, recs[i].NotBefore)
		}
	}
}

// TestShutdownPaths verifies the post-shutdown behavior of enqueue and
// FlushAll: with the writer loops gone and the channels at capacity, the
// cancelled context wins deterministically and FlushAll reports it.
func TestShutdownPaths(t *testing.T) {
	e := newTestEngine(t)
	e.Stop()

	// Fill every writer shard to capacity; with no writer loops draining them,
	// a send would block, so the cancelled ctx must win the select.
	for _, ch := range e.writerShards {
		for i := 0; i < cap(ch); i++ {
			ch <- func() error { return nil }
		}
	}
	e.enqueue("", func() error { return nil }) // must return via ctx.Done

	if err := e.FlushAll(); !errors.Is(err, context.Canceled) {
		t.Fatalf("FlushAll after stop: %v, want context.Canceled", err)
	}
}

// TestEngineRebuildAICPagination seeds more AIC extensions than loadPageSize
// and verifies the paginated AIC load walks both pages.
func TestEngineRebuildAICPagination(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	const total = loadPageSize + 1
	for i := 0; i < total; i++ {
		a := &db.AICExtension{
			CAName:           "issuing",
			SerialNumber:     fmt.Sprintf("%X", i),
			AgentID:          "agent-aic",
			PrincipalUID:     "uid-aic",
			CapabilitiesJSON: "{}",
			AICJSON:          "{}",
		}
		if err := d.InsertAICExtension(a); err != nil {
			t.Fatal(err)
		}
	}

	e, err := NewEngine(d, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	if e.aic.Len() != total {
		t.Fatalf("expected %d AIC extensions loaded, got %d", total, e.aic.Len())
	}
	if recs, _ := e.ListAICExtensionsByAgentID("agent-aic"); len(recs) != total {
		t.Fatalf("expected %d AIC by agent, got %d", total, len(recs))
	}
}
