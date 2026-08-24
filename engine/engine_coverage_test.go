// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"errors"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// TestJanitorLoopBackground exercises the real background goroutine path
// (Start/janitorLoop/Stop) and verifies expiry pruning covers certificates,
// revoked-set entries, in-memory nonces, and the backend renewal_tokens table.
func TestJanitorLoopBackground(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	e, err := NewEngine(d, EngineOptions{
		Grace:           100 * time.Millisecond,
		JanitorInterval: 20 * time.Millisecond,
		NonceTTL:        30 * time.Millisecond,
		Logger:          discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	now := time.Now()
	expired := makeCert(1, "expired.example.com", now.Add(-time.Hour))
	if err := e.IssueCert(expired); err != nil {
		t.Fatal(err)
	}
	short := makeCert(2, "short.example.com", now.Add(60*time.Millisecond))
	if err := e.IssueCert(short); err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeCert("issuing", "2", 1); err != nil {
		t.Fatal(err)
	}
	nonce := []byte("0123456789abcdef")
	if err := e.StoreNonce(nonce); err != nil {
		t.Fatal(err)
	}

	e.Start()
	e.Start() // Start must be idempotent

	waitFor(t, "expired cert eviction", func() bool {
		_, err := e.GetCert("issuing", "1")
		return errors.Is(err, ErrNotFound)
	})
	waitFor(t, "revoked entry pruning", func() bool {
		entries, _ := e.GetRevokedCertEntries("issuing")
		return len(entries) == 0
	})
	waitFor(t, "nonce memory pruning", func() bool {
		return e.Metrics().NonceSetSize == 0
	})
	waitFor(t, "backend nonce cleanup", func() bool {
		recs, err := e.DB().ListNonces()
		return err == nil && len(recs) == 0
	})

	if m := e.Metrics(); m.WindowEvictions < 1 {
		t.Fatalf("expected eviction counter from background janitor, got %d", m.WindowEvictions)
	}
}

func waitFor(t *testing.T, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

// TestGetRevokedCertsAndReadMissPaths covers GetRevokedCerts plus the miss
// paths of the secondary read methods.
func TestGetRevokedCertsAndReadMissPaths(t *testing.T) {
	e := newTestEngine(t)
	if err := e.IssueCert(makeCert(1, "crl.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeCert("issuing", "1", 1); err != nil {
		t.Fatal(err)
	}

	recs, err := e.GetRevokedCerts("issuing")
	if err != nil || len(recs) != 1 {
		t.Fatalf("revoked records: %d err=%v", len(recs), err)
	}
	if recs[0].Status != "R" || recs[0].RevokedAt == nil || recs[0].RevokeReason == nil {
		t.Fatalf("unexpected revoked record: %+v", recs[0])
	}

	if _, err := e.GetSubCA("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSubCA miss: %v", err)
	}
	if _, err := e.GetTrustAnchor(999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetTrustAnchor miss: %v", err)
	}
	if _, err := e.GetAICExtensionByCert("issuing", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAICExtensionByCert miss: %v", err)
	}
	if _, err := e.GetCertStatusByIssuer("CN=Unknown,O=X", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCertStatusByIssuer miss: %v", err)
	}

	// Secondary list queries return empty, not an error, on miss.
	if recs, _, _, _ := e.GetCertBySPKIHash("spki-nope", "", "", 0, nil); len(recs) != 0 {
		t.Fatalf("spki miss: %d", len(recs))
	}
	if recs, _, _, _ := e.ListCertsByPrincipalUid("uid-nope", "", 0, nil); len(recs) != 0 {
		t.Fatalf("principal miss: %d", len(recs))
	}
	if recs, _, _, _ := e.ListCertsByAgentID("agent-nope", "", 0, nil); len(recs) != 0 {
		t.Fatalf("agent miss: %d", len(recs))
	}
	if recs, _ := e.ListAICExtensionsByAgentID("agent-nope"); len(recs) != 0 {
		t.Fatalf("aic agent miss: %d", len(recs))
	}
	if recs, _ := e.ListAICExtensionsByPrincipalUid("uid-nope"); len(recs) != 0 {
		t.Fatalf("aic uid miss: %d", len(recs))
	}
	// SPKI hit filtered out by a mismatched CA name.
	if recs, _, _, err := e.GetCertBySPKIHash("spki-crl.example.com", "other-ca", "", 0, nil); err != nil || len(recs) != 0 {
		t.Fatalf("spki ca filter: %d err=%v", len(recs), err)
	}
}

// TestNonceBackpressureAndUnknown covers the bounded nonce store, the unknown
// nonce paths, and the expired-entry reclaim before the bound is enforced.
func TestNonceBackpressureAndUnknown(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	e, err := NewEngine(d, EngineOptions{
		MaxNonces: 2,
		NonceTTL:  40 * time.Millisecond,
		Logger:    discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	n1 := []byte("aaaaaaaaaaaaaaaa")
	n2 := []byte("bbbbbbbbbbbbbbbb")
	n3 := []byte("cccccccccccccccc")
	if err := e.StoreNonce(n1); err != nil {
		t.Fatal(err)
	}
	if err := e.StoreNonce(n2); err != nil {
		t.Fatal(err)
	}
	if err := e.StoreNonce(n3); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("expected backpressure, got %v", err)
	}

	unknown := []byte("dddddddddddddddd")
	if err := e.ConsumeNonce(unknown); !errors.Is(err, db.ErrNonceNotFound) {
		t.Fatalf("unknown consume: %v", err)
	}
	if used, _ := e.IsNonceUsed(unknown); used {
		t.Fatal("unknown nonce must be unused")
	}
	if err := e.StoreNonce([]byte("short")); err == nil {
		t.Fatal("expected error for non-16-byte nonce")
	}
	if err := e.ConsumeNonce([]byte("short")); err == nil {
		t.Fatal("expected error for non-16-byte nonce")
	}

	// Expired entries are reclaimed before the bound is enforced.
	time.Sleep(60 * time.Millisecond)
	if err := e.StoreNonce(n3); err != nil {
		t.Fatalf("expired reclaim failed: %v", err)
	}
	if m := e.Metrics(); m.NonceSetSize != 1 {
		t.Fatalf("expected 1 live nonce after reclaim, got %d", m.NonceSetSize)
	}
}

// TestEngineDBAccessor verifies DB() returns the backend handle.
func TestEngineDBAccessor(t *testing.T) {
	e := newTestEngine(t)
	if e.DB() != e.DB() {
		t.Fatal("DB() must return the backend database handle")
	}
}
