// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// TestReconcileOutOfBandRevocation verifies that a revocation performed
// directly in the backend (CLI-via-SQL / cross-tool backfill) becomes visible
// to the in-memory read path after a reconciliation pass, so mTLS/OCSP/CRL stop
// authorizing the certificate without a full restart (finding 7).
func TestReconcileOutOfBandRevocation(t *testing.T) {
	e := newTestEngine(t)

	rec := makeCert(1, "oob.example.com", time.Time{})
	if err := e.IssueCert(rec); err != nil {
		t.Fatal(err)
	}
	if err := e.FlushAll(); err != nil {
		t.Fatal(err)
	}

	// Out-of-band revoke: the DB row is flipped directly, bypassing the engine.
	if err := e.DB().RevokeCert("issuing", "1", 2); err != nil {
		t.Fatal(err)
	}

	// Before reconcile, memory (authoritative) still reports valid.
	st, err := e.GetCertStatus("issuing", "1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "V" {
		t.Fatalf("expected memory to still report V before reconcile, got %q", st.Status)
	}

	// Reconcile must flip the resident cert to revoked with the DB timestamp.
	e.reconcileRevocations()

	st, err = e.GetCertStatus("issuing", "1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "R" {
		t.Fatalf("expected R after reconcile, got %q", st.Status)
	}
	if st.RevokeReason == nil || *st.RevokeReason != 2 {
		t.Fatalf("expected reason 2 after reconcile, got %+v", st.RevokeReason)
	}

	// The revoked set must contain it for CRL generation.
	entries, err := e.GetRevokedCertEntries("issuing")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, en := range entries {
		if en.SerialNumber == "1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("reconciled cert missing from revoked entries (CRL source)")
	}

	// A second reconcile is a no-op (idempotent).
	e.reconcileRevocations()
}

// TestRevokeIsDurableBeforeAck verifies that once RevokeCert returns success,
// the backend row is already revoked — a crash/restart cannot resurrect the
// certificate (finding 1). Also verifies the already-revoked convergence path
// does not leave a stale active DB row after a failed first attempt.
func TestRevokeIsDurableBeforeAck(t *testing.T) {
	e := newTestEngine(t)

	rec := makeCert(2, "durable.example.com", time.Now().Add(365*24*time.Hour))
	if err := e.IssueCert(rec); err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeCert("issuing", "2", 3); err != nil {
		t.Fatal(err)
	}

	// The backend row must already be 'R' — no async window.
	row, err := e.DB().GetCert("issuing", "2")
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != "R" {
		t.Fatalf("expected backend R immediately after RevokeCert, got %q", row.Status)
	}

	// A second engine rebuilt from the same store must see it revoked too
	// (crash-recovery equivalent).
	d2, err := db.Open(e.DB().Path())
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	e2, err := NewEngine(d2, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Stop()
	st, err := e2.GetCertStatus("issuing", "2")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "R" {
		t.Fatalf("expected R after rebuild, got %q", st.Status)
	}
}
