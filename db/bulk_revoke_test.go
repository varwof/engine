// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"fmt"
	"testing"
)

// TestBulkStoreDANonces verifies the batched DA nonce sink (R1): a large set
// of nonces persists in a few multi-row statements, duplicates are ignored,
// and the rows land in the da_nonces table.
func TestBulkStoreDANonces(t *testing.T) {
	d := newTestDB(t)

	nonces := make([][]byte, 500)
	for i := range nonces {
		nonces[i] = make([]byte, 32)
		nonces[i][0] = byte(i)
		nonces[i][1] = byte(i >> 8)
		nonces[i][2] = byte(i >> 16)
		nonces[i][3] = byte(i >> 24)
	}

	n, err := d.BulkStoreDANonces(nonces)
	if err != nil {
		t.Fatal(err)
	}
	if n != 500 {
		t.Fatalf("expected 500 stored, got %d", n)
	}

	// Duplicate set (replay) is ignored entirely.
	n, err = d.BulkStoreDANonces(nonces)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 duplicates stored, got %d", n)
	}

	// Every nonce is individually visible via IsDANonceUsed.
	for i := range nonces {
		used, err := d.IsDANonceUsed(nonces[i])
		if err != nil {
			t.Fatal(err)
		}
		if !used {
			t.Fatalf("nonce %d not found after bulk store", i)
		}
	}

	// Mixed batch: 300 new + 200 duplicates → only 300 stored.
	mixed := make([][]byte, 500)
	for i := 0; i < 300; i++ {
		mixed[i] = make([]byte, 32)
		mixed[i][0] = byte(i + 0xA0)
		mixed[i][1] = byte(i>>8 + 0xA0)
		mixed[i][2] = byte(i >> 16)
		mixed[i][3] = byte(i >> 24)
	}
	copy(mixed[300:], nonces[:200])
	n, err = d.BulkStoreDANonces(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if n != 300 {
		t.Fatalf("expected 300 new in mixed batch, got %d", n)
	}

	// Wrong-length nonces are rejected (single-store contract preserved).
	if _, err := d.BulkStoreDANonces([][]byte{make([]byte, 16)}); err == nil {
		t.Fatal("expected error for a 16-byte DA nonce in bulk path")
	}
}

// TestBulkRevokeCertificates verifies the single-statement bulk revocation
// path (R3): many entries across chunk boundaries, per-row reasons, and
// status=R convergence.
func TestBulkRevokeCertificates(t *testing.T) {
	d := newTestDB(t)

	const total = 300 // spans 2 chunks of 199 + 101
	entries := make([]RevokeBatchEntry, total)
	for i := 0; i < total; i++ {
		serial := int64(0x1000 + i)
		rec := makeTestCert(t, serial, fmt.Sprintf("bulk%d.example.com", i))
		if err := d.InsertCert(rec); err != nil {
			t.Fatal(err)
		}
		entries[i] = RevokeBatchEntry{CA: "issuing", Serial: fmt.Sprintf("%X", serial), Reason: i % 3}
	}

	n, err := d.BulkRevokeCertificates(entries)
	if err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Fatalf("expected %d rows updated, got %d", total, n)
	}

	// Every row is revoked with its own per-row reason.
	for i, en := range entries {
		rec, err := d.GetCert(en.CA, en.Serial)
		if err != nil {
			t.Fatalf("get %s: %v", en.Serial, err)
		}
		if rec.Status != "R" {
			t.Fatalf("serial %s status = %s, want R", en.Serial, rec.Status)
		}
		if rec.RevokeReason == nil || *rec.RevokeReason != i%3 {
			t.Fatalf("serial %s reason = %v, want %d", en.Serial, rec.RevokeReason, i%3)
		}
		if rec.RevokedAt == nil || rec.InvalidityDate == nil {
			t.Fatalf("serial %s missing revoked_at/invalidity_date", en.Serial)
		}
	}

	// Re-running the batch against already-revoked rows updates 0 rows.
	n, err = d.BulkRevokeCertificates(entries)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0 updates on re-run, got %d", n)
	}
}
