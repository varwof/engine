// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
)

// TestListNonces covers the full nonce lifecycle read used by the engine
// startup rebuild, including used flags and created-time parsing.
func TestListNonces(t *testing.T) {
	d := newTestDB(t)

	n1 := []byte("aaaaaaaaaaaaaaaa")
	n2 := []byte("bbbbbbbbbbbbbbbb")
	if err := d.StoreNonce(n1); err != nil {
		t.Fatal(err)
	}
	if err := d.StoreNonce(n2); err != nil {
		t.Fatal(err)
	}
	if err := d.ConsumeNonce(n1); err != nil {
		t.Fatal(err)
	}

	recs, err := d.ListNonces()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 nonce records, got %d", len(recs))
	}

	byNonce := map[string]NonceRecord{}
	for _, r := range recs {
		byNonce[string(r.Nonce)] = r
	}
	if r := byNonce[string(n1)]; !r.Used {
		t.Fatal("consumed nonce must be marked used")
	}
	if r := byNonce[string(n2)]; r.Used {
		t.Fatal("unconsumed nonce must not be marked used")
	}
	if recs[0].Created.IsZero() {
		t.Fatal("created timestamp must be parsed")
	}
}

// TestUpdatePGSQLSequencesOnSQLite exercises updatePGSQLSequences against a
// non-PostgreSQL backend: every setval fails and is skipped, but the function
// must complete without error.
func TestUpdatePGSQLSequencesOnSQLite(t *testing.T) {
	d := newTestDB(t)
	if err := d.InsertCert(makeTestCert(t, 1, "seq.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := updatePGSQLSequences(d); err != nil {
		t.Fatalf("updatePGSQLSequences on SQLite should be a no-op: %v", err)
	}
}
