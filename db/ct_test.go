// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
)

func TestStoreAndGetSCT(t *testing.T) {
	d := newTestDB(t)

	if err := d.StoreSCT("ca1", "SERIAL01", 0, "log-id-abc", 1234567890, []byte("sig-data")); err != nil {
		t.Fatalf("StoreSCT: %v", err)
	}

	rec, err := d.GetSCT("ca1", "SERIAL01")
	if err != nil {
		t.Fatalf("GetSCT: %v", err)
	}

	if rec.LogID != "log-id-abc" {
		t.Fatalf("expected log-id-abc, got %q", rec.LogID)
	}
	if rec.Timestamp != 1234567890 {
		t.Fatalf("expected 1234567890, got %d", rec.Timestamp)
	}
	if string(rec.Signature) != "sig-data" {
		t.Fatalf("expected sig-data, got %q", string(rec.Signature))
	}
}

func TestStoreSCTReplace(t *testing.T) {
	d := newTestDB(t)

	d.StoreSCT("ca1", "SERIAL01", 0, "first-log", 100, []byte("first-sig"))
	d.StoreSCT("ca1", "SERIAL01", 1, "second-log", 200, []byte("second-sig"))

	rec, _ := d.GetSCT("ca1", "SERIAL01")
	if rec.SCTVersion != 1 {
		t.Fatalf("expected version 1 after replace, got %d", rec.SCTVersion)
	}
}

func TestGetSCTNotFound(t *testing.T) {
	d := newTestDB(t)

	_, err := d.GetSCT("ca1", "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for nonexistent SCT")
	}
}
