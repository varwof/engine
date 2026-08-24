// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
)

func TestStoreAndGetEscrowedKey(t *testing.T) {
	d := newTestDB(t)

	keyData := []byte("encrypted-key-data-12345")
	if err := d.StoreEscrowedKey("test-ca", "SERIAL001", keyData); err != nil {
		t.Fatalf("StoreEscrowedKey: %v", err)
	}

	got, err := d.GetEscrowedKey("test-ca", "SERIAL001")
	if err != nil {
		t.Fatalf("GetEscrowedKey: %v", err)
	}

	if string(got) != string(keyData) {
		t.Fatalf("data mismatch: got %q, want %q", string(got), string(keyData))
	}
}

func TestStoreEscrowedKeyReplace(t *testing.T) {
	d := newTestDB(t)

	if err := d.StoreEscrowedKey("ca1", "S1", []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := d.StoreEscrowedKey("ca1", "S1", []byte("replaced")); err != nil {
		t.Fatal(err)
	}

	got, _ := d.GetEscrowedKey("ca1", "S1")
	if string(got) != "replaced" {
		t.Fatalf("expected replaced, got %q", string(got))
	}
}

func TestGetEscrowedKeyNotFound(t *testing.T) {
	d := newTestDB(t)

	_, err := d.GetEscrowedKey("nonexistent", "NOPE")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestStoreEscrowedKeyEmpty(t *testing.T) {
	d := newTestDB(t)

	if err := d.StoreEscrowedKey("ca-e", "S-EMPTY", []byte{}); err != nil {
		t.Fatalf("StoreEscrowedKey empty: %v", err)
	}

	got, err := d.GetEscrowedKey("ca-e", "S-EMPTY")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty data, got %d bytes", len(got))
	}
}
