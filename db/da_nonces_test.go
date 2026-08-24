// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestDANonce_FullCycle(t *testing.T) {
	d := newTestDB(t)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	if err := d.StoreDANonce(nonce); err != nil {
		t.Fatalf("store: %v", err)
	}

	used, err := d.IsDANonceUsed(nonce)
	if err != nil {
		t.Fatalf("is_used: %v", err)
	}
	if !used {
		t.Fatal("stored DA nonce should be reported used")
	}

	// Replay: the same nonce must be rejected.
	err = d.StoreDANonce(nonce)
	if !errors.Is(err, ErrDuplicateNonce) {
		t.Fatalf("replay store: want ErrDuplicateNonce, got %v", err)
	}
}

func TestDANonce_List(t *testing.T) {
	d := newTestDB(t)

	var want [][]byte
	for i := 0; i < 3; i++ {
		n := make([]byte, 32)
		if _, err := rand.Read(n); err != nil {
			t.Fatal(err)
		}
		if err := d.StoreDANonce(n); err != nil {
			t.Fatal(err)
		}
		want = append(want, n)
	}

	got, err := d.ListDANonces()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("listed %d, want %d", len(got), len(want))
	}
	for _, rec := range got {
		found := false
		for _, w := range want {
			if string(rec.Nonce) == string(w) {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("listed nonce not stored")
		}
	}
}

func TestDANonce_InvalidLen(t *testing.T) {
	d := newTestDB(t)
	if err := d.StoreDANonce(make([]byte, 16)); err == nil {
		t.Error("expected error for 16-byte nonce (DA nonce must be 32)")
	}
	if _, err := d.IsDANonceUsed(make([]byte, 31)); err == nil {
		t.Error("expected error for 31-byte nonce")
	}
}

func TestDANonce_NotFound(t *testing.T) {
	d := newTestDB(t)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	used, err := d.IsDANonceUsed(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if used {
		t.Fatal("fresh nonce should not be reported used")
	}
}

func TestCleanupExpiredDANonces(t *testing.T) {
	d := newTestDB(t)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	if err := d.StoreDANonce(nonce); err != nil {
		t.Fatal(err)
	}

	// Force the created timestamp into the past so the cleanup removes it.
	if _, err := d.Exec(`UPDATE da_nonces SET created = ? WHERE nonce = ?`,
		time.Now().Add(-48*time.Hour).Format("2006-01-02 15:04:05"), nonce); err != nil {
		t.Fatal(err)
	}

	n, err := d.CleanupExpiredDANonces(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("cleaned %d, want 1", n)
	}

	used, err := d.IsDANonceUsed(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if used {
		t.Fatal("nonce should be removed after cleanup")
	}
}
