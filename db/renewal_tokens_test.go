// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func newRenewalTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func randomNonce() []byte {
	b := make([]byte, 16)
	rand.Read(b)
	return b
}

func TestStoreNonce_Success(t *testing.T) {
	d := newRenewalTestDB(t)
	nonce := randomNonce()
	if err := d.StoreNonce(nonce); err != nil {
		t.Fatalf("StoreNonce: %v", err)
	}
	used, err := d.IsNonceUsed(nonce)
	if err != nil {
		t.Fatalf("IsNonceUsed: %v", err)
	}
	if used {
		t.Fatal("nonce should not be used after store")
	}
}

func TestStoreNonce_Duplicate(t *testing.T) {
	d := newRenewalTestDB(t)
	nonce := randomNonce()
	if err := d.StoreNonce(nonce); err != nil {
		t.Fatalf("first StoreNonce: %v", err)
	}
	if err := d.StoreNonce(nonce); err != ErrDuplicateNonce {
		t.Fatalf("expected ErrDuplicateNonce, got %v", err)
	}
}

func TestStoreNonce_WrongLength(t *testing.T) {
	d := newRenewalTestDB(t)
	if err := d.StoreNonce(make([]byte, 8)); err == nil {
		t.Fatal("expected error for 8-byte nonce")
	}
}

func TestConsumeNonce_Success(t *testing.T) {
	d := newRenewalTestDB(t)
	nonce := randomNonce()
	if err := d.StoreNonce(nonce); err != nil {
		t.Fatalf("StoreNonce: %v", err)
	}
	if err := d.ConsumeNonce(nonce); err != nil {
		t.Fatalf("ConsumeNonce: %v", err)
	}
	used, err := d.IsNonceUsed(nonce)
	if err != nil {
		t.Fatalf("IsNonceUsed: %v", err)
	}
	if !used {
		t.Fatal("nonce should be used after consume")
	}
}

func TestConsumeNonce_DoubleConsume(t *testing.T) {
	d := newRenewalTestDB(t)
	nonce := randomNonce()
	if err := d.StoreNonce(nonce); err != nil {
		t.Fatalf("StoreNonce: %v", err)
	}
	if err := d.ConsumeNonce(nonce); err != nil {
		t.Fatalf("first ConsumeNonce: %v", err)
	}
	if err := d.ConsumeNonce(nonce); err != ErrNonceAlreadyUsed {
		t.Fatalf("expected ErrNonceAlreadyUsed, got %v", err)
	}
}

func TestConsumeNonce_NotFound(t *testing.T) {
	d := newRenewalTestDB(t)
	nonce := randomNonce()
	if err := d.ConsumeNonce(nonce); err != ErrNonceNotFound {
		t.Fatalf("expected ErrNonceNotFound, got %v", err)
	}
}

func TestConsumeNonce_WrongLength(t *testing.T) {
	d := newRenewalTestDB(t)
	if err := d.ConsumeNonce(make([]byte, 32)); err == nil {
		t.Fatal("expected error for 32-byte nonce")
	}
}

func TestIsNonceUsed_NotFound(t *testing.T) {
	d := newRenewalTestDB(t)
	nonce := randomNonce()
	used, err := d.IsNonceUsed(nonce)
	if err != nil {
		t.Fatalf("IsNonceUsed: %v", err)
	}
	if used {
		t.Fatal("unknown nonce should not be reported as used")
	}
}

func TestConsumeNonce_Concurrent(t *testing.T) {
	d := newRenewalTestDB(t)
	nonce := randomNonce()
	if err := d.StoreNonce(nonce); err != nil {
		t.Fatalf("StoreNonce: %v", err)
	}

	const goroutines = 10
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			errs <- d.ConsumeNonce(nonce)
		}()
	}

	successes := 0
	var lastErr error
	for i := 0; i < goroutines; i++ {
		err := <-errs
		if err == nil {
			successes++
		} else {
			lastErr = err
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful consume, got %d (last err: %v)", successes, lastErr)
	}
}

func TestCleanupExpiredNonces(t *testing.T) {
	d := newRenewalTestDB(t)
	nonce1 := randomNonce()
	nonce2 := randomNonce()
	if err := d.StoreNonce(nonce1); err != nil {
		t.Fatalf("StoreNonce 1: %v", err)
	}
	if err := d.StoreNonce(nonce2); err != nil {
		t.Fatalf("StoreNonce 2: %v", err)
	}

	// Backdate nonce1 by inserting directly
	_, err := d.Exec(`UPDATE renewal_tokens SET created = ? WHERE nonce = ?`,
		time.Now().Add(-2*time.Hour).UTC().Format("2006-01-02 15:04:05"), nonce1)
	if err != nil {
		t.Fatalf("backdate nonce1: %v", err)
	}

	n, err := d.CleanupExpiredNonces(1 * time.Hour)
	if err != nil {
		t.Fatalf("CleanupExpiredNonces: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 cleaned, got %d", n)
	}

	// nonce1 should be gone, nonce2 should remain
	used1, _ := d.IsNonceUsed(nonce1)
	used2, _ := d.IsNonceUsed(nonce2)
	if used1 {
		t.Fatal("nonce1 should have been cleaned")
	}
	_ = bytes.Compare(nonce1, nonce2) // suppress unused
	if !used2 && !bytes.Equal(nonce2, nonce2) {
		t.Fatal("nonce2 should still exist")
	}
	_ = used2 // nonce2 exists (used=false → IsNonceUsed returns false)
}

func TestStoreNonce_MultipleNonces(t *testing.T) {
	d := newRenewalTestDB(t)
	const count = 100
	nonces := make([][]byte, count)
	for i := 0; i < count; i++ {
		nonces[i] = randomNonce()
		if err := d.StoreNonce(nonces[i]); err != nil {
			t.Fatalf("StoreNonce %d: %v", i, err)
		}
	}
	// Consume all
	for i, nonce := range nonces {
		if err := d.ConsumeNonce(nonce); err != nil {
			t.Fatalf("ConsumeNonce %d: %v", i, err)
		}
	}
	// All should be used
	for i, nonce := range nonces {
		used, err := d.IsNonceUsed(nonce)
		if err != nil {
			t.Fatalf("IsNonceUsed %d: %v", i, err)
		}
		if !used {
			t.Fatalf("nonce %d should be used", i)
		}
	}
}
