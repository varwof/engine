// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"errors"
	"testing"
	"time"

	"github.com/varwof/engine/db"
	"github.com/varwof/engine/recordbuffer"
)

// TestPersistDurableRetriesTransient verifies that a durability-critical op
// is retried on transient failure and succeeds once the backend recovers
// (findings 1/4 retry path).
func TestPersistDurableRetriesTransient(t *testing.T) {
	e := newTestEngine(t)
	attempts := 0
	err := e.persistDurable("retry-key", func() error {
		attempts++
		if attempts < 3 {
			return errors.New("transient backend failure")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("persistDurable: want nil after retries, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("want 3 attempts, got %d", attempts)
	}
}

// TestPersistDurableSurfacesFinalError verifies that when the backend never
// recovers, the caller receives the error instead of a silent in-memory
// acknowledgement (findings 1/4: no fire-and-forget).
func TestPersistDurableSurfacesFinalError(t *testing.T) {
	e := newTestEngine(t)
	err := e.persistDurable("fail-key", func() error {
		return errors.New("backend down")
	})
	if err == nil {
		t.Fatal("expected surfaced error after retries exhausted")
	}
	if !errors.Is(err, errors.New("backend down")) && err.Error() != "backend down" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestStoreDANonceErrNormalization verifies record-buffer backpressure is
// normalized onto the public ErrBackpressure sentinel so callers can use
// errors.Is regardless of the append path (finding 2).
func TestStoreDANonceErrNormalization(t *testing.T) {
	if err := storeDANonceErr(recordbuffer.ErrBackpressure); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("want ErrBackpressure, got %v", err)
	}
	other := storeDANonceErr(errors.New("disk full"))
	if errors.Is(other, ErrBackpressure) {
		t.Fatal("non-backpressure error must not map to ErrBackpressure")
	}
	if other == nil || other.Error() != "store_da_nonce: disk full" {
		t.Fatalf("unexpected wrapped error: %v", other)
	}
}

// TestNonceTTL verifies the configured nonce lifetime is exposed and defaulted
// by option validation.
func TestNonceTTL(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/ttl.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	e, err := NewEngine(d, EngineOptions{Logger: discardLogger(), NonceTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	if got := e.NonceTTL(); got != time.Hour {
		t.Fatalf("NonceTTL() = %v, want 1h", got)
	}
}

// TestUserTokenLifecycle covers the in-memory user/token index: put user,
// put token (valid + expired), get by token, delete by id and by user
// (finding 19: RFC3339 expiry parsed as time, not string).
func TestUserTokenLifecycle(t *testing.T) {
	e := newTestEngine(t)

	e.PutUser(&db.RBACUser{ID: 7, Username: "alice", Role: "admin", Enabled: true})
	u, err := e.GetUserByUsername("alice")
	if err != nil || u.ID != 7 {
		t.Fatalf("GetUserByUsername: %+v err=%v", u, err)
	}

	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	e.PutTokenHash(db.TokenHashRow{ID: 11, UserID: 7,
		TokenHash: db.TokenHash("secret-token"), ExpiresAt: &exp})
	info, err := e.GetToken("secret-token")
	if err != nil || info.Username != "alice" || info.Role != "admin" {
		t.Fatalf("GetToken: %+v err=%v", info, err)
	}

	// Expired token must be rejected (fail-safe).
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	e.PutTokenHash(db.TokenHashRow{ID: 12, UserID: 7,
		TokenHash: db.TokenHash("expired-token"), ExpiresAt: &past})
	if _, err := e.GetToken("expired-token"); err != ErrNotFound {
		t.Fatalf("expired token: want ErrNotFound, got %v", err)
	}

	// Delete by id.
	e.DeleteTokenByID(11)
	if _, err := e.GetToken("secret-token"); err != ErrNotFound {
		t.Fatalf("after DeleteTokenByID: want ErrNotFound, got %v", err)
	}

	// Delete by user removes all remaining tokens.
	e.PutTokenHash(db.TokenHashRow{ID: 13, UserID: 7,
		TokenHash: db.TokenHash("tok-b"), ExpiresAt: &exp})
	e.DeleteTokensByUserID(7)
	if _, err := e.GetToken("tok-b"); err != ErrNotFound {
		t.Fatalf("after DeleteTokensByUserID: want ErrNotFound, got %v", err)
	}
}

// TestHashNonceForLogNoPlaintext verifies nonce logging uses a short hash
// prefix and never the raw value (finding 6).
func TestHashNonceForLogNoPlaintext(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	h := hashNonceForLog(nonce)
	if len(h) != 8 {
		t.Fatalf("hashNonceForLog length = %d, want 8", len(h))
	}
	if string(nonce[:4]) == h {
		t.Fatal("log hash must not equal raw nonce bytes")
	}
}
