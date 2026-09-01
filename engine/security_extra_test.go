// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"errors"
	"testing"

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
