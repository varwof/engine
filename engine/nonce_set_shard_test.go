// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// TestNonceSetShardedConcurrency hammers store/consume/has from many goroutines
// to exercise the sharded lock layout and per-nonce atomicity (CAS). Every
// stored nonce must be consumable exactly once and reported present.
func TestNonceSetShardedConcurrency(t *testing.T) {
	s := NewNonceSet(0)
	const n = 20000
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			base := w * (n / 16)
			for i := 0; i < n/16; i++ {
				nonce := make([]byte, 32)
				rand.Read(nonce)
				if err := s.store(nonce, time.Now().Add(time.Hour)); err != nil {
					t.Errorf("store: %v", err)
					return
				}
				if !s.has(nonce) {
					t.Error("stored nonce not present")
					return
				}
				if err := s.consume(nonce); err != nil {
					t.Errorf("consume: %v", err)
					return
				}
				if !s.isUsed(nonce) {
					t.Error("consumed nonce not used")
					return
				}
				if err := s.consume(nonce); !errors.Is(err, db.ErrNonceAlreadyUsed) {
					t.Errorf("double-consume: want ErrNonceAlreadyUsed, got %v", err)
					return
				}
				_ = base
			}
		}(w)
	}
	wg.Wait()
	if got := s.Len(); got != n {
		t.Fatalf("Len = %d, want %d", got, n)
	}
}

// TestNonceSetPruneExpiredAcrossShards verifies expiry pruning spans all
// shards and the count is decremented accordingly.
func TestNonceSetPruneExpiredAcrossShards(t *testing.T) {
	s := NewNonceSet(0)
	for i := 0; i < 100; i++ {
		nonce := make([]byte, 32)
		nonce[0] = byte(i)
		exp := time.Now().Add(time.Hour)
		if i%2 == 0 {
			exp = time.Now().Add(-time.Minute)
		}
		if err := s.store(nonce, exp); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.pruneExpired(time.Now()); got != 50 {
		t.Fatalf("pruned %d, want 50", got)
	}
	if got := s.Len(); got != 50 {
		t.Fatalf("Len after prune = %d, want 50", got)
	}
}

// TestNonceSetBackpressureCapacity verifies the capacity bound still holds
// across shards: stores beyond max (with nothing reclaimable) return
// ErrBackpressure, and expired entries are reclaimed first.
func TestNonceSetBackpressureCapacity(t *testing.T) {
	s := NewNonceSet(10)
	for i := 0; i < 9; i++ {
		nonce := make([]byte, 32)
		nonce[0] = byte(i)
		if err := s.store(nonce, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	// 10th slot filled by an already-expired entry.
	expired := make([]byte, 32)
	expired[0] = 0xBB
	if err := s.store(expired, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("store expired: %v", err)
	}
	// Full with nothing reclaimable except the expired entry → reclaim frees
	// one slot and the insert succeeds.
	again := make([]byte, 32)
	again[0] = 0xCC
	if err := s.store(again, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("store after reclaim: want success, got %v", err)
	}
	// Now genuinely full (all live) → ErrBackpressure.
	extra := make([]byte, 32)
	extra[0] = 0xAA
	if err := s.store(extra, time.Now().Add(time.Hour)); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("capacity store: want ErrBackpressure, got %v", err)
	}
}
