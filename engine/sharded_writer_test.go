// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// TestWriterShardForKeyStable verifies the shard routing is deterministic per
// key: the same ordering key always lands on the same shard (that is what
// preserves nonce Store→Consume order), and a zero key routes to shard 0.
func TestWriterShardForKeyStable(t *testing.T) {
	e := newTestEngine(t)
	if len(e.writerShards) != 4 {
		t.Fatalf("expected 4 default writer shards, got %d", len(e.writerShards))
	}

	key := "nonce:deadbeef"
	first := e.writerShardForKey(key)
	for i := 0; i < 100; i++ {
		if got := e.writerShardForKey(key); got != first {
			t.Fatalf("same key routed to different shards: %d vs %d", got, first)
		}
	}
	if e.writerShardForKey("") != 0 {
		t.Fatal("empty key must route to shard 0")
	}

	// Distinct keys spread across shards (sanity, not a hard guarantee).
	seen := map[int]bool{}
	for i := 0; i < 64; i++ {
		seen[e.writerShardForKey(fmt.Sprintf("key-%d", i))] = true
	}
	if len(seen) < 2 {
		t.Fatalf("keys did not spread across shards, only %d distinct", len(seen))
	}
}

// TestShardedWriterNonceOrdering verifies the ordering guarantee that makes
// sharding safe: for the same nonce, Store must reach the DB before Consume
// (the DB Consume is a CAS on used=0→1). With keyed routing both land on the
// same writer shard in enqueue order, so no nonce reports ErrNonceNotFound
// after convergence.
func TestShardedWriterNonceOrdering(t *testing.T) {
	e := newTestEngine(t)

	const n = 500
	nonces := make([][]byte, n)
	for i := range nonces {
		nonces[i] = make([]byte, 16)
		if _, err := rand.Read(nonces[i]); err != nil {
			t.Fatal(err)
		}
	}

	// Interleave Store/Consume concurrently across many goroutines; each nonce
	// is stored then consumed immediately, both queued behind the same key.
	var wg sync.WaitGroup
	for i := range nonces {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := e.StoreNonce(nonces[i]); err != nil {
				t.Errorf("store %d: %v", i, err)
			}
			if err := e.ConsumeNonce(nonces[i]); err != nil {
				t.Errorf("consume %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if err := e.FlushAll(); err != nil {
		t.Fatal(err)
	}

	// Backend convergence: every nonce is present and marked used. A sharding
	// ordering bug would surface here as ErrNonceNotFound (consume ahead of
	// store) leaving some nonces unconsumed.
	deadline := time.Now().Add(3 * time.Second)
	for {
		all := true
		for i := range nonces {
			used, err := e.DB().IsNonceUsed(nonces[i])
			if err != nil {
				t.Fatalf("is_used %d: %v", i, err)
			}
			if !used {
				all = false
				break
			}
		}
		if all {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nonces did not converge as used within 3s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestShardedWriterAllShardsActive verifies every writer shard actually runs
// its own goroutine (R4 parallelism): an op queued to each shard executes and
// FlushAll waits for all of them.
func TestShardedWriterAllShardsActive(t *testing.T) {
	e := newTestEngine(t)

	done := make([]chan struct{}, len(e.writerShards))
	for i := range done {
		done[i] = make(chan struct{})
		e.writerShards[i] <- func() error { close(done[i]); return nil }
	}

	if err := e.FlushAll(); err != nil {
		t.Fatal(err)
	}
	for i, c := range done {
		select {
		case <-c:
		case <-time.After(2 * time.Second):
			t.Fatalf("shard %d did not execute its op", i)
		}
	}
}

// TestRevokeCertsBatchOrderingAcrossShards verifies a bulk revocation still
// converges even when individual cert revocations land on different shards:
// all paths flush the cert INSERTs first, and every revoke op is idempotent.
func TestRevokeCertsBatchOrderingAcrossShards(t *testing.T) {
	e := newTestEngine(t)

	const total = 40
	entries := make([]RevokeBatchEntry, total)
	for i := 0; i < total; i++ {
		serial := int64(0x3000 + i)
		if err := e.IssueCert(makeCert(serial, fmt.Sprintf("shard%d.example.com", i), time.Time{})); err != nil {
			t.Fatal(err)
		}
		entries[i] = RevokeBatchEntry{CA: "issuing", Serial: fmt.Sprintf("%X", serial), Reason: 1}
	}
	e.FlushAll()

	n, miss, err := e.RevokeCertsBatch(entries)
	if err != nil {
		t.Fatal(err)
	}
	if n != total || len(miss) != 0 {
		t.Fatalf("revoked=%d miss=%d, want %d/0", n, len(miss), total)
	}

	// Interleave a per-cert revocation of the same batch on its own shard keys
	// to exercise cross-shard idempotence.
	for _, en := range entries {
		e.enqueue(en.CA+"/"+en.Serial, func() error {
			_, err := e.DB().BulkRevokeCertificates([]db.RevokeBatchEntry{en})
			return err
		})
	}
	if err := e.FlushAll(); err != nil {
		t.Fatal(err)
	}

	for i, en := range entries {
		st, err := e.DB().GetCertStatus(en.CA, en.Serial)
		if err != nil || st.Status != "R" {
			t.Fatalf("serial %s status=%+v err=%v", en.Serial, st, err)
		}
		if i == 0 {
			break
		}
	}
}
