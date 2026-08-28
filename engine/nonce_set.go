// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/engine/db"
)

// nonceEntry tracks a one-time nonce's consumed flag and expiration.
type nonceEntry struct {
	used bool
	exp  time.Time
}

// nonceShards is the number of shards backing NonceSet. Each shard has its own
// lock, so concurrent store/consume on different nonces do not serialize. This
// removes the single-lock queueing that previously showed up as ~36% of the
// engine's mutex wait under AIC load (per-request storeDANonce).
const nonceShards = 16

// nonceSetShard is one independently-locked slice of the nonce store.
type nonceSetShard struct {
	mu    sync.RWMutex
	entry map[string]*nonceEntry
}

// NonceSet is the in-memory one-time nonce store. It is the authoritative
// source for Store/Consume/IsUsed; the backend renewal_tokens table converges
// asynchronously. Consume is an atomic CAS under the shard mutex, so concurrent
// double-spends resolve with exactly one winner.
//
// Entries are sharded by hash of the hex nonce key; the same nonce always maps
// to the same shard, preserving per-nonce atomicity.
type NonceSet struct {
	shards [nonceShards]*nonceSetShard
	max    int
	count  atomic.Int64
}

// NewNonceSet creates a bounded nonce set. max <= 0 disables the bound.
func NewNonceSet(max int) *NonceSet {
	s := &NonceSet{max: max}
	for i := range s.shards {
		s.shards[i] = &nonceSetShard{entry: make(map[string]*nonceEntry)}
	}
	return s
}

func nonceKey(nonce []byte) string { return hex.EncodeToString(nonce) }

// shardFor returns the shard owning a hex nonce key. FNV-1a gives a uniform
// spread over the (power-of-two) shard count regardless of hex-character
// distribution.
func (s *NonceSet) shardFor(k string) *nonceSetShard {
	h := uint32(2166136261)
	for i := 0; i < len(k); i++ {
		h ^= uint32(k[i])
		h *= 16777619
	}
	return s.shards[h&(nonceShards-1)]
}

func (s *NonceSet) Len() int { return int(s.count.Load()) }

// store inserts a fresh (unused) nonce. Returns db.ErrDuplicateNonce on
// collision. When at capacity it first reclaims expired entries across all
// shards; if still full it returns ErrBackpressure.
func (s *NonceSet) store(nonce []byte, exp time.Time) error {
	k := nonceKey(nonce)
	if s.max > 0 && s.count.Load() >= int64(s.max) {
		s.reclaimExpired(time.Now())
	}
	sh := s.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.entry[k]; ok {
		return db.ErrDuplicateNonce
	}
	if s.max > 0 && s.count.Load() >= int64(s.max) {
		return ErrBackpressure
	}
	sh.entry[k] = &nonceEntry{exp: exp}
	s.count.Add(1)
	return nil
}

// load inserts an entry already present in the backend (startup rebuild).
// An expired entry is skipped.
func (s *NonceSet) load(nonce []byte, used bool, exp time.Time) {
	if exp.Before(time.Now()) {
		return
	}
	k := nonceKey(nonce)
	sh := s.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.entry[k]; ok {
		return
	}
	sh.entry[k] = &nonceEntry{used: used, exp: exp}
	s.count.Add(1)
}

// consume atomically transitions unused → used. It returns db.ErrNonceNotFound
// if the nonce is unknown and db.ErrNonceAlreadyUsed on double-spend.
func (s *NonceSet) consume(nonce []byte) error {
	sh := s.shardFor(nonceKey(nonce))
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.entry[nonceKey(nonce)]
	if !ok {
		return db.ErrNonceNotFound
	}
	if e.used {
		return db.ErrNonceAlreadyUsed
	}
	e.used = true
	return nil
}

// isUsed reports whether a nonce has been consumed. Unknown nonces are unused.
func (s *NonceSet) isUsed(nonce []byte) bool {
	sh := s.shardFor(nonceKey(nonce))
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	e, ok := sh.entry[nonceKey(nonce)]
	return ok && e.used
}

// has reports whether a nonce is present in the set regardless of its
// consumed state. DA nonces are "used" the moment they are stored (they were
// spent to mint an AIC), so replay pre-checks use presence, not consumption.
func (s *NonceSet) has(nonce []byte) bool {
	sh := s.shardFor(nonceKey(nonce))
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	_, ok := sh.entry[nonceKey(nonce)]
	return ok
}

// remove deletes a nonce from the set. It is used to roll back a memory
// reservation when the backend persistence of the nonce fails.
func (s *NonceSet) remove(nonce []byte) {
	k := nonceKey(nonce)
	sh := s.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.entry[k]; ok {
		delete(sh.entry, k)
		s.count.Add(-1)
	}
}

// pruneExpired removes expired nonces from every shard, returning the count
// removed.
func (s *NonceSet) pruneExpired(now time.Time) int {
	removed := 0
	for _, sh := range s.shards {
		sh.mu.Lock()
		for k, e := range sh.entry {
			if now.After(e.exp) {
				delete(sh.entry, k)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	if removed > 0 {
		s.count.Add(-int64(removed))
	}
	return removed
}

// reclaimExpired is the capacity-path expiry sweep (see store). It must not be
// called while holding any shard lock.
func (s *NonceSet) reclaimExpired(now time.Time) {
	s.pruneExpired(now)
}

// snapshotUsed returns the current entry set as map[hexKey]used. Used by the
// convergence test to compare memory against the backend.
func (s *NonceSet) snapshotUsed() map[string]bool {
	out := make(map[string]bool, s.Len())
	for _, sh := range s.shards {
		sh.mu.RLock()
		for k, e := range sh.entry {
			out[k] = e.used
		}
		sh.mu.RUnlock()
	}
	return out
}
