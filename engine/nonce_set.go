// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/varwof/engine/db"
)

// nonceEntry tracks a one-time nonce's consumed flag and expiration.
type nonceEntry struct {
	used bool
	exp  time.Time
}

// NonceSet is the in-memory one-time nonce store. It is the authoritative
// source for Store/Consume/IsUsed; the backend renewal_tokens table converges
// asynchronously. Consume is an atomic CAS under the set mutex, so concurrent
// double-spends resolve with exactly one winner.
type NonceSet struct {
	mu    sync.RWMutex
	entry map[string]*nonceEntry
	max   int
}

// NewNonceSet creates a bounded nonce set. max <= 0 disables the bound.
func NewNonceSet(max int) *NonceSet {
	return &NonceSet{
		entry: make(map[string]*nonceEntry),
		max:   max,
	}
}

func (s *NonceSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entry)
}

func nonceKey(nonce []byte) string { return hex.EncodeToString(nonce) }

// store inserts a fresh (unused) nonce. Returns db.ErrDuplicateNonce on
// collision.
func (s *NonceSet) store(nonce []byte, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := nonceKey(nonce)
	if _, ok := s.entry[k]; ok {
		return db.ErrDuplicateNonce
	}
	if s.max > 0 && len(s.entry) >= s.max {
		// Reclaim expired entries first, then enforce the bound.
		now := time.Now()
		for kk, v := range s.entry {
			if now.After(v.exp) {
				delete(s.entry, kk)
			}
		}
		if len(s.entry) >= s.max {
			return ErrBackpressure
		}
	}
	s.entry[k] = &nonceEntry{exp: exp}
	return nil
}

// load inserts an entry already present in the backend (startup rebuild).
// An expired entry is skipped.
func (s *NonceSet) load(nonce []byte, used bool, exp time.Time) {
	if exp.Before(time.Now()) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entry[nonceKey(nonce)] = &nonceEntry{used: used, exp: exp}
}

// consume atomically transitions unused → used. It returns db.ErrNonceNotFound
// if the nonce is unknown and db.ErrNonceAlreadyUsed on double-spend.
func (s *NonceSet) consume(nonce []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := nonceKey(nonce)
	e, ok := s.entry[k]
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entry[nonceKey(nonce)]
	return ok && e.used
}

// has reports whether a nonce is present in the set regardless of its
// consumed state. DA nonces are "used" the moment they are stored (they were
// spent to mint an AIC), so replay pre-checks use presence, not consumption.
func (s *NonceSet) has(nonce []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.entry[nonceKey(nonce)]
	return ok
}

// remove deletes a nonce from the set. It is used to roll back a memory
// reservation when the backend persistence of the nonce fails.
func (s *NonceSet) remove(nonce []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entry, nonceKey(nonce))
}

// pruneExpired removes expired nonces, returning the count removed.
func (s *NonceSet) pruneExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for k, e := range s.entry {
		if now.After(e.exp) {
			delete(s.entry, k)
			removed++
		}
	}
	return removed
}
