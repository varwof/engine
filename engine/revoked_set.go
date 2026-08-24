// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"sort"
	"sync"
	"time"

	"github.com/varwof/engine/db"
)

// RevokedSet holds revoked certificates that are still within their validity
// window (status='R' AND not_after >= now) per CA, sorted by revoked_at
// descending for CRL generation. CRL generation is a pure in-memory traversal.
type RevokedSet struct {
	mu       sync.RWMutex
	byCA     map[string]map[string]*db.CertRecord
	order    map[string][]*db.CertRecord // ca -> sorted by revoked_at desc
	maxPerCA int
}

// NewRevokedSet creates an empty revocation set. maxPerCA bounds the per-CA
// revoked window (the CRL shape); when a CA exceeds it the oldest-revoked
// entries are evicted from the window. maxPerCA <= 0 disables the bound.
func NewRevokedSet(maxPerCA int) *RevokedSet {
	return &RevokedSet{
		byCA:     make(map[string]map[string]*db.CertRecord),
		order:    make(map[string][]*db.CertRecord),
		maxPerCA: maxPerCA,
	}
}

func (s *RevokedSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, m := range s.byCA {
		total += len(m)
	}
	return total
}

// put inserts a revoked record if its validity window is still open.
func (s *RevokedSet) put(r *db.CertRecord) {
	if r.Status != "R" || r.RevokedAt == nil {
		return
	}
	if r.NotAfter.Before(time.Now()) {
		return // outside the CRL validity window; skip
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byCA[r.CAName] == nil {
		s.byCA[r.CAName] = make(map[string]*db.CertRecord)
	}
	s.byCA[r.CAName][r.SerialNumber] = r
	s.orderInsertLocked(r)
	s.evictOverflowLocked(r.CAName)
}

// evictOverflowLocked trims a CA's revoked window to maxPerCA by dropping the
// oldest-revoked entries (the tail of the revoked_at-desc order slice). The
// certificate's status stays 'R' in the certificate index; only the CRL window
// is trimmed.
func (s *RevokedSet) evictOverflowLocked(ca string) {
	if s.maxPerCA <= 0 {
		return
	}
	m := s.byCA[ca]
	o := s.order[ca]
	for len(o) > s.maxPerCA {
		oldest := o[len(o)-1]
		o = o[:len(o)-1]
		delete(m, oldest.SerialNumber)
	}
	s.order[ca] = o
	if len(m) == 0 {
		delete(s.byCA, ca)
		delete(s.order, ca)
	}
}

func (s *RevokedSet) orderInsertLocked(r *db.CertRecord) {
	o := s.order[r.CAName]
	at := *r.RevokedAt
	pos := sort.Search(len(o), func(n int) bool {
		return o[n].RevokedAt.Before(at) // desc: first strictly-older entry
	})
	o = append(o, nil)
	copy(o[pos+1:], o[pos:])
	o[pos] = r
	s.order[r.CAName] = o
}

// entries returns a copy of a CA's revoked certificates in revoked_at
// descending order. The copy keeps callers safe from concurrent insert/prune
// mutations of the underlying order slice.
func (s *RevokedSet) entries(ca string) []*db.CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*db.CertRecord(nil), s.order[ca]...)
}

// putAll inserts a batch of revoked records, keeping each CA's order slice
// sorted with a single pass. It is the O(n log n) path for bulk revocations;
// repeated put calls would be O(n²) per CA.
func (s *RevokedSet) putAll(records []*db.CertRecord) {
	if len(records) == 0 {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range records {
		if r.Status != "R" || r.RevokedAt == nil || r.NotAfter.Before(now) {
			continue
		}
		if s.byCA[r.CAName] == nil {
			s.byCA[r.CAName] = make(map[string]*db.CertRecord)
		}
		if _, dup := s.byCA[r.CAName][r.SerialNumber]; dup {
			continue
		}
		s.byCA[r.CAName][r.SerialNumber] = r
		s.order[r.CAName] = append(s.order[r.CAName], r)
	}
	for _, o := range s.order {
		sort.Slice(o, func(a, b int) bool {
			return o[a].RevokedAt.After(*o[b].RevokedAt)
		})
	}
	for ca := range s.order {
		s.evictOverflowLocked(ca)
	}
}

// pruneExpired removes revoked records whose validity window has closed. The
// per-CA order slice is rebuilt in one pass per CA, so a janitor cycle that
// expires k of m entries is O(m) instead of O(k·m).
func (s *RevokedSet) pruneExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for ca, m := range s.byCA {
		for serial, r := range m {
			if r.NotAfter.Before(now) {
				delete(m, serial)
				removed++
			}
		}
		if len(m) == 0 {
			delete(s.byCA, ca)
			delete(s.order, ca)
			continue
		}
		kept := make([]*db.CertRecord, 0, len(m))
		for _, r := range s.order[ca] {
			if _, ok := m[r.SerialNumber]; ok {
				kept = append(kept, r)
			}
		}
		s.order[ca] = kept
	}
	return removed
}
