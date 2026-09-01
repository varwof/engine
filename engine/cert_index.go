// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"container/heap"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/engine/db"
)

// certKey identifies a certificate by its primary key (ca_name, serial_number).
type certKey struct {
	ca     string
	serial string
}

// issuerKey identifies a certificate by issuer DN + serial for handshake
// revocation lookups where the CA name is not known ahead of time.
type issuerKey struct {
	issuerDN string
	serial   string
}

// caCNKey groups certificates by CA + common name for duplicate-CN checks.
type caCNKey struct {
	ca string
	cn string
}

// certIndexShards is the number of shards backing CertIndex. Each shard owns
// the full secondary-index entries for a subset of primary keys (chosen by
// FNV-1a hash of ca+serial), so per-record insert/lookup/revoke only contends
// on that shard's lock instead of a single global one. This removes the
// single-lock queueing that previously dominated engine mutex wait under AIC
// load (~60% of it; RISKS R5).
const certIndexShards = 16

// certIndexShard is one independently-locked slice of the certificate index.
type certIndexShard struct {
	mu    sync.RWMutex
	byKey map[certKey]*db.CertRecord
	// Secondary indexes: each record's secondary entries live in the same
	// shard as its primary key, so point mutations stay single-shard.
	byIssuer map[issuerKey]*db.CertRecord
	bySPKI   map[string]map[*db.CertRecord]struct{}
	byAgent  map[string]map[*db.CertRecord]struct{}
	byUid    map[string]map[*db.CertRecord]struct{}
	byCAcn   map[caCNKey]map[*db.CertRecord]struct{}
	windows  map[string]*certHeap // ca -> min-heap by NotAfter asc (eviction order)
}

// CertIndex is the primary in-memory certificate index. All certificates
// (valid and revoked) that have not yet expired out of the hot window live
// here. Records are immutable once published: revocation publishes a clone
// (copy-on-write) that replaces the original in every index, so readers
// holding a pre-revocation pointer observe a stable snapshot. Only the
// eviction-window heap retains the original instance until eviction.
//
// The index is sharded by primary-key hash: each shard has its own lock, and a
// record and all its secondary entries always live in one shard. Cross-shard
// secondary lookups (by SPKI/UID/agent/CN/issuer) scan every shard and merge;
// those paths are rare relative to the write path that the sharding protects.
type CertIndex struct {
	shards [certIndexShards]*certIndexShard

	// count / residentBytes are global, atomically tracked estimates used to
	// enforce the MaxCerts / MaxResidentBytes budgets across all shards.
	count         atomic.Int64
	residentBytes atomic.Int64
}

// estimateRecordBytes returns a conservative estimate of the resident memory a
// *db.CertRecord occupies across the primary + 5 secondary maps and the
// eviction-window heap. It is intentionally not an exact heap measurement:
// fixed base overhead covers the struct, map buckets, and heap entry; the
// variable part is the cert_der payload and the string field lengths.
func estimateRecordBytes(r *db.CertRecord) int64 {
	const baseOverhead = 512 // struct + map entries + heap entry + padding
	n := int64(baseOverhead) + int64(len(r.CertDER))
	n += int64(len(r.SerialNumber) + len(r.CAName) + len(r.Status) +
		len(r.Subject) + len(r.CommonName) + len(r.Fingerprint) +
		len(r.SubjectO) + len(r.SubjectC) + len(r.IssuerDN) +
		len(r.KeyAlgo) + len(r.SigAlgo) + len(r.SKI) + len(r.AKI) +
		len(r.SAN) + len(r.Profile) + len(r.SPKIHash) +
		len(r.PrincipalUid) + len(r.AgentId))
	return n
}

// shardForCertKey returns the shard index owning a primary key.
func shardForCertKey(ca, serial string) int {
	h := uint32(2166136261)
	for i := 0; i < len(ca); i++ {
		h ^= uint32(ca[i])
		h *= 16777619
	}
	h ^= 0x00
	h *= 16777619
	for i := 0; i < len(serial); i++ {
		h ^= uint32(serial[i])
		h *= 16777619
	}
	return int(h & (certIndexShards - 1))
}

func (i *CertIndex) shardForKey(k certKey) *certIndexShard {
	return i.shards[shardForCertKey(k.ca, k.serial)]
}

// ResidentBytes returns the estimated resident bytes of the certificate index.
func (i *CertIndex) ResidentBytes() int64 { return i.residentBytes.Load() }

// NewCertIndex creates an empty certificate index.
func NewCertIndex() *CertIndex {
	idx := &CertIndex{}
	for s := range idx.shards {
		idx.shards[s] = &certIndexShard{
			byKey:    make(map[certKey]*db.CertRecord),
			byIssuer: make(map[issuerKey]*db.CertRecord),
			bySPKI:   make(map[string]map[*db.CertRecord]struct{}),
			byAgent:  make(map[string]map[*db.CertRecord]struct{}),
			byUid:    make(map[string]map[*db.CertRecord]struct{}),
			byCAcn:   make(map[caCNKey]map[*db.CertRecord]struct{}),
			windows:  make(map[string]*certHeap),
		}
	}
	return idx
}

func (i *CertIndex) Len() int { return int(i.count.Load()) }

// put inserts a record into the primary and all secondary indexes. It must be
// called only for records not already present.
func (i *CertIndex) put(r *db.CertRecord) {
	sh := i.shardForKey(certKey{ca: r.CAName, serial: r.SerialNumber})
	sh.mu.Lock()
	sh.putLocked(r)
	sh.mu.Unlock()
	i.count.Add(1)
	i.residentBytes.Add(estimateRecordBytes(r))
}

// insertIfAbsent inserts r atomically under its shard lock, so concurrent
// IssueCert calls for the same (ca, serial) resolve consistently: exactly one
// wins the slot and others observe the existing record. When maxCerts > 0 and
// the index is at capacity, expired certificates (NotAfter < cutoff) are
// evicted first; if none can be evicted the insert is rejected with
// ErrBackpressure. The same holds for maxBytes (estimated resident byte
// budget). evicted reports how many expired certificates were removed. The
// capacity budget is global (tracked atomically across shards) and checked
// before and after the shard lock; the bound is approximate under heavy
// concurrency, matching the NonceSet capacity semantics.
func (i *CertIndex) insertIfAbsent(r *db.CertRecord, maxCerts int, maxBytes int64, cutoff time.Time) (existing *db.CertRecord, inserted bool, evicted int, err error) {
	if maxCerts > 0 || maxBytes > 0 {
		if i.overBudget(maxCerts, maxBytes, estimateRecordBytes(r)) {
			evicted = len(i.evictExpired(cutoff))
			if i.overBudget(maxCerts, maxBytes, estimateRecordBytes(r)) {
				return nil, false, evicted, ErrBackpressure
			}
		}
	}
	k := certKey{ca: r.CAName, serial: r.SerialNumber}
	sh := i.shardForKey(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if existing, ok := sh.byKey[k]; ok {
		return existing, false, 0, nil
	}
	if maxCerts > 0 || maxBytes > 0 {
		if i.overBudget(maxCerts, maxBytes, estimateRecordBytes(r)) {
			return nil, false, 0, ErrBackpressure
		}
	}
	sh.putLocked(r)
	i.count.Add(1)
	i.residentBytes.Add(estimateRecordBytes(r))
	return nil, true, evicted, nil
}

func (i *CertIndex) overBudget(maxCerts int, maxBytes int64, est int64) bool {
	if maxCerts > 0 && i.count.Load() >= int64(maxCerts) {
		return true
	}
	if maxBytes > 0 && i.residentBytes.Load()+est > maxBytes {
		return true
	}
	return false
}

// putLocked inserts a record into the shard's primary and all secondary
// indexes. The caller must hold the shard lock.
func (sh *certIndexShard) putLocked(r *db.CertRecord) {
	k := certKey{ca: r.CAName, serial: r.SerialNumber}
	sh.byKey[k] = r

	if r.IssuerDN != "" {
		sh.byIssuer[issuerKey{issuerDN: r.IssuerDN, serial: r.SerialNumber}] = r
	}
	if r.SPKIHash != "" {
		m := sh.bySPKI[r.SPKIHash]
		if m == nil {
			m = make(map[*db.CertRecord]struct{})
			sh.bySPKI[r.SPKIHash] = m
		}
		m[r] = struct{}{}
	}
	if r.AgentId != "" {
		m := sh.byAgent[r.AgentId]
		if m == nil {
			m = make(map[*db.CertRecord]struct{})
			sh.byAgent[r.AgentId] = m
		}
		m[r] = struct{}{}
	}
	if r.PrincipalUid != "" {
		m := sh.byUid[r.PrincipalUid]
		if m == nil {
			m = make(map[*db.CertRecord]struct{})
			sh.byUid[r.PrincipalUid] = m
		}
		m[r] = struct{}{}
	}
	if r.CommonName != "" {
		key := caCNKey{ca: r.CAName, cn: r.CommonName}
		m := sh.byCAcn[key]
		if m == nil {
			m = make(map[*db.CertRecord]struct{})
			sh.byCAcn[key] = m
		}
		m[r] = struct{}{}
	}
	sh.windowInsertLocked(r)
}

// certHeap is a min-heap over *db.CertRecord ordered by NotAfter ascending,
// so the heap top is always the certificate that expires first. It backs each
// CA's eviction window. Inserting into an O(n) sorted slice was the dominant
// cost of the write path once a CA accumulated thousands of certs (the sort
// + shift is O(n)); the heap turns that into O(log n), so per-issue cost no
// longer grows linearly with resident certificate count.
type certHeap []*db.CertRecord

func (h certHeap) Len() int { return len(h) }
func (h certHeap) Less(i, j int) bool {
	return h[i].NotAfter.Before(h[j].NotAfter)
}
func (h certHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *certHeap) Push(x any)   { *h = append(*h, x.(*db.CertRecord)) }
func (h *certHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func (sh *certIndexShard) windowInsertLocked(r *db.CertRecord) {
	h := sh.windows[r.CAName]
	if h == nil {
		h = &certHeap{}
		sh.windows[r.CAName] = h
	}
	heap.Push(h, r)
}

// get returns the certificate by (ca, serial). Second return reports presence.
func (i *CertIndex) get(ca, serial string) (*db.CertRecord, bool) {
	sh := i.shardForKey(certKey{ca: ca, serial: serial})
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	r, ok := sh.byKey[certKey{ca: ca, serial: serial}]
	return r, ok
}

// getByIssuer returns the certificate by issuer DN + serial. The issuer key
// does not carry the CA, so every shard is searched.
func (i *CertIndex) getByIssuer(issuerDN, serial string) (*db.CertRecord, bool) {
	ik := issuerKey{issuerDN: issuerDN, serial: serial}
	for _, sh := range i.shards {
		sh.mu.RLock()
		r, ok := sh.byIssuer[ik]
		sh.mu.RUnlock()
		if ok {
			return r, true
		}
	}
	return nil, false
}

// CertCursor is an opaque pagination cursor for high-cardinality certificate
// queries (SPKI hash / principal UID / agent ID). It encodes the sort position
// of the last returned record (NotBefore descending, serial descending as the
// tiebreaker); pass it back as the `after` argument to fetch the next page.
// A nil cursor starts at the beginning.
type CertCursor struct {
	NotBefore time.Time
	Serial    string
}

// certAfterCursor reports whether r sorts after the cursor position under the
// canonical order (NotBefore desc, serial desc), i.e. whether it belongs on a
// page that starts after `after`.
func certAfterCursor(r *db.CertRecord, c *CertCursor) bool {
	if c == nil {
		return true
	}
	if r.NotBefore.Before(c.NotBefore) {
		return true
	}
	return r.NotBefore.Equal(c.NotBefore) && r.SerialNumber < c.Serial
}

// getBySPKI returns certificates for a spki_hash, optionally filtered by CA
// name and status, sorted by NotBefore descending. limit <= 0 returns the full
// matching set. When limit bounds the page, the returned cursor resumes from
// the last record and hasMore reports whether another page exists. The SPKI
// index is sharded, so each shard's matching set is merged first.
func (i *CertIndex) getBySPKI(spkiHash, caName, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
	merged := make(map[*db.CertRecord]struct{})
	for _, sh := range i.shards {
		sh.mu.RLock()
		for r := range sh.bySPKI[spkiHash] {
			merged[r] = struct{}{}
		}
		sh.mu.RUnlock()
	}
	return filterSortedSetPage(merged, caName, status, limit, after)
}

// getByUid returns certificates for a principal_uid, optionally filtered by
// status, sorted by NotBefore descending. See getBySPKI for pagination.
func (i *CertIndex) getByUid(uid, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
	merged := make(map[*db.CertRecord]struct{})
	for _, sh := range i.shards {
		sh.mu.RLock()
		for r := range sh.byUid[uid] {
			merged[r] = struct{}{}
		}
		sh.mu.RUnlock()
	}
	return filterSortedSetPage(merged, "", status, limit, after)
}

// getByAgent returns certificates for an agent_id, optionally filtered by
// status, sorted by NotBefore descending. See getBySPKI for pagination.
func (i *CertIndex) getByAgent(agent, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
	merged := make(map[*db.CertRecord]struct{})
	for _, sh := range i.shards {
		sh.mu.RLock()
		for r := range sh.byAgent[agent] {
			merged[r] = struct{}{}
		}
		sh.mu.RUnlock()
	}
	return filterSortedSetPage(merged, "", status, limit, after)
}

// filterSortedSetPage filters and sorts a secondary-index set without doing a
// full O(n log n) sort of a high-cardinality result. It keeps the best
// limit+1 records in a min-heap sized O(limit): each page costs O(n) filter
// scan plus O(n log limit) heap work, and only limit+1 records are
// materialized. hasMore is exact because the limit+1-th record acts as a
// sentinel. limit <= 0 preserves the old all-at-once behavior.
func filterSortedSetPage(set map[*db.CertRecord]struct{}, caName, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
	if len(set) == 0 {
		return nil, nil, false
	}
	h := &pageHeap{}
	var all []*db.CertRecord // limit <= 0 path: full materialization
	for r := range set {
		if caName != "" && r.CAName != caName {
			continue
		}
		if status != "" && r.Status != status {
			continue
		}
		if !certAfterCursor(r, after) {
			continue
		}
		if limit > 0 {
			if h.Len() < limit+1 {
				heap.Push(h, r)
			} else if certWorse((*h)[0], r) {
				(*h)[0] = r
				heap.Fix(h, 0)
			}
			continue
		}
		all = append(all, r)
	}
	if limit <= 0 {
		if len(all) == 0 {
			return nil, nil, false
		}
		sortCertRecords(all)
		return all, nil, false
	}
	n := h.Len()
	if n == 0 {
		return nil, nil, false
	}
	out := make([]*db.CertRecord, n)
	for i := n - 1; i >= 0; i-- {
		out[i] = heap.Pop(h).(*db.CertRecord)
	}
	// heap.Pop returns the worst first, which is assigned to the end of out, so
	// out is ordered best→worst (NotBefore desc, serial desc).
	if n <= limit {
		return out, nil, false
	}
	// The best `limit` candidates are out[0:limit]; out[limit] is the limit+1-th
	// sentinel that proves hasMore. Cursor = the worst record of this page.
	page := out[:limit]
	last := page[len(page)-1]
	return page, &CertCursor{NotBefore: last.NotBefore, Serial: last.SerialNumber}, true
}

// pageHeap is a min-heap that keeps the "worst" (last in canonical order)
// record at the top, so it can hold the best limit+1 candidates of a page.
type pageHeap []*db.CertRecord

func (h pageHeap) Len() int           { return len(h) }
func (h pageHeap) Less(i, j int) bool { return certWorse(h[i], h[j]) }
func (h pageHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *pageHeap) Push(x any)        { *h = append(*h, x.(*db.CertRecord)) }
func (h *pageHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// certWorse reports whether a sorts after b in the canonical order (NotBefore
// desc, serial desc tiebreaker), i.e. a belongs later in the result list.
func certWorse(a, b *db.CertRecord) bool {
	if a.NotBefore.Equal(b.NotBefore) {
		return a.SerialNumber < b.SerialNumber
	}
	return a.NotBefore.Before(b.NotBefore)
}

// sortCertRecords sorts by NotBefore descending with serial descending as the
// tiebreaker, giving a stable total order that the pagination cursor relies on.
func sortCertRecords(recs []*db.CertRecord) {
	sort.Slice(recs, func(a, b int) bool {
		if recs[a].NotBefore.Equal(recs[b].NotBefore) {
			return recs[a].SerialNumber > recs[b].SerialNumber
		}
		return recs[a].NotBefore.After(recs[b].NotBefore)
	})
}

// getActiveByCN returns active (status='V') certificates for a CA + CN across
// all shards.
func (i *CertIndex) getActiveByCN(ca, cn string) []*db.CertRecord {
	var out []*db.CertRecord
	key := caCNKey{ca: ca, cn: cn}
	for _, sh := range i.shards {
		sh.mu.RLock()
		for r := range sh.byCAcn[key] {
			if r.Status == "V" {
				out = append(out, r)
			}
		}
		sh.mu.RUnlock()
	}
	return out
}

// revokePair identifies one certificate to revoke with its per-entry reason.
type revokePair struct {
	CA     string
	Serial string
	Reason int
}

// setRevoked marks a certificate revoked via copy-on-write. Returns (record,
// true) on success, or (nil, false) if the cert is missing or already revoked.
// The returned record is the published (revoked) clone; the pre-revocation
// instance is left untouched for any reader that already holds it.
func (i *CertIndex) setRevoked(ca, serial string, now time.Time, reason int) (*db.CertRecord, bool) {
	k := certKey{ca: ca, serial: serial}
	sh := i.shardForKey(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.setRevokedLocked(k, now, reason)
}

// reconcileRevoked flips a resident certificate to revoked using the timestamp
// and reason recorded by the backend, so an out-of-band DB revocation becomes
// visible to in-memory reads (mTLS/OCSP/CRL) without waiting for a restart
// (finding 7). No-op when the cert is missing or already revoked.
func (i *CertIndex) reconcileRevoked(ca, serial string, revokedAt time.Time, reason *int) *db.CertRecord {
	k := certKey{ca: ca, serial: serial}
	sh := i.shardForKey(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	old, ok := sh.byKey[k]
	if !ok || old.Status == "R" {
		return nil
	}
	now := revokedAt
	if now.IsZero() {
		now = time.Now()
	}
	r := 0
	if reason != nil {
		r = *reason
	}
	clone := *old
	clone.Status = "R"
	clone.RevokedAt = &now
	clone.RevokeReason = &r
	clone.InvalidityDate = &now
	sh.replaceLocked(old, &clone)
	return &clone
}

// bulkSetRevoked marks a set of certificates revoked, grouping pairs by shard
// so each shard is locked once. For each pair it reports the published
// (revoked) record when the cert was active, and the keys that are not
// resident in memory (so callers can distinguish "already revoked" from "not
// resident"). Non-active or already-revoked certs are skipped.
func (i *CertIndex) bulkSetRevoked(pairs []revokePair, now time.Time) (revoked []*db.CertRecord, missing []certKey) {
	byShard := make(map[*certIndexShard][]revokePair)
	for _, p := range pairs {
		sh := i.shardForKey(certKey{ca: p.CA, serial: p.Serial})
		byShard[sh] = append(byShard[sh], p)
	}
	revoked = make([]*db.CertRecord, 0, len(pairs))
	for sh, ps := range byShard {
		sh.mu.Lock()
		for _, p := range ps {
			k := certKey{ca: p.CA, serial: p.Serial}
			if _, ok := sh.byKey[k]; !ok {
				missing = append(missing, k)
				continue
			}
			if clone, ok := sh.setRevokedLocked(k, now, p.Reason); ok {
				revoked = append(revoked, clone)
			}
		}
		sh.mu.Unlock()
	}
	return revoked, missing
}

// setRevokedLocked publishes a revoked copy of the record identified by key.
// The original instance is never mutated — a clone carries the revoked fields
// and replaces the original in every index (copy-on-write), so concurrent
// readers that already hold the old pointer observe a stable pre-revocation
// snapshot and never see a half-updated record. Returns the published clone.
// The caller must hold the shard lock. (The resident-byte estimate is not
// adjusted for the clone; the fields that change contribute a negligible delta
// to the conservative budget estimate.)
func (sh *certIndexShard) setRevokedLocked(key certKey, now time.Time, reason int) (*db.CertRecord, bool) {
	old, ok := sh.byKey[key]
	if !ok || old.Status == "R" {
		return nil, false
	}
	clone := *old
	clone.Status = "R"
	clone.RevokedAt = &now
	clone.RevokeReason = &reason
	clone.InvalidityDate = &now
	sh.replaceLocked(old, &clone)
	return &clone, true
}

// replaceLocked swaps the published instance of a record for a new instance
// across the primary and all secondary indexes of the shard. The eviction-window
// heap keeps the old instance (a stable pre-replacement snapshot);
// removeLocked resolves the current instance by key so pointer-keyed deletions
// still match. The caller must hold the shard lock.
func (sh *certIndexShard) replaceLocked(old, new *db.CertRecord) {
	k := certKey{ca: old.CAName, serial: old.SerialNumber}
	sh.byKey[k] = new

	if old.IssuerDN != "" {
		ik := issuerKey{issuerDN: old.IssuerDN, serial: old.SerialNumber}
		delete(sh.byIssuer, ik)
		sh.byIssuer[ik] = new
	}
	if old.SPKIHash != "" {
		m := sh.bySPKI[old.SPKIHash]
		delete(m, old)
		m[new] = struct{}{}
	}
	if old.AgentId != "" {
		m := sh.byAgent[old.AgentId]
		delete(m, old)
		m[new] = struct{}{}
	}
	if old.PrincipalUid != "" {
		m := sh.byUid[old.PrincipalUid]
		delete(m, old)
		m[new] = struct{}{}
	}
	if old.CommonName != "" {
		m := sh.byCAcn[caCNKey{ca: old.CAName, cn: old.CommonName}]
		delete(m, old)
		m[new] = struct{}{}
	}
}

// bulkSetRevokedByUid marks every active certificate of a principal revoked
// and returns them. Each shard is locked in turn; bulk revocation is race-free
// against concurrent reads on the same shard.
func (i *CertIndex) bulkSetRevokedByUid(uid string, now time.Time, reason int) []*db.CertRecord {
	var out []*db.CertRecord
	for _, sh := range i.shards {
		sh.mu.Lock()
		for r := range sh.byUid[uid] {
			if r.Status == "V" {
				k := certKey{ca: r.CAName, serial: r.SerialNumber}
				if clone, ok := sh.setRevokedLocked(k, now, reason); ok {
					out = append(out, clone)
				}
			}
		}
		sh.mu.Unlock()
	}
	return out
}

// bulkSetRevokedByCA marks every active certificate issued by a CA revoked and
// returns them. Each shard is locked in turn.
func (i *CertIndex) bulkSetRevokedByCA(caName string, now time.Time, reason int) []*db.CertRecord {
	var out []*db.CertRecord
	for _, sh := range i.shards {
		sh.mu.Lock()
		for _, r := range sh.byKey {
			if r.CAName == caName && r.Status == "V" {
				k := certKey{ca: r.CAName, serial: r.SerialNumber}
				if clone, ok := sh.setRevokedLocked(k, now, reason); ok {
					out = append(out, clone)
				}
			}
		}
		sh.mu.Unlock()
	}
	return out
}

// evictExpired removes every certificate whose NotAfter is strictly before
// cutoff from all indexes, shard by shard. It uses each CA's NotAfter-sorted
// window to find the eviction boundary in O(log n), then drops those records
// from the secondary maps. Returns the evicted certificates' primary keys so
// callers (e.g. the janitor) can cascade-clean related rows such as AIC
// extensions.
// remove deletes a resident certificate from the index, returning whether it
// was present. Used to roll back a memory-first insert when the write pipeline
// cannot queue the persistence (finding 18), so a certificate is never pinned
// in memory without a backend write.
func (i *CertIndex) remove(ca, serial string) bool {
	k := certKey{ca: ca, serial: serial}
	sh := i.shardForKey(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	_, ok := sh.byKey[k]
	if !ok {
		return false
	}
	sh.removeLocked(&db.CertRecord{CAName: ca, SerialNumber: serial})
	i.count.Add(-1)
	return true
}

// evictExpired removes certificates whose NotAfter has passed the cutoff from
// the hot indexes, returning the removed keys so the caller can cascade-clean
// related rows such as AIC extensions. It is the janitor's expiry path.
func (i *CertIndex) evictExpired(cutoff time.Time) []certKey {
	var evicted []certKey
	for _, sh := range i.shards {
		sh.mu.Lock()
		for _, r := range sh.evictExpiredLocked(cutoff) {
			evicted = append(evicted, certKey{ca: r.CAName, serial: r.SerialNumber})
			i.count.Add(-1)
			i.residentBytes.Add(-estimateRecordBytes(r))
		}
		sh.mu.Unlock()
	}
	return evicted
}

// evictExpiredLocked pops expired records from the shard's eviction windows
// and removes them from the shard's indexes. Returns the removed (current
// published) records; the caller updates the global counters. The caller must
// hold the shard lock.
func (sh *certIndexShard) evictExpiredLocked(cutoff time.Time) []*db.CertRecord {
	var removed []*db.CertRecord
	for ca, h := range sh.windows {
		if h == nil || h.Len() == 0 {
			continue
		}
		// Heap top is the earliest NotAfter; pop while it is expired.
		for h.Len() > 0 && (*h)[0].NotAfter.Before(cutoff) {
			r := heap.Pop(h).(*db.CertRecord)
			sh.removeLocked(r)
			removed = append(removed, r)
		}
		if h.Len() == 0 {
			delete(sh.windows, ca)
		}
	}
	return removed
}

// removeLocked removes a record from the shard's primary and all secondary
// indexes. The eviction-window heap may hold a pre-revocation pointer
// (copy-on-write revocation never re-publishes into the heap), so the current
// published instance is resolved by primary key before the pointer-keyed
// deletions run. The caller must hold the shard lock.
func (sh *certIndexShard) removeLocked(r *db.CertRecord) {
	k := certKey{ca: r.CAName, serial: r.SerialNumber}
	cur, ok := sh.byKey[k]
	if !ok {
		return // already removed
	}
	r = cur
	delete(sh.byKey, k)
	if r.IssuerDN != "" {
		delete(sh.byIssuer, issuerKey{issuerDN: r.IssuerDN, serial: r.SerialNumber})
	}
	if r.SPKIHash != "" {
		if m := sh.bySPKI[r.SPKIHash]; m != nil {
			delete(m, r)
			if len(m) == 0 {
				delete(sh.bySPKI, r.SPKIHash)
			}
		}
	}
	if r.AgentId != "" {
		if m := sh.byAgent[r.AgentId]; m != nil {
			delete(m, r)
			if len(m) == 0 {
				delete(sh.byAgent, r.AgentId)
			}
		}
	}
	if r.PrincipalUid != "" {
		if m := sh.byUid[r.PrincipalUid]; m != nil {
			delete(m, r)
			if len(m) == 0 {
				delete(sh.byUid, r.PrincipalUid)
			}
		}
	}
	if r.CommonName != "" {
		key := caCNKey{ca: r.CAName, cn: r.CommonName}
		if m := sh.byCAcn[key]; m != nil {
			delete(m, r)
			if len(m) == 0 {
				delete(sh.byCAcn, key)
			}
		}
	}
}

// snapshotAll returns a copy of the full primary index (key -> record), used
// by the convergence test to compare memory against the backend.
func (i *CertIndex) snapshotAll() map[certKey]*db.CertRecord {
	out := make(map[certKey]*db.CertRecord, i.Len())
	for _, sh := range i.shards {
		sh.mu.RLock()
		for k, r := range sh.byKey {
			out[k] = r
		}
		sh.mu.RUnlock()
	}
	return out
}
