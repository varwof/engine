// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"container/heap"
	"sort"
	"sync"
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

// CertIndex is the primary in-memory certificate index. All certificates
// (valid and revoked) that have not yet expired out of the hot window live
// here. Records are immutable once published: revocation publishes a clone
// (copy-on-write) that replaces the original in every index, so readers
// holding a pre-revocation pointer observe a stable snapshot. Only the
// eviction-window heap retains the original instance until eviction.
type CertIndex struct {
	mu sync.RWMutex

	byKey    map[certKey]*db.CertRecord
	byIssuer map[issuerKey]*db.CertRecord
	bySPKI   map[string]map[*db.CertRecord]struct{}
	byAgent  map[string]map[*db.CertRecord]struct{}
	byUid    map[string]map[*db.CertRecord]struct{}
	byCAcn   map[caCNKey]map[*db.CertRecord]struct{}
	windows  map[string]*certHeap // ca -> min-heap by NotAfter asc (eviction order)

	// residentBytes is an estimate of the resident memory attributable to the
	// records in this index (see estimateRecordBytes). It is maintained under
	// mu and used to enforce the MaxResidentBytes byte budget.
	residentBytes int64
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

// ResidentBytes returns the estimated resident bytes of the certificate index.
func (i *CertIndex) ResidentBytes() int64 {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.residentBytes
}

// NewCertIndex creates an empty certificate index.
func NewCertIndex() *CertIndex {
	return &CertIndex{
		byKey:    make(map[certKey]*db.CertRecord),
		byIssuer: make(map[issuerKey]*db.CertRecord),
		bySPKI:   make(map[string]map[*db.CertRecord]struct{}),
		byAgent:  make(map[string]map[*db.CertRecord]struct{}),
		byUid:    make(map[string]map[*db.CertRecord]struct{}),
		byCAcn:   make(map[caCNKey]map[*db.CertRecord]struct{}),
		windows:  make(map[string]*certHeap),
	}
}

func (i *CertIndex) Len() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.byKey)
}

// put inserts a record into the primary and all secondary indexes. It must be
// called only for records not already present.
func (i *CertIndex) put(r *db.CertRecord) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.putLocked(r)
}

// insertIfAbsent inserts r atomically under the index lock, so concurrent
// IssueCert calls for the same (ca, serial) resolve consistently: exactly one
// wins the slot and others observe the existing record. When maxCerts > 0 and
// the index is at capacity, expired certificates (NotAfter < cutoff) are
// evicted first; if none can be evicted the insert is rejected with
// ErrBackpressure. The same holds for maxBytes (estimated resident byte
// budget). evicted reports how many expired certificates were removed.
func (i *CertIndex) insertIfAbsent(r *db.CertRecord, maxCerts int, maxBytes int64, cutoff time.Time) (existing *db.CertRecord, inserted bool, evicted int, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	k := certKey{ca: r.CAName, serial: r.SerialNumber}
	if existing, ok := i.byKey[k]; ok {
		return existing, false, 0, nil
	}
	if (maxCerts > 0 && len(i.byKey) >= maxCerts) ||
		(maxBytes > 0 && i.residentBytes+estimateRecordBytes(r) > maxBytes) {
		keys := i.evictExpiredLocked(cutoff)
		evicted = len(keys)
		if (maxCerts > 0 && len(i.byKey) >= maxCerts) ||
			(maxBytes > 0 && i.residentBytes+estimateRecordBytes(r) > maxBytes) {
			return nil, false, evicted, ErrBackpressure
		}
	}
	i.putLocked(r)
	return nil, true, evicted, nil
}

func (i *CertIndex) putLocked(r *db.CertRecord) {
	k := certKey{ca: r.CAName, serial: r.SerialNumber}
	i.byKey[k] = r
	i.residentBytes += estimateRecordBytes(r)

	if r.IssuerDN != "" {
		i.byIssuer[issuerKey{issuerDN: r.IssuerDN, serial: r.SerialNumber}] = r
	}
	if r.SPKIHash != "" {
		m := i.bySPKI[r.SPKIHash]
		if m == nil {
			m = make(map[*db.CertRecord]struct{})
			i.bySPKI[r.SPKIHash] = m
		}
		m[r] = struct{}{}
	}
	if r.AgentId != "" {
		m := i.byAgent[r.AgentId]
		if m == nil {
			m = make(map[*db.CertRecord]struct{})
			i.byAgent[r.AgentId] = m
		}
		m[r] = struct{}{}
	}
	if r.PrincipalUid != "" {
		m := i.byUid[r.PrincipalUid]
		if m == nil {
			m = make(map[*db.CertRecord]struct{})
			i.byUid[r.PrincipalUid] = m
		}
		m[r] = struct{}{}
	}
	if r.CommonName != "" {
		key := caCNKey{ca: r.CAName, cn: r.CommonName}
		m := i.byCAcn[key]
		if m == nil {
			m = make(map[*db.CertRecord]struct{})
			i.byCAcn[key] = m
		}
		m[r] = struct{}{}
	}
	i.windowInsertLocked(r)
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

// windowInsertLocked inserts a record into its CA's NotAfter min-heap in
// O(log n), keeping the eviction window ordered by expiry without a linear
// slice shift.
func (i *CertIndex) windowInsertLocked(r *db.CertRecord) {
	h := i.windows[r.CAName]
	if h == nil {
		h = &certHeap{}
		i.windows[r.CAName] = h
	}
	heap.Push(h, r)
}

// get returns the certificate by (ca, serial). Second return reports presence.
func (i *CertIndex) get(ca, serial string) (*db.CertRecord, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	r, ok := i.byKey[certKey{ca: ca, serial: serial}]
	return r, ok
}

// getByIssuer returns the certificate by issuer DN + serial.
func (i *CertIndex) getByIssuer(issuerDN, serial string) (*db.CertRecord, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	r, ok := i.byIssuer[issuerKey{issuerDN: issuerDN, serial: serial}]
	return r, ok
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

// getBySPKI returns certificates for a spki_hash, optionally filtered by CA
// name and status, sorted by NotBefore descending. limit <= 0 returns the full
// matching set. When limit bounds the page, the returned cursor resumes from
// the last record and hasMore reports whether another page exists.
func (i *CertIndex) getBySPKI(spkiHash, caName, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return filterSortedSetPage(i.bySPKI[spkiHash], caName, status, limit, after)
}

// getByUid returns certificates for a principal_uid, optionally filtered by
// status, sorted by NotBefore descending. See getBySPKI for pagination.
func (i *CertIndex) getByUid(uid, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return filterSortedSetPage(i.byUid[uid], "", status, limit, after)
}

// getByAgent returns certificates for an agent_id, optionally filtered by
// status, sorted by NotBefore descending. See getBySPKI for pagination.
func (i *CertIndex) getByAgent(agent, status string, limit int, after *CertCursor) ([]*db.CertRecord, *CertCursor, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return filterSortedSetPage(i.byAgent[agent], "", status, limit, after)
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

// getActiveByCN returns active (status='V') certificates for a CA + CN.
func (i *CertIndex) getActiveByCN(ca, cn string) []*db.CertRecord {
	i.mu.RLock()
	defer i.mu.RUnlock()
	var out []*db.CertRecord
	for r := range i.byCAcn[caCNKey{ca: ca, cn: cn}] {
		if r.Status == "V" {
			out = append(out, r)
		}
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
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.setRevokedLocked(certKey{ca: ca, serial: serial}, now, reason)
}

// bulkSetRevoked marks a set of certificates revoked under a single lock
// acquisition (the revocation-storm fast path). For each pair it reports the
// published (revoked) record when the cert was active, and the keys that are
// not resident in memory (so callers can distinguish "already revoked" from
// "not resident"). Non-active or already-revoked certs are skipped.
func (i *CertIndex) bulkSetRevoked(pairs []revokePair, now time.Time) (revoked []*db.CertRecord, missing []certKey) {
	i.mu.Lock()
	defer i.mu.Unlock()
	revoked = make([]*db.CertRecord, 0, len(pairs))
	for _, p := range pairs {
		k := certKey{ca: p.CA, serial: p.Serial}
		if _, ok := i.byKey[k]; !ok {
			missing = append(missing, k)
			continue
		}
		if clone, ok := i.setRevokedLocked(k, now, p.Reason); ok {
			revoked = append(revoked, clone)
		}
	}
	return revoked, missing
}

// setRevokedLocked publishes a revoked copy of the record identified by key.
// The original instance is never mutated — a clone carries the revoked fields
// and replaces the original in every index (copy-on-write), so concurrent
// readers that already hold the old pointer observe a stable pre-revocation
// snapshot and never see a half-updated record. Returns the published clone.
// The caller must hold the index lock.
func (i *CertIndex) setRevokedLocked(key certKey, now time.Time, reason int) (*db.CertRecord, bool) {
	old, ok := i.byKey[key]
	if !ok || old.Status == "R" {
		return nil, false
	}
	clone := *old
	clone.Status = "R"
	clone.RevokedAt = &now
	clone.RevokeReason = &reason
	clone.InvalidityDate = &now
	i.replaceLocked(old, &clone)
	return &clone, true
}

// replaceLocked swaps the published instance of a record for a new instance
// across the primary and all secondary indexes. The eviction-window heap keeps
// the old instance (a stable pre-replacement snapshot); removeLocked resolves
// the current instance by key so pointer-keyed deletions still match. The
// caller must hold the index lock.
func (i *CertIndex) replaceLocked(old, new *db.CertRecord) {
	k := certKey{ca: old.CAName, serial: old.SerialNumber}
	i.byKey[k] = new
	i.residentBytes -= estimateRecordBytes(old)
	i.residentBytes += estimateRecordBytes(new)

	if old.IssuerDN != "" {
		ik := issuerKey{issuerDN: old.IssuerDN, serial: old.SerialNumber}
		delete(i.byIssuer, ik)
		i.byIssuer[ik] = new
	}
	if old.SPKIHash != "" {
		m := i.bySPKI[old.SPKIHash]
		delete(m, old)
		m[new] = struct{}{}
	}
	if old.AgentId != "" {
		m := i.byAgent[old.AgentId]
		delete(m, old)
		m[new] = struct{}{}
	}
	if old.PrincipalUid != "" {
		m := i.byUid[old.PrincipalUid]
		delete(m, old)
		m[new] = struct{}{}
	}
	if old.CommonName != "" {
		m := i.byCAcn[caCNKey{ca: old.CAName, cn: old.CommonName}]
		delete(m, old)
		m[new] = struct{}{}
	}
}

// bulkSetRevokedByUid marks every active certificate of a principal revoked
// and returns them. The mutation runs under the index lock (single revoke uses
// the same helper), so bulk revocation is race-free against concurrent reads.
func (i *CertIndex) bulkSetRevokedByUid(uid string, now time.Time, reason int) []*db.CertRecord {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []*db.CertRecord
	for r := range i.byUid[uid] {
		if r.Status == "V" {
			k := certKey{ca: r.CAName, serial: r.SerialNumber}
			if clone, ok := i.setRevokedLocked(k, now, reason); ok {
				out = append(out, clone)
			}
		}
	}
	return out
}

// bulkSetRevokedByCA marks every active certificate issued by a CA revoked and
// returns them. The mutation runs under the index lock.
func (i *CertIndex) bulkSetRevokedByCA(caName string, now time.Time, reason int) []*db.CertRecord {
	i.mu.Lock()
	defer i.mu.Unlock()
	var out []*db.CertRecord
	for _, r := range i.byKey {
		if r.CAName == caName && r.Status == "V" {
			k := certKey{ca: r.CAName, serial: r.SerialNumber}
			if clone, ok := i.setRevokedLocked(k, now, reason); ok {
				out = append(out, clone)
			}
		}
	}
	return out
}

// evictExpired removes every certificate whose NotAfter is strictly before
// cutoff from all indexes. It uses each CA's NotAfter-sorted window to find
// the eviction boundary in O(log n), then drops those records from the
// secondary maps. Returns the evicted certificates' primary keys so callers
// (e.g. the janitor) can cascade-clean related rows such as AIC extensions.
func (i *CertIndex) evictExpired(cutoff time.Time) []certKey {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.evictExpiredLocked(cutoff)
}

// evictExpiredLocked is evictExpired with the index lock already held.
func (i *CertIndex) evictExpiredLocked(cutoff time.Time) []certKey {
	var evicted []certKey
	for ca, h := range i.windows {
		if h == nil || h.Len() == 0 {
			continue
		}
		// Heap top is the earliest NotAfter; pop while it is expired.
		for h.Len() > 0 && (*h)[0].NotAfter.Before(cutoff) {
			r := heap.Pop(h).(*db.CertRecord)
			i.removeLocked(r)
			evicted = append(evicted, certKey{ca: r.CAName, serial: r.SerialNumber})
		}
		if h.Len() == 0 {
			delete(i.windows, ca)
		}
	}
	return evicted
}

// removeLocked removes a record from the primary and all secondary indexes.
// The eviction-window heap may hold a pre-revocation pointer (copy-on-write
// revocation never re-publishes into the heap), so the current published
// instance is resolved by primary key before the pointer-keyed deletions run.
func (i *CertIndex) removeLocked(r *db.CertRecord) {
	k := certKey{ca: r.CAName, serial: r.SerialNumber}
	cur, ok := i.byKey[k]
	if !ok {
		return // already removed
	}
	r = cur
	delete(i.byKey, k)
	i.residentBytes -= estimateRecordBytes(r)
	if r.IssuerDN != "" {
		delete(i.byIssuer, issuerKey{issuerDN: r.IssuerDN, serial: r.SerialNumber})
	}
	if r.SPKIHash != "" {
		if m := i.bySPKI[r.SPKIHash]; m != nil {
			delete(m, r)
			if len(m) == 0 {
				delete(i.bySPKI, r.SPKIHash)
			}
		}
	}
	if r.AgentId != "" {
		if m := i.byAgent[r.AgentId]; m != nil {
			delete(m, r)
			if len(m) == 0 {
				delete(i.byAgent, r.AgentId)
			}
		}
	}
	if r.PrincipalUid != "" {
		if m := i.byUid[r.PrincipalUid]; m != nil {
			delete(m, r)
			if len(m) == 0 {
				delete(i.byUid, r.PrincipalUid)
			}
		}
	}
	if r.CommonName != "" {
		key := caCNKey{ca: r.CAName, cn: r.CommonName}
		if m := i.byCAcn[key]; m != nil {
			delete(m, r)
			if len(m) == 0 {
				delete(i.byCAcn, key)
			}
		}
	}
}
