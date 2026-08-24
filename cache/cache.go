// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// Package cache provides thread-safe, bounded in-memory caches used by the
// varwof-db-lib memory engine for hot-path read acceleration.
//
// Two families are provided:
//
//   - Cache: a generic TTL cache with a bounded entry count and best-effort
//     eviction of expired entries when full (the "short-TTL lookup" pattern).
//     Used for mTLS handshake revocation status (issuerDN+serial → revoked)
//     and derived auth scopes (username → scopes).
//
//   - LRU: an LRU cache whose entries are indexed by a secondary "serial"
//     key so that a single invalidation (e.g. cert revoked) can drop every
//     entry that references that serial. Used for OCSP response caching
//     (request-hash key → DER response, grouped by cert serial).
package cache

import (
	"container/heap"
	"container/list"
	"sync"
	"time"
)

// Entry is a single cached value with an expiration time.
type Entry struct {
	value any
	exp   time.Time
}

// expEntry is a heap node tracking one key's expiry. The heap is kept in sync
// with entries: overwrites use heap.Fix and deletes use heap.Remove, so the
// heap never grows stale (unlike a lazy push-only design).
type expEntry struct {
	key   string
	exp   time.Time
	index int
}

// expHeap is a min-heap by expiry; the top is always the earliest-expiring key.
type expHeap []*expEntry

func (h expHeap) Len() int           { return len(h) }
func (h expHeap) Less(i, j int) bool { return h[i].exp.Before(h[j].exp) }
func (h expHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index, h[j].index = i, j }
func (h *expHeap) Push(x any)        { e := x.(*expEntry); e.index = len(*h); *h = append(*h, e) }
func (h *expHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	e.index = -1
	*h = old[:n-1]
	return e
}

// Cache is a thread-safe, bounded TTL cache.
//
// Design notes (extracted from varwof-core's handshake revocation cache and auth
// scopes cache):
//   - Lookups are O(1) via a map guarded by a mutex. The critical path
//     (mTLS handshake) performs one map read per chain cert; hits take the
//     read lock only, so parallel readers do not serialize.
//   - Bounded by MaxEntries. When full, expired entries are reclaimed via the
//     expiry min-heap (O(log n) per reclaim, not a full-map scan); if still
//     full, new entries are dropped rather than growing unbounded.
//   - Expired entries are removed lazily on read (Get) and on insert-when-full.
type Cache struct {
	mu         sync.RWMutex
	entries    map[string]Entry
	heap       expHeap
	heapIndex  map[string]*expEntry
	ttl        time.Duration
	maxEntries int
}

// NewCache creates a bounded TTL cache. ttl must be > 0; maxEntries bounds the
// number of live entries (0 = unbounded, not recommended for hot paths).
func NewCache(ttl time.Duration, maxEntries int) *Cache {
	return &Cache{
		entries:    make(map[string]Entry),
		heapIndex:  make(map[string]*expEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

// Get returns the cached value for key and whether it was present and fresh.
// Expired entries are removed on access. A hit never mutates the map, so it
// takes only the read lock and parallel readers do not serialize.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}
	if time.Now().After(e.exp) {
		c.mu.RUnlock()
		c.mu.Lock()
		c.removeLocked(key)
		c.mu.Unlock()
		return nil, false
	}
	c.mu.RUnlock()
	return e.value, true
}

// Set stores value under key with the cache TTL. If the cache is full and no
// expired entries can be reclaimed, the value is dropped.
func (c *Cache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := time.Now().Add(c.ttl)
	if _, ok := c.entries[key]; ok {
		// Overwrite in place; Fix keeps the heap ordered without a stale node.
		c.entries[key] = Entry{value: value, exp: exp}
		if e := c.heapIndex[key]; e != nil {
			e.exp = exp
			heap.Fix(&c.heap, e.index)
		}
		return
	}
	if c.maxEntries > 0 && len(c.entries) >= c.maxEntries && !c.reclaimExpiredLocked() {
		return // still full after reclaim: drop new entry
	}
	c.entries[key] = Entry{value: value, exp: exp}
	e := &expEntry{key: key, exp: exp}
	heap.Push(&c.heap, e)
	c.heapIndex[key] = e
}

// reclaimExpiredLocked drops every expired entry. The heap top is the globally
// earliest expiry, so once it is fresh nothing else can be expired and the
// scan stops. Returns whether a slot was freed.
func (c *Cache) reclaimExpiredLocked() bool {
	now := time.Now()
	for len(c.heap) > 0 && !c.heap[0].exp.After(now) {
		e := heap.Pop(&c.heap).(*expEntry)
		delete(c.heapIndex, e.key)
		if cur, ok := c.entries[e.key]; ok && !cur.exp.After(now) {
			delete(c.entries, e.key)
		}
	}
	return len(c.entries) < c.maxEntries
}

// removeLocked deletes a key from the map and its heap node.
func (c *Cache) removeLocked(key string) {
	delete(c.entries, key)
	if e := c.heapIndex[key]; e != nil {
		heap.Remove(&c.heap, e.index)
		delete(c.heapIndex, key)
	}
}

// Delete removes a single key.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
}

// DeleteMatching removes every entry whose key satisfies pred. Used for
// bulk invalidation (e.g. all revoked certificates of one issuer).
func (c *Cache) DeleteMatching(pred func(key string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if pred(k) {
			c.removeLocked(k)
		}
	}
}

// Len returns the number of live entries (approximate; expired entries are
// not purged by this call).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// LRUEntry is a single LRU cache entry, grouped by an optional serial key.
type LRUEntry struct {
	key    string
	serial string
	data   []byte
	exp    time.Time
}

// LRU is a thread-safe, bounded LRU cache whose entries can be invalidated in
// bulk by a secondary "serial" key (extracted from varwof-core's internal/ocsp
// cache). On overflow the least-recently-used entry is evicted. Entries expire
// by TTL and are removed lazily on read.
type LRU struct {
	mu        sync.Mutex
	entries   map[string]*list.Element
	serialIdx map[string]map[string]struct{} // serial → set of keys
	order     *list.List
	maxSize   int
	ttl       time.Duration
}

// NewLRU creates a bounded LRU cache. maxSize bounds live entries; ttl > 0
// governs entry lifetime.
func NewLRU(maxSize int, ttl time.Duration) *LRU {
	return &LRU{
		entries:   make(map[string]*list.Element),
		serialIdx: make(map[string]map[string]struct{}),
		order:     list.New(),
		maxSize:   maxSize,
		ttl:       ttl,
	}
}

// Get returns the cached bytes for key and whether it was present and fresh.
// A hit moves the entry to the front (LRU order); an expired entry is removed.
func (c *LRU) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	ent := elem.Value.(*LRUEntry)
	if time.Now().After(ent.exp) {
		c.removeLocked(elem)
		return nil, false
	}
	c.order.MoveToFront(elem)
	return ent.data, true
}

// Set stores data under key with no serial grouping.
func (c *LRU) Set(key string, data []byte) {
	c.SetWithSerial(key, "", data)
}

// SetWithSerial stores data under key and records the serial association so
// PurgeSerial can drop the entry later. Overwrites the existing key if present.
func (c *LRU) SetWithSerial(key, serial string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[key]; ok {
		ent := elem.Value.(*LRUEntry)
		ent.data = data
		ent.exp = time.Now().Add(c.ttl)
		c.order.MoveToFront(elem)
		return
	}
	if c.order.Len() >= c.maxSize {
		if back := c.order.Back(); back != nil {
			c.removeLocked(back)
		}
	}
	ent := &LRUEntry{key: key, serial: serial, data: data, exp: time.Now().Add(c.ttl)}
	elem := c.order.PushFront(ent)
	c.entries[key] = elem
	if serial != "" {
		if _, ok := c.serialIdx[serial]; !ok {
			c.serialIdx[serial] = make(map[string]struct{})
		}
		c.serialIdx[serial][key] = struct{}{}
	}
}

// PurgeSerial drops every entry associated with the given serial.
// Used when a certificate is revoked so stale OCSP responses fail closed.
func (c *LRU) PurgeSerial(serial string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys, ok := c.serialIdx[serial]
	if !ok {
		return
	}
	for key := range keys {
		if elem, ok := c.entries[key]; ok {
			c.order.Remove(elem)
			delete(c.entries, key)
		}
	}
	delete(c.serialIdx, serial)
}

func (c *LRU) removeLocked(elem *list.Element) {
	ent := elem.Value.(*LRUEntry)
	c.order.Remove(elem)
	delete(c.entries, ent.key)
	if ent.serial != "" {
		if keys, ok := c.serialIdx[ent.serial]; ok {
			delete(keys, ent.key)
			if len(keys) == 0 {
				delete(c.serialIdx, ent.serial)
			}
		}
	}
}

// Len returns the current number of live entries.
func (c *LRU) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
