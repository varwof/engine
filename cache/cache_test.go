// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package cache

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestCacheGetSet(t *testing.T) {
	c := NewCache(time.Minute, 10)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected miss")
	}
	c.Set("k", "v")
	v, ok := c.Get("k")
	if !ok || v != "v" {
		t.Fatalf("expected hit with v, got %v/%v", v, ok)
	}
}

func TestCacheExpiry(t *testing.T) {
	c := NewCache(30*time.Millisecond, 10)
	c.Set("k", "v")
	time.Sleep(50 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected expiry miss")
	}
}

func TestCacheBounded(t *testing.T) {
	c := NewCache(time.Minute, 2)
	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3) // no expired entries to reclaim → dropped
	if c.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", c.Len())
	}
}

func TestCacheDeleteAndMatching(t *testing.T) {
	c := NewCache(time.Minute, 10)
	c.Set("a", 1)
	c.Set("b", 2)
	c.Delete("a")
	if _, ok := c.Get("a"); ok {
		t.Fatal("expected a deleted")
	}
	c.Set("a", 1)
	c.DeleteMatching(func(k string) bool { return k == "a" || k == "b" })
	if c.Len() != 0 {
		t.Fatalf("expected empty, got %d", c.Len())
	}
}

// TestCacheReclaimWhenFullWithExpired verifies that a full cache reclaims
// expired entries via the expiry heap instead of dropping the new value.
func TestCacheReclaimWhenFullWithExpired(t *testing.T) {
	c := NewCache(30*time.Millisecond, 2)
	c.Set("a", 1)
	c.Set("b", 2)
	time.Sleep(50 * time.Millisecond) // "a" and "b" expire
	c.Set("c", 3)                     // reclaims a (and b), inserts c
	if c.Len() != 1 {
		t.Fatalf("expected 1 reclaimed entry, got %d", c.Len())
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatal("expected c present")
	}
}

// TestCacheOverwriteHeapConsistency exercises the heap.Fix path: overwriting a
// key must not leave a stale heap node that later claims a slot or leaks.
func TestCacheOverwriteHeapConsistency(t *testing.T) {
	c := NewCache(time.Minute, 2)
	for i := 0; i < 50; i++ {
		c.Set("hot", i)
	}
	if c.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", c.Len())
	}
	c.Set("b", 2)
	c.Set("c", 3) // full, nothing expired → dropped
	if c.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", c.Len())
	}
	if v, ok := c.Get("hot"); !ok || v != 49 {
		t.Fatalf("expected hot=49, got %v/%v", v, ok)
	}
	c.Delete("hot")
	c.Delete("b")
	if c.Len() != 0 {
		t.Fatalf("expected empty after delete, got %d", c.Len())
	}
	// Heap must be drained; a subsequent Set should not resurrect stale nodes.
	c.Set("d", 4)
	if v, ok := c.Get("d"); !ok || v != 4 {
		t.Fatalf("expected d=4, got %v/%v", v, ok)
	}
}

// TestCacheReclaimMixedExpired verifies the heap reclaim only frees expired
// slots and leaves fresh entries intact at capacity.
func TestCacheReclaimMixedExpired(t *testing.T) {
	c := NewCache(40*time.Millisecond, 3)
	c.Set("expire1", 1)
	c.Set("expire2", 3)
	time.Sleep(60 * time.Millisecond) // both expire
	c.Set("keep", 2)                  // fills to capacity (3), keep fresh
	c.Set("new", 4)                   // reclaims expire1+expire2, keeps keep+new
	if c.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", c.Len())
	}
	if _, ok := c.Get("keep"); !ok {
		t.Fatal("expected keep present")
	}
	if _, ok := c.Get("new"); !ok {
		t.Fatal("expected new present")
	}
}

// TestCacheConcurrent hammers the heap-backed cache from many goroutines,
// mixing Set (overwrite + heap.Fix), Get (lazy expiry removal + heap.Remove),
// Delete, and DeleteMatching. Designed to run under -race in CI.
func TestCacheConcurrent(t *testing.T) {
	c := NewCache(5*time.Millisecond, 256)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < 5000; i++ {
				k := fmt.Sprintf("k%d", rng.Intn(512))
				switch rng.Intn(4) {
				case 0:
					c.Set(k, i)
				case 1:
					c.Get(k)
				case 2:
					c.Delete(k)
				case 3:
					c.DeleteMatching(func(key string) bool { return key[0] == 'k' })
				}
			}
		}(int64(g))
	}
	wg.Wait()
	if n := c.Len(); n > 256 {
		t.Fatalf("len %d exceeds bound", n)
	}
}

// TestLRUConcurrent exercises LRU Get/Set/PurgeSerial concurrently.
func TestLRUConcurrent(t *testing.T) {
	c := NewLRU(256, 5*time.Millisecond)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < 5000; i++ {
				k := fmt.Sprintf("key%d", rng.Intn(512))
				s := fmt.Sprintf("serial%d", rng.Intn(32))
				switch rng.Intn(4) {
				case 0:
					c.SetWithSerial(k, s, []byte("data"))
				case 1:
					c.Get(k)
				case 2:
					c.PurgeSerial(s)
				case 3:
					c.Set(k, []byte("data"))
				}
			}
		}(int64(g))
	}
	wg.Wait()
	if n := c.Len(); n > 256 {
		t.Fatalf("len %d exceeds bound", n)
	}
}

func TestLRUGetSet(t *testing.T) {
	c := NewLRU(2, time.Minute)
	c.Set("a", []byte("1"))
	c.Set("b", []byte("2"))
	c.Set("c", []byte("3")) // evicts a (LRU)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expected a evicted")
	}
	if v, ok := c.Get("c"); !ok || string(v) != "3" {
		t.Fatal("expected c present")
	}
}

func TestLRUExpiry(t *testing.T) {
	c := NewLRU(10, 30*time.Millisecond)
	c.Set("a", []byte("1"))
	time.Sleep(50 * time.Millisecond)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expected expiry miss")
	}
}

func TestLRUPurgeSerial(t *testing.T) {
	c := NewLRU(10, time.Minute)
	c.SetWithSerial("k1", "S1", []byte("1"))
	c.SetWithSerial("k2", "S1", []byte("2"))
	c.SetWithSerial("k3", "S2", []byte("3"))
	c.PurgeSerial("S1")
	if _, ok := c.Get("k1"); ok {
		t.Fatal("expected k1 purged")
	}
	if _, ok := c.Get("k2"); ok {
		t.Fatal("expected k2 purged")
	}
	if v, ok := c.Get("k3"); !ok || string(v) != "3" {
		t.Fatal("expected k3 present")
	}
	c.PurgeSerial("S1") // no-op
}
