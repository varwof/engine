// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package cache

import (
	"strconv"
	"testing"
	"time"
)

// BenchmarkCacheGetHit measures the mTLS handshake revocation lookup pattern:
// parallel reads over a bounded TTL cache (single mutex, no mutation on hit).
func BenchmarkCacheGetHit(b *testing.B) {
	c := NewCache(time.Minute, 1<<20)
	for i := 0; i < 1000; i++ {
		c.Set("key-"+strconv.Itoa(i), i)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for i := 0; pb.Next(); i++ {
			c.Get("key-" + strconv.Itoa(i%1000))
		}
	})
}

// BenchmarkCacheGetMiss measures the miss path (unknown key lookup).
func BenchmarkCacheGetMiss(b *testing.B) {
	c := NewCache(time.Minute, 1<<20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get("missing-key")
	}
}

// BenchmarkCacheSet measures Set over a fixed key set (overwrite, no growth).
func BenchmarkCacheSet(b *testing.B) {
	c := NewCache(time.Minute, 1<<20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set("key-"+strconv.Itoa(i%1000), i)
	}
}

// BenchmarkCacheSetAtCapacity measures Set when the cache is full and nothing
// is expired: the new value is dropped. The expiry heap makes this O(1) —
// previously it was an O(maxEntries) full-map scan on every Set.
func BenchmarkCacheSetAtCapacity(b *testing.B) {
	c := NewCache(time.Hour, 1000)
	for i := 0; i < 1000; i++ {
		c.Set("key-"+strconv.Itoa(i), i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set("overflow-"+strconv.Itoa(i), i)
	}
}

// BenchmarkLRUGetHit measures the OCSP response lookup pattern: parallel reads
// over an LRU where a hit moves the entry to the front.
func BenchmarkLRUGetHit(b *testing.B) {
	l := NewLRU(1<<20, time.Minute)
	for i := 0; i < 1000; i++ {
		l.Set("key-"+strconv.Itoa(i), []byte("data"))
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for i := 0; pb.Next(); i++ {
			l.Get("key-" + strconv.Itoa(i%1000))
		}
	})
}

// BenchmarkLRUSetWithSerial measures SetWithSerial over a bounded key space
// (overwrite path with serial-index maintenance).
func BenchmarkLRUSetWithSerial(b *testing.B) {
	l := NewLRU(10000, time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.SetWithSerial("key-"+strconv.Itoa(i%10000),
			"serial-"+strconv.Itoa(i%100), []byte("data"))
	}
}

// BenchmarkLRUPurgeSerialMiss measures the common revocation-invalidation case
// where the serial is not cached (fast no-op).
func BenchmarkLRUPurgeSerialMiss(b *testing.B) {
	l := NewLRU(1<<20, time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.PurgeSerial("serial-" + strconv.Itoa(i))
	}
}

// BenchmarkLRUPurgeSerialHit100 measures PurgeSerial when the serial has 100
// cached entries. Re-population runs outside the timed loop.
func BenchmarkLRUPurgeSerialHit100(b *testing.B) {
	l := NewLRU(1<<20, time.Minute)
	const perSerial = 100
	for j := 0; j < perSerial; j++ {
		l.SetWithSerial("key-"+strconv.Itoa(j), "serial-1", []byte("data"))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for j := 0; j < perSerial; j++ {
			l.SetWithSerial("key-"+strconv.Itoa(j), "serial-1", []byte("data"))
		}
		b.StartTimer()
		l.PurgeSerial("serial-1")
	}
	if l.Len() != 0 {
		b.Fatalf("expected empty cache after purge, len=%d", l.Len())
	}
}
