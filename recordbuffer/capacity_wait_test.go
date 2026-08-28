// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package recordbuffer

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// TestRecordBufferAddDANonceWaitsForCapacity verifies the WAL-less full-buffer
// path: when the buffer is full, AddDANonce must NOT force a synchronous
// FlushAll (which would thundering-herd request goroutines onto flushMu).
// Instead it waits for capacity to be freed — by an external FlushAll here —
// and then appends successfully.
func TestRecordBufferAddDANonceWaitsForCapacity(t *testing.T) {
	d := testDB(t)
	// High threshold + high latency so the background drain does not free the
	// buffer on its own; capacity is freed only by the explicit FlushAll below.
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 100, 2, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	if !rb.Add(rec("00000000000000000000000000000000000000C1", "alice")) {
		t.Fatal("first Add should succeed")
	}
	if !rb.Add(rec("00000000000000000000000000000000000000C2", "bob")) {
		t.Fatal("second Add should succeed")
	}
	if !rb.IsFull() {
		t.Fatal("buffer should be full at maxPending")
	}

	done := make(chan error, 1)
	go func() {
		done <- rb.AddDANonce(daNonce(t, 0x7a))
	}()

	// Give the waiter a moment to observe the full buffer, then free capacity.
	time.Sleep(50 * time.Millisecond)
	rb.FlushAll()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("AddDANonce should succeed once capacity frees, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("AddDANonce hung after capacity was freed")
	}
}

// TestRecordBufferAddDANonceConcurrentWaits verifies the herd case: many
// concurrent AddDANonce calls against a full buffer all succeed (none deadlock,
// none is force-flushed individually) once capacity is freed.
func TestRecordBufferAddDANonceConcurrentWaits(t *testing.T) {
	d := testDB(t)
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 100, 2, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	if !rb.Add(rec("00000000000000000000000000000000000000C1", "alice")) {
		t.Fatal("Add failed")
	}
	if !rb.Add(rec("00000000000000000000000000000000000000C2", "bob")) {
		t.Fatal("Add failed")
	}

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = rb.AddDANonce(daNonce(t, byte(i)))
		}(i)
	}

	time.Sleep(50 * time.Millisecond)
	rb.FlushAll()

	wgDone := make(chan struct{})
	go func() { wg.Wait(); close(wgDone) }()
	select {
	case <-wgDone:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent AddDANonce calls deadlocked")
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("AddDANonce %d: unexpected error %v", i, err)
		}
	}
}

// TestRecordBufferAddDANonceBackpressureTimeout verifies that when the drain
// cannot free capacity (backend writes keep failing), a full-buffer AddDANonce
// returns ErrBackpressure after a bounded wait instead of blocking forever on a
// synchronous flush.
func TestRecordBufferAddDANonceBackpressureTimeout(t *testing.T) {
	old := fullWaitTimeout
	fullWaitTimeout = 300 * time.Millisecond
	defer func() { fullWaitTimeout = old }()

	d := testDB(t)
	rb, err := NewRecordBuffer(func() *db.DB { return d }, 100, 2, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	if !rb.Add(rec("00000000000000000000000000000000000000C1", "alice")) {
		t.Fatal("Add failed")
	}
	if !rb.Add(rec("00000000000000000000000000000000000000C2", "bob")) {
		t.Fatal("Add failed")
	}

	// Make every flush fail so the drain can never free capacity.
	d.Close()

	start := time.Now()
	err = rb.AddDANonce(daNonce(t, 0x7b))
	if err == nil {
		t.Fatal("AddDANonce should fail with backpressure when capacity cannot be freed")
	}
	if !errors.Is(err, ErrBackpressure) {
		t.Fatalf("want ErrBackpressure, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < fullWaitTimeout/2 || elapsed > fullWaitTimeout*4 {
		t.Fatalf("AddDANonce should time out after ~fullWaitTimeout, took %v", elapsed)
	}
}
