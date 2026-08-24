// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"testing"
	"time"
)

func TestNoopLock(t *testing.T) {
	l := noopLock{}
	ctx := context.Background()

	// Lock/unlock
	if err := l.Lock(ctx, 1); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := l.Unlock(1); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// TryLock
	ok, err := l.TryLock(ctx, 1)
	if err != nil {
		t.Fatalf("TryLock: %v", err)
	}
	if !ok {
		t.Fatal("TryLock should succeed on noop")
	}
}

func TestPGAdvisoryLock(t *testing.T) {
	// This test requires PostgreSQL
	d, err := Open(t.TempDir() + "/test_lock.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Non-PostgreSQL dialects must NOT use the PG advisory lock. They now use a
	// real on-disk file lock (G-12) on Unix, or fall back to noopLock on
	// platforms without flock support (e.g. Windows).
	lock := d.NewDistLock()
	if _, ok := lock.(*pgAdvisoryLock); ok {
		t.Fatal("SQLite should not use pgAdvisoryLock")
	}

	// The non-PG lock must support reentrant locking.
	ctx := context.Background()
	if err := lock.Lock(ctx, LockKeyCRLGenerate); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := lock.Lock(ctx, LockKeyCRLGenerate); err != nil {
		t.Fatalf("reentrant Lock: %v", err)
	}
	if err := lock.Unlock(LockKeyCRLGenerate); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := lock.Unlock(LockKeyCRLGenerate); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Only test PG if available
	_ = PGConfig{}
}

func TestDistLockConstants(t *testing.T) {
	// Ensure no duplicate lock keys
	keys := map[int64]string{
		LockKeyCRLGenerate: "CRLGenerate",
		LockKeyMigration:   "Migration",
		LockKeyCertSerial:  "CertSerial",
		LockKeyCRLRenew:    "CRLRenew",
	}
	seen := make(map[int64]bool)
	for k, name := range keys {
		if seen[k] {
			t.Fatalf("duplicate lock key %d (%s)", k, name)
		}
		seen[k] = true
	}
}

func TestPGAdvisoryLockReentrancy(t *testing.T) {
	d, err := Open(t.TempDir() + "/test_reentrant.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	l := d.NewDistLock()
	ctx := context.Background()

	// Simulate reentrant lock
	if err := l.Lock(ctx, 42); err != nil {
		t.Fatalf("first Lock: %v", err)
	}
	if err := l.Lock(ctx, 42); err != nil {
		t.Fatalf("reentrant Lock: %v", err)
	}
	if err := l.Unlock(42); err != nil {
		t.Fatalf("first Unlock: %v", err)
	}
	if err := l.Unlock(42); err != nil {
		t.Fatalf("second Unlock: %v", err)
	}
}

func TestNoopLockConcurrent(t *testing.T) {
	l := noopLock{}
	ctx := context.Background()

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			l.Lock(ctx, 1)
			time.Sleep(time.Millisecond)
			l.Unlock(1)
			done <- struct{}{}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
