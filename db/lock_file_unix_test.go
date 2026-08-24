// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build !windows

package db

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFileLockReentrantAndRelease(t *testing.T) {
	dir := t.TempDir()
	d := &DB{path: filepath.Join(dir, "pki.db")}
	lk := newFileLock(d)
	ctx := context.Background()

	if ok, err := lk.TryLock(ctx, LockKeyCRLGenerate); err != nil || !ok {
		t.Fatalf("TryLock: ok=%v err=%v", ok, err)
	}
	// Reentrant acquire on the same key must succeed without blocking.
	if ok, err := lk.TryLock(ctx, LockKeyCRLGenerate); err != nil || !ok {
		t.Fatalf("reentrant TryLock: ok=%v err=%v", ok, err)
	}
	// A different key must be independently acquirable.
	if ok, err := lk.TryLock(ctx, LockKeyMigration); err != nil || !ok {
		t.Fatalf("TryLock other key: ok=%v err=%v", ok, err)
	}
	if err := lk.Unlock(LockKeyCRLGenerate); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := lk.Unlock(LockKeyCRLGenerate); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := lk.Unlock(LockKeyMigration); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

// TestFileLockBlocksConcurrentProcess spawns a child copy of this test binary
// that attempts a non-blocking flock on a lock file the parent holds, proving
// the file lock coordinates across processes (G-12).
func TestFileLockBlocksConcurrentProcess(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "varwof-engine.lock.99")

	// Parent holds the lock.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if err := syscallFlock(int(f.Fd()), true, true); err != nil {
		t.Fatalf("parent flock: %v", err)
	}

	// Child must fail to acquire (lock held).
	child := exec.Command(os.Args[0], "-test.run=TestFileLockHelper", "-test.v")
	child.Env = append(os.Environ(), "PKI_LOCK_HELPER="+lockPath, "PKI_LOCK_EXPECT=blocked")
	if err := child.Run(); err == nil {
		t.Fatal("expected child flock to fail (lock held by parent)")
	}

	// Release parent; child must now succeed.
	if err := syscallFlock(int(f.Fd()), false, true); err != nil {
		t.Fatalf("parent unlock: %v", err)
	}
	child2 := exec.Command(os.Args[0], "-test.run=TestFileLockHelper", "-test.v")
	child2.Env = append(os.Environ(), "PKI_LOCK_HELPER="+lockPath, "PKI_LOCK_EXPECT=acquired")
	if err := child2.Run(); err != nil {
		t.Fatalf("expected child flock to succeed after release: %v", err)
	}
}

// TestFileLockHelper is the subprocess entrypoint for the cross-process test.
// It is gated by the PKI_LOCK_HELPER env var so it does nothing when run
// normally.
func TestFileLockHelper(t *testing.T) {
	lockPath := os.Getenv("PKI_LOCK_HELPER")
	if lockPath == "" {
		t.Skip("not a lock helper subprocess")
	}
	expect := os.Getenv("PKI_LOCK_EXPECT") // "blocked" or "acquired"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	err = syscallFlock(int(f.Fd()), true, false) // non-blocking acquire
	acquired := err == nil
	if acquired {
		_ = syscallFlock(int(f.Fd()), false, true) // release
	}
	switch expect {
	case "acquired":
		if !acquired {
			t.Fatalf("expected to acquire lock, got error: %v", err)
		}
	case "blocked":
		if acquired {
			t.Fatal("expected lock to be blocked, but acquired")
		}
	}
}
