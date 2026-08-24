// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeNonSQLiteDialect overrides only DriverName so non-SQLite branches that
// key off the driver string can be exercised without a real PG/MySQL server.
type fakeNonSQLiteDialect struct {
	SQLiteDialect
}

func (fakeNonSQLiteDialect) DriverName() string { return "pgx" }

func newLockForDir(t *testing.T, dir, name string) *fileLock {
	t.Helper()
	l := newFileLock(&DB{path: filepath.Join(dir, name)})
	fl, ok := l.(*fileLock)
	if !ok {
		t.Fatal("expected fileLock implementation")
	}
	return fl
}

// TestFileLockBasic covers acquire, TryLock, reentrancy, and release.
func TestFileLockBasic(t *testing.T) {
	l := newLockForDir(t, t.TempDir(), "a.db")
	ctx := context.Background()

	if err := l.Lock(ctx, LockKeyMigration); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	// Reentrant acquire must succeed without deadlock and bump the refcount.
	if err := l.Lock(ctx, LockKeyMigration); err != nil {
		t.Fatalf("reentrant Lock: %v", err)
	}
	if l.held[LockKeyMigration].refcount != 2 {
		t.Fatalf("refcount = %d, want 2", l.held[LockKeyMigration].refcount)
	}
	// Release twice to drop the refcount to zero and actually unlock.
	for i := 0; i < 2; i++ {
		if err := l.Unlock(LockKeyMigration); err != nil {
			t.Fatalf("Unlock %d: %v", i, err)
		}
	}
	if h, ok := l.held[LockKeyMigration]; ok {
		t.Fatalf("held entry not released: %+v", h)
	}

	if ok, err := l.TryLock(ctx, LockKeyCRLGenerate); err != nil || !ok {
		t.Fatalf("TryLock: ok=%v err=%v", ok, err)
	}
	if ok, err := l.TryLock(ctx, LockKeyCRLGenerate); err != nil || !ok {
		t.Fatalf("reentrant TryLock: ok=%v err=%v", ok, err)
	}
	if err := l.Unlock(LockKeyCRLGenerate); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := l.Unlock(LockKeyCRLGenerate); err != nil {
		t.Fatalf("Unlock to zero: %v", err)
	}
}

// TestFileLockContention verifies a second lock instance on the same directory
// cannot acquire while the first holds the key (cross-process coordination).
func TestFileLockContention(t *testing.T) {
	dir := t.TempDir()
	l1 := newLockForDir(t, dir, "a.db")
	l2 := newLockForDir(t, dir, "b.db")
	ctx := context.Background()

	if ok, err := l1.TryLock(ctx, LockKeyMigration); err != nil || !ok {
		t.Fatalf("l1 TryLock: ok=%v err=%v", ok, err)
	}
	if ok, err := l2.TryLock(ctx, LockKeyMigration); err != nil || ok {
		t.Fatalf("l2 TryLock should fail while l1 holds: ok=%v err=%v", ok, err)
	}
	if err := l1.Unlock(LockKeyMigration); err != nil {
		t.Fatal(err)
	}
	if ok, err := l2.TryLock(ctx, LockKeyMigration); err != nil || !ok {
		t.Fatalf("l2 TryLock after release: ok=%v err=%v", ok, err)
	}
	if err := l2.Unlock(LockKeyMigration); err != nil {
		t.Fatal(err)
	}
}

// TestFileLockContextCancel verifies Lock honours a cancelled context: the
// in-flight blocking flock is allowed to complete, then the lock is released
// and context.Err() returned.
func TestFileLockContextCancel(t *testing.T) {
	dir := t.TempDir()
	l1 := newLockForDir(t, dir, "a.db")
	l2 := newLockForDir(t, dir, "b.db")

	if err := l1.Lock(context.Background(), LockKeyMigration); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Lock

	// Release l1 shortly so l2's in-flight flock can complete.
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = l1.Unlock(LockKeyMigration)
	}()

	if err := l2.Lock(ctx, LockKeyMigration); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	// l2 must have cleaned up its own acquired lock.
	if _, ok := l2.held[LockKeyMigration]; ok {
		t.Fatal("l2 must not hold the key after cancellation")
	}
}

// TestFileLockUnlockUnknown verifies unlocking an unheld key is a no-op.
func TestFileLockUnlockUnknown(t *testing.T) {
	l := newLockForDir(t, t.TempDir(), "a.db")
	if err := l.Unlock(999); err != nil {
		t.Fatalf("Unlock of unheld key: %v", err)
	}
}

// TestNewDistLockNonPG verifies SQLite returns the file-backed lock and that
// NewDistLock is reentrant-safe through the public interface.
func TestNewDistLockNonPG(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()
	l := d.NewDistLock()
	if err := l.Lock(ctx, LockKeyCertSerial); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := l.Lock(ctx, LockKeyCertSerial); err != nil {
		t.Fatalf("reentrant Lock: %v", err)
	}
	if err := l.Unlock(LockKeyCertSerial); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := l.Unlock(LockKeyCertSerial); err != nil {
		t.Fatalf("final Unlock: %v", err)
	}
}

// TestPGAdvisoryLockReentrantAndErrors exercises the PG-only advisory lock's
// reentrancy bookkeeping against a SQLite backend: reentrant paths never touch
// the DB, and any real PG call fails cleanly.
func TestPGAdvisoryLockReentrantAndErrors(t *testing.T) {
	d := newTestDB(t)
	l := newPGAdvisoryLock(d)
	ctx := context.Background()

	// White-box: key already held → Lock/TryLock are reentrant, no DB call.
	l.held[1] = 1
	if err := l.Lock(ctx, 1); err != nil {
		t.Fatalf("reentrant Lock: %v", err)
	}
	if ok, err := l.TryLock(ctx, 1); err != nil || !ok {
		t.Fatalf("reentrant TryLock: ok=%v err=%v", ok, err)
	}
	if l.held[1] != 3 {
		t.Fatalf("held[1] = %d, want 3", l.held[1])
	}
	// Unlocks decrement in memory until the refcount reaches zero: 3 → 2 → 1.
	if err := l.Unlock(1); err != nil {
		t.Fatalf("Unlock decrement: %v", err)
	}
	if l.held[1] != 2 {
		t.Fatalf("held[1] = %d, want 2", l.held[1])
	}
	if err := l.Unlock(1); err != nil {
		t.Fatalf("Unlock decrement: %v", err)
	}
	if l.held[1] != 1 {
		t.Fatalf("held[1] = %d, want 1", l.held[1])
	}
	// Final unlock issues pg_advisory_unlock, which SQLite does not know.
	if err := l.Unlock(1); err == nil {
		t.Fatal("expected pg_advisory_unlock to fail on SQLite")
	}
	if _, ok := l.held[1]; ok {
		t.Fatal("held entry must be removed after final unlock")
	}

	// New keys must attempt real PG calls and fail cleanly on SQLite.
	if err := l.Lock(ctx, 2); err == nil {
		t.Fatal("expected pg_advisory_lock to fail on SQLite")
	}
	if _, err := l.TryLock(ctx, 3); err == nil {
		t.Fatal("expected pg_try_advisory_lock to fail on SQLite")
	}
}

// TestOpenVariants covers the DATABASE_URL override, the sqlite:// prefix, and
// the ping-failure path.
func TestOpenVariants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "var.db")

	// sqlite:// prefix is stripped.
	d, err := Open("sqlite://" + path)
	if err != nil {
		t.Fatalf("Open sqlite:// prefix: %v", err)
	}
	d.Close()

	// DATABASE_URL takes precedence over the path argument.
	t.Setenv("DATABASE_URL", path)
	d2, err := Open("/ignored/path.db")
	if err != nil {
		t.Fatalf("Open with DATABASE_URL: %v", err)
	}
	d2.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("env override did not open %s: %v", path, err)
	}

	// Unwritable parent directory → ping failure.
	t.Setenv("DATABASE_URL", "")
	if _, err := Open(filepath.Join(t.TempDir(), "no-such-dir", "db.sqlite")); err == nil {
		t.Fatal("expected error opening database in missing directory")
	}
}

// TestInsertReturningErrorPath covers the non-PG error branch of InsertReturning.
func TestInsertReturningErrorPath(t *testing.T) {
	d := newTestDB(t)
	if _, err := d.InsertReturning("INSERT INTO no_such_table (x) VALUES (?)", 1); err == nil {
		t.Fatal("expected error for unknown table")
	}
}

// TestCheckpointWALDialectBranches covers the non-SQLite no-op and the SQLite
// checkpoint execution.
func TestCheckpointWALDialectBranches(t *testing.T) {
	d := newTestDB(t)
	d.dialect = fakeNonSQLiteDialect{}
	d.CheckpointWAL() // must be a no-op, no panic

	d.dialect = SQLiteDialect{}
	d.CheckpointWAL() // must execute without error
}
