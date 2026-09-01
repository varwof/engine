// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"fmt"
	"sync"
)

// DistLock is a distributed lock interface for coordinating across instances.
// Implementations must be reentrant-safe: a lock held by the same key can be
// acquired multiple times without deadlock.
type DistLock interface {
	// Lock acquires the lock, blocking until successful or context cancelled.
	Lock(ctx context.Context, key int64) error

	// TryLock attempts to acquire the lock without blocking.
	// Returns true if the lock was acquired.
	TryLock(ctx context.Context, key int64) (bool, error)

	// Unlock releases the lock held by this key.
	Unlock(key int64) error
}

// noopLock is a no-op implementation for SQLite/single-instance mode.
type noopLock struct{}

func (noopLock) Lock(_ context.Context, _ int64) error            { return nil }
func (noopLock) TryLock(_ context.Context, _ int64) (bool, error) { return true, nil }
func (noopLock) Unlock(_ int64) error                             { return nil }

// failClosedLock reports an error on every acquisition attempt. It is returned
// when a lock implementation cannot be set up (e.g. the on-disk lock directory
// cannot be created), so callers learn that mutual exclusion is unavailable
// rather than believing they hold a lock they do not (finding 13).
type failClosedLock struct {
	err error
}

func (l *failClosedLock) Lock(_ context.Context, _ int64) error { return l.err }
func (l *failClosedLock) TryLock(_ context.Context, _ int64) (bool, error) {
	return false, l.err
}
func (l *failClosedLock) Unlock(_ int64) error { return nil }

// pgAdvisoryLock implements DistLock via PostgreSQL pg_advisory_lock.
// Uses session-level locks so they auto-release on connection close.
type pgAdvisoryLock struct {
	d    *DB
	mu   sync.Mutex
	held map[int64]int // key → refcount for reentrancy
}

func newPGAdvisoryLock(d *DB) *pgAdvisoryLock {
	return &pgAdvisoryLock{d: d, held: make(map[int64]int)}
}

func (l *pgAdvisoryLock) Lock(ctx context.Context, key int64) error {
	l.mu.Lock()
	if n := l.held[key]; n > 0 {
		l.held[key] = n + 1
		l.mu.Unlock()
		return nil // reentrant
	}
	l.mu.Unlock()

	_, err := l.d.DB.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key)
	if err != nil {
		return fmt.Errorf("pg_advisory_lock(%d): %w", key, err)
	}

	l.mu.Lock()
	l.held[key] = 1
	l.mu.Unlock()
	return nil
}

func (l *pgAdvisoryLock) TryLock(ctx context.Context, key int64) (bool, error) {
	l.mu.Lock()
	if n := l.held[key]; n > 0 {
		l.held[key] = n + 1
		l.mu.Unlock()
		return true, nil
	}
	l.mu.Unlock()

	var acquired bool
	err := l.d.DB.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&acquired)
	if err != nil {
		return false, fmt.Errorf("pg_try_advisory_lock(%d): %w", key, err)
	}
	if acquired {
		l.mu.Lock()
		l.held[key] = 1
		l.mu.Unlock()
	}
	return acquired, nil
}

func (l *pgAdvisoryLock) Unlock(key int64) error {
	l.mu.Lock()
	n := l.held[key]
	if n <= 1 {
		delete(l.held, key)
		l.mu.Unlock()
		_, err := l.d.DB.Exec("SELECT pg_advisory_unlock($1)", key)
		return err
	}
	l.held[key] = n - 1
	l.mu.Unlock()
	return nil
}

// LockKey constants for well-known lock identifiers.
// Use positive int64 values to avoid sign issues with pg_advisory_lock.
const (
	LockKeyCRLGenerate int64 = 1 // CRL generation
	LockKeyMigration   int64 = 2 // Database migration
	LockKeyCertSerial  int64 = 3 // Certificate serial number allocation
	LockKeyCRLRenew    int64 = 4 // CRL auto-renewal
)

// NewDistLock creates the appropriate lock implementation for the database.
func (d *DB) NewDistLock() DistLock {
	switch d.dialect.(type) {
	case pgDialect, *pgDialectWithConfig:
		return newPGAdvisoryLock(d)
	case mysqlDialect, *mysqlDialectWithConfig:
		// MySQL GET_LOCK coordinates across hosts sharing the same server; the
		// on-disk fallback below would not (each host locks its own /tmp).
		return newMySQLAdvisoryLock(d)
	}
	// SQLite: use a real on-disk lock so that multiple varwof-core processes
	// sharing the same database coordinate (G-12). On platforms without flock
	// support this falls back to noopLock.
	return newNonPGLock(d)
}

// newNonPGLock constructs the lock used for non-PostgreSQL dialects. It is
// overridden by the platform-specific file-lock implementation where
// available (see lock_file_unix.go); the default is a no-op.
var newNonPGLock = func(_ *DB) DistLock { return noopLock{} }
