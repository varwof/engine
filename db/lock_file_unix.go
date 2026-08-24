// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build !windows

package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

func init() {
	newNonPGLock = newFileLock
}

// fileLock is a distributed-ish lock backed by advisory file locks
// (syscall.Flock) on per-key lock files. It coordinates across processes that
// share the same on-disk database directory — closing the gap left by the
// SQLite noopLock for CRL generation, migration and serial allocation (G-12).
//
// Each logical lock key maps to a lock file "<dir>/varwof-core.lock.<key>" inside
// the database's directory (falling back to os.TempDir when unknown). The file
// handle is kept open for the lifetime of the held lock so Flock releases only
// on Unlock (or process exit). Reentrancy is tracked with a per-process
// refcount keyed by lock key.
type fileLock struct {
	dir  string
	mu   sync.Mutex
	held map[int64]*fileLockHandle // key → open handle + refcount
}

type fileLockHandle struct {
	f        *os.File
	refcount int
}

func newFileLock(d *DB) DistLock {
	dir := lockDirForDB(d)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		// If we cannot prepare a lock directory, degrade to noop rather than
		// crashing startup. Coordination is best-effort.
		return noopLock{}
	}
	return &fileLock{dir: dir, held: make(map[int64]*fileLockHandle)}
}

func lockDirForDB(d *DB) string {
	if d.path != "" {
		if abs, err := filepath.Abs(d.path); err == nil {
			return filepath.Dir(abs)
		}
	}
	return os.TempDir()
}

// syscallFlock is a small wrapper around syscall.Flock. When unlock is true it
// releases the lock; otherwise it acquires exclusively, blocking if block is
// true or returning EWOULDBLOCK immediately otherwise.
func syscallFlock(fd int, block, unlock bool) error {
	if unlock {
		return syscall.Flock(fd, syscall.LOCK_UN)
	}
	op := syscall.LOCK_EX
	if !block {
		op |= syscall.LOCK_NB
	}
	return syscall.Flock(fd, op)
}

func (l *fileLock) lockPath(key int64) string {
	return filepath.Join(l.dir, fmt.Sprintf("varwof-core.lock.%d", key))
}

func (l *fileLock) acquire(key int64, block bool) (bool, error) {
	l.mu.Lock()
	if h, ok := l.held[key]; ok {
		h.refcount++
		l.mu.Unlock()
		return true, nil // reentrant
	}
	l.mu.Unlock()

	f, err := os.OpenFile(l.lockPath(key), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, fmt.Errorf("open lock file: %w", err)
	}

	var op int
	if block {
		op = syscall.LOCK_EX
	} else {
		op = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), op); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return false, nil
		}
		return false, fmt.Errorf("flock: %w", err)
	}

	l.mu.Lock()
	l.held[key] = &fileLockHandle{f: f, refcount: 1}
	l.mu.Unlock()
	return true, nil
}

func (l *fileLock) Lock(ctx context.Context, key int64) error {
	// Blocking Flock (LOCK_EX) waits in the kernel until the lock is free, so
	// a successful return means acquired. Honour context cancellation by
	// racing the blocking call against ctx.Done via a separate goroutine.
	type res struct {
		ok  bool
		err error
	}
	done := make(chan res, 1)
	go func() {
		ok, err := l.acquire(key, true)
		done <- res{ok, err}
	}()
	select {
	case <-ctx.Done():
		// Cannot safely abort the in-flight flock; let it finish and release.
		r := <-done
		if r.ok {
			_ = l.Unlock(key)
		}
		return ctx.Err()
	case r := <-done:
		return r.err
	}
}

func (l *fileLock) TryLock(_ context.Context, key int64) (bool, error) {
	return l.acquire(key, false)
}

func (l *fileLock) Unlock(key int64) error {
	l.mu.Lock()
	h, ok := l.held[key]
	if !ok {
		l.mu.Unlock()
		return nil
	}
	if h.refcount > 1 {
		h.refcount--
		l.mu.Unlock()
		return nil
	}
	delete(l.held, key)
	l.mu.Unlock()

	if err := syscall.Flock(int(h.f.Fd()), syscall.LOCK_UN); err != nil {
		h.f.Close()
		return fmt.Errorf("flock unlock: %w", err)
	}
	return h.f.Close()
}
