// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// mysqlAdvisoryLock implements DistLock via MySQL GET_LOCK / RELEASE_LOCK on a
// dedicated connection pinned for the duration of the lock. Unlike the on-disk
// file lock (which on network paths degrades to a per-host /tmp directory that
// does not coordinate across hosts), GET_LOCK is server-side and coordinates
// every host sharing the same MySQL instance — closing the cross-node duplicate
// serial / torn schema window (finding 22).
//
// GET_LOCK is session-scoped, so a dedicated connection is held (and never
// returned to the pool) while the lock is held; RELEASE_LOCK and the connection
// close both happen on Unlock. Reentrancy is tracked with a per-process
// refcount keyed by lock key.
type mysqlAdvisoryLock struct {
	d    *DB
	mu   sync.Mutex
	held map[int64]*mysqlLockHandle // key → dedicated connection + refcount
}

type mysqlLockHandle struct {
	conn     *sql.Conn
	refcount int
}

func newMySQLAdvisoryLock(d *DB) *mysqlAdvisoryLock {
	return &mysqlAdvisoryLock{d: d, held: make(map[int64]*mysqlLockHandle)}
}

func (l *mysqlAdvisoryLock) lockName(key int64) string {
	return fmt.Sprintf("varwof:core:%d", key)
}

// getLock acquires GET_LOCK on conn for name, honoring ctx cancellation while
// the server-side lock blocks. timeoutSec is the per-attempt GET_LOCK timeout.
func getLock(ctx context.Context, conn *sql.Conn, name string, timeoutSec uint) error {
	for {
		var got int
		err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", name, timeoutSec).Scan(&got)
		if err != nil {
			return err
		}
		if got == 1 {
			return nil
		}
		// Lock held by another session; GET_LOCK timed out. Re-try unless the
		// caller gave up.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func (l *mysqlAdvisoryLock) Lock(ctx context.Context, key int64) error {
	l.mu.Lock()
	if h, ok := l.held[key]; ok {
		h.refcount++
		l.mu.Unlock()
		return nil // reentrant
	}
	l.mu.Unlock()

	conn, err := l.d.RawDB().Conn(ctx)
	if err != nil {
		return fmt.Errorf("mysql advisory lock: acquire conn: %w", err)
	}
	if err := getLock(ctx, conn, l.lockName(key), 1); err != nil {
		conn.Close()
		return fmt.Errorf("mysql GET_LOCK(%d): %w", key, err)
	}
	l.mu.Lock()
	l.held[key] = &mysqlLockHandle{conn: conn, refcount: 1}
	l.mu.Unlock()
	return nil
}

func (l *mysqlAdvisoryLock) TryLock(ctx context.Context, key int64) (bool, error) {
	l.mu.Lock()
	if h, ok := l.held[key]; ok {
		h.refcount++
		l.mu.Unlock()
		return true, nil // reentrant
	}
	l.mu.Unlock()

	conn, err := l.d.RawDB().Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("mysql advisory lock: acquire conn: %w", err)
	}
	var got int
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 0)", l.lockName(key)).Scan(&got); err != nil {
		conn.Close()
		return false, fmt.Errorf("mysql GET_LOCK(%d): %w", key, err)
	}
	if got != 1 {
		conn.Close()
		return false, nil // held elsewhere
	}
	l.mu.Lock()
	l.held[key] = &mysqlLockHandle{conn: conn, refcount: 1}
	l.mu.Unlock()
	return true, nil
}

func (l *mysqlAdvisoryLock) Unlock(key int64) error {
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
	conn := h.conn
	l.mu.Unlock()

	_, err := conn.ExecContext(context.Background(), "SELECT RELEASE_LOCK(?)", l.lockName(key))
	closeErr := conn.Close()
	if err != nil {
		return fmt.Errorf("mysql RELEASE_LOCK(%d): %w", key, err)
	}
	return closeErr
}
