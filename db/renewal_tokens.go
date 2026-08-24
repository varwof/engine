// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"database/sql"
	"fmt"
	"time"
)

// NonceRecord tracks a renewal token nonce for one-time-use enforcement.
type NonceRecord struct {
	Nonce   []byte
	Used    bool
	Created time.Time
}

// StoreNonce inserts a new nonce with used=false.
// Returns ErrDuplicateNonce if the nonce already exists (collision or replay).
func (d *DB) StoreNonce(nonce []byte) error {
	if len(nonce) != 16 {
		return fmt.Errorf("store_nonce: nonce must be 16 bytes, got %d", len(nonce))
	}
	res, err := d.Exec(`
		INSERT OR IGNORE INTO renewal_tokens (nonce, used)
		VALUES (?, 0)`, nonce)
	if err != nil {
		return fmt.Errorf("store_nonce: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrDuplicateNonce
	}
	return nil
}

// ConsumeNonce atomically marks a nonce as used.
// Returns nil on success, ErrNonceAlreadyUsed if already consumed,
// ErrNonceNotFound if the nonce does not exist.
func (d *DB) ConsumeNonce(nonce []byte) error {
	if len(nonce) != 16 {
		return fmt.Errorf("consume_nonce: nonce must be 16 bytes, got %d", len(nonce))
	}

	// Phase 1: try to consume (used=0 → used=1)
	res, err := d.Exec(`
		UPDATE renewal_tokens
		SET used = 1
		WHERE nonce = ? AND used = 0`, nonce)
	if err != nil {
		return fmt.Errorf("consume_nonce: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		return nil // consumed successfully
	}

	// Phase 2: determine if nonce exists but was already used
	var exists int
	err = d.QueryRow(`
		SELECT 1 FROM renewal_tokens WHERE nonce = ?`, nonce).Scan(&exists)
	if err == sql.ErrNoRows {
		return ErrNonceNotFound
	}
	if err != nil {
		return fmt.Errorf("consume_nonce: lookup: %w", err)
	}
	return ErrNonceAlreadyUsed
}

// IsNonceUsed checks whether a nonce has been consumed.
func (d *DB) IsNonceUsed(nonce []byte) (bool, error) {
	var used int
	err := d.QueryRow(`
		SELECT used FROM renewal_tokens WHERE nonce = ?`, nonce).Scan(&used)
	if err == sql.ErrNoRows {
		return false, nil // not found → not used
	}
	if err != nil {
		return false, fmt.Errorf("is_nonce_used: %w", err)
	}
	return used == 1, nil
}

// ListNonces returns all renewal-token nonces. It is used by the memory
// engine (engine package) to rebuild the in-memory NonceSet on startup.
func (d *DB) ListNonces() ([]NonceRecord, error) {
	rows, err := d.Query("SELECT nonce, used, created FROM renewal_tokens")
	if err != nil {
		return nil, fmt.Errorf("list nonces: %w", err)
	}
	defer rows.Close()

	var records []NonceRecord
	for rows.Next() {
		var r NonceRecord
		var used int
		var created string
		if err := rows.Scan(&r.Nonce, &used, &created); err != nil {
			return nil, fmt.Errorf("scan nonce: %w", err)
		}
		r.Used = used == 1
		if t, err := time.Parse("2006-01-02 15:04:05", created); err == nil {
			r.Created = t
		} else if t, err := time.Parse(time.RFC3339, created); err == nil {
			r.Created = t
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// CleanupExpiredNonces removes nonces older than maxAge.
func (d *DB) CleanupExpiredNonces(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UTC().Format("2006-01-02 15:04:05")
	res, err := d.Exec(`
		DELETE FROM renewal_tokens
		WHERE created < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleanup_nonces: %w", err)
	}
	return res.RowsAffected()
}

// DB errors for renewal token nonce tracking.
var (
	ErrDuplicateNonce   = fmt.Errorf("nonce already exists")
	ErrNonceAlreadyUsed = fmt.Errorf("nonce already used")
	ErrNonceNotFound    = fmt.Errorf("nonce not found")
)
