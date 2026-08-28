// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// DANonceRecord tracks a DelegationAuthorization nonce for replay protection.
// The nonce is always 32 bytes (AIC spec: delegationAuth.nonce SIZE(32)).
type DANonceRecord struct {
	Nonce   []byte
	Created time.Time
}

// StoreDANonce persists a DelegationAuthorization nonce (32 bytes) so that the
// same authorization signature cannot be replayed to mint a second AIC.
// Returns ErrDuplicateNonce if the nonce was already stored (replay).
func (d *DB) StoreDANonce(nonce []byte) error {
	if len(nonce) != 32 {
		return fmt.Errorf("store_da_nonce: nonce must be 32 bytes, got %d", len(nonce))
	}
	res, err := d.Exec(`
		INSERT OR IGNORE INTO da_nonces (nonce)
		VALUES (?)`, nonce)
	if err != nil {
		return fmt.Errorf("store_da_nonce: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrDuplicateNonce
	}
	return nil
}

// IsDANonceUsed reports whether a DelegationAuthorization nonce has already
// been persisted (i.e. was used for a prior AIC issuance).
func (d *DB) IsDANonceUsed(nonce []byte) (bool, error) {
	if len(nonce) != 32 {
		return false, fmt.Errorf("is_da_nonce_used: nonce must be 32 bytes, got %d", len(nonce))
	}
	var exists int
	err := d.QueryRow(`
		SELECT 1 FROM da_nonces WHERE nonce = ?`, nonce).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("is_da_nonce_used: %w", err)
	}
	return true, nil
}

// BulkStoreDANonces persists a batch of DelegationAuthorization nonces in a
// single multi-row INSERT OR IGNORE statement (chunked under the SQL variable
// limit). Returns the number of nonces newly stored; duplicates (replay) are
// silently ignored, mirroring StoreDANonce's idempotence for a single nonce.
// This is the batched backend sink for the engine's DA nonce write pipeline.
func (d *DB) BulkStoreDANonces(nonces [][]byte) (int, error) {
	return d.BulkStoreDANoncesCtx(context.Background(), nonces)
}

// BulkStoreDANoncesCtx is the context-aware variant of BulkStoreDANonces. The
// write pipeline passes a bounded context so a hung backend connection surfaces
// as an error (context cleanup / driver timeout) instead of blocking the flush
// indefinitely.
func (d *DB) BulkStoreDANoncesCtx(ctx context.Context, nonces [][]byte) (int, error) {
	for i, nc := range nonces {
		if len(nc) != 32 {
			return 0, fmt.Errorf("bulk_store_da_nonces: nonce %d must be 32 bytes, got %d", i, len(nc))
		}
	}
	chunkSize := maxSQLVars
	if chunkSize <= 0 {
		chunkSize = 500
	}
	var total int
	for len(nonces) > 0 {
		size := chunkSize
		if size > len(nonces) {
			size = len(nonces)
		}
		n, err := d.bulkStoreDANonceChunkCtx(ctx, nonces[:size])
		if err != nil {
			return total + n, err
		}
		total += n
		nonces = nonces[size:]
	}
	return total, nil
}

func (d *DB) bulkStoreDANonceChunk(nonces [][]byte) (int, error) {
	return d.bulkStoreDANonceChunkCtx(context.Background(), nonces)
}

func (d *DB) bulkStoreDANonceChunkCtx(ctx context.Context, nonces [][]byte) (int, error) {
	n := len(nonces)
	if n == 0 {
		return 0, nil
	}
	args := make([]any, n)
	rows := make([]string, n)
	for i, nc := range nonces {
		args[i] = nc
		rows[i] = "(" + d.dialect.Placeholder(i) + ")"
	}
	// InsertOrIgnore wraps values in parentheses itself, which is wrong for
	// multi-row lists; build the multi-row INSERT directly per dialect.
	values := strings.Join(rows, ",")
	var query string
	switch d.dialect.DriverName() {
	case "pgx":
		query = "INSERT INTO da_nonces (nonce) VALUES " + values + " ON CONFLICT DO NOTHING"
	case "mysql":
		query = "INSERT IGNORE INTO da_nonces (nonce) VALUES " + values
	default: // sqlite
		query = "INSERT OR IGNORE INTO da_nonces (nonce) VALUES " + values
	}
	res, err := d.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("bulk_store_da_nonces: %w", err)
	}
	n2, _ := res.RowsAffected()
	return int(n2), nil
}

// ListDANonces returns all persisted DelegationAuthorization nonces. It is used
// by the memory engine (engine package) to rebuild the in-memory DA nonce set
// on startup.
func (d *DB) ListDANonces() ([]DANonceRecord, error) {
	rows, err := d.Query("SELECT nonce, created FROM da_nonces")
	if err != nil {
		return nil, fmt.Errorf("list da nonces: %w", err)
	}
	defer rows.Close()

	var records []DANonceRecord
	for rows.Next() {
		var r DANonceRecord
		var created string
		if err := rows.Scan(&r.Nonce, &created); err != nil {
			return nil, fmt.Errorf("scan da nonce: %w", err)
		}
		if t, err := time.Parse("2006-01-02 15:04:05", created); err == nil {
			r.Created = t
		} else if t, err := time.Parse(time.RFC3339, created); err == nil {
			r.Created = t
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// CleanupExpiredDANonces removes DelegationAuthorization nonces older than
// maxAge. DA nonces outlive the certificates they mint by design (replay
// protection window), so callers pass the DA validity ceiling.
func (d *DB) CleanupExpiredDANonces(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UTC().Format("2006-01-02 15:04:05")
	res, err := d.Exec(`
		DELETE FROM da_nonces
		WHERE created < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleanup_da_nonces: %w", err)
	}
	return res.RowsAffected()
}
