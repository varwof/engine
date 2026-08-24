// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"database/sql"
	"fmt"
)

// GetLastCRLNumber returns the last persisted CRL number for a CA, or 0 when
// no CRL has ever been recorded for it. Persisting the number across restarts
// prevents RFC 5280 §5.2.4 monotonicity violations (H12 fix): without it a
// freshly-booted process would renumber CRLs from 1, and clients that enforce
// monotonic cRLNumber would reject the newer (smaller-numbered) CRL — leaving
// revocations invisible until the counter catches up.
func (d *DB) GetLastCRLNumber(caName string) (int64, error) {
	var n int64
	err := d.QueryRow(`
		SELECT last_number FROM crl_number_state WHERE ca_name = ?`, caName).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get_last_crl_number: %w", err)
	}
	return n, nil
}

// SetLastCRLNumber records the CRL number used for a CA. It is monotonically
// increasing (only ever raises the stored value), so a stale in-memory counter
// can never overwrite a higher persisted number.
func (d *DB) SetLastCRLNumber(caName string, number int64) error {
	// Monotonic upsert per dialect. The CASE / VALUES() guard ensures a stale
	// lower counter can never overwrite a higher persisted number.
	var query string
	switch d.dialect.DriverName() {
	case "mysql":
		query = `
			INSERT INTO crl_number_state (ca_name, last_number)
			VALUES (?, ?)
			ON DUPLICATE KEY UPDATE
				last_number = IF(crl_number_state.last_number < VALUES(last_number),
					VALUES(last_number), crl_number_state.last_number),
				updated_at = ` + d.dialect.NowExpr()
	default: // sqlite, pgx
		query = `
			INSERT INTO crl_number_state (ca_name, last_number)
			VALUES (?, ?)
			ON CONFLICT(ca_name) DO UPDATE SET
				last_number = CASE WHEN crl_number_state.last_number < excluded.last_number
					THEN excluded.last_number ELSE crl_number_state.last_number END,
				updated_at = ` + d.dialect.NowExpr()
	}
	if _, err := d.Exec(query, caName, number); err != nil {
		return fmt.Errorf("set_last_crl_number: %w", err)
	}
	return nil
}

// ListCRLNumbers returns all persisted per-CA CRL numbers, used by the memory
// engine to rebuild the authoritative counter on startup.
func (d *DB) ListCRLNumbers() (map[string]int64, error) {
	rows, err := d.Query("SELECT ca_name, last_number FROM crl_number_state")
	if err != nil {
		return nil, fmt.Errorf("list_crl_numbers: %w", err)
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var ca string
		var n int64
		if err := rows.Scan(&ca, &n); err != nil {
			return nil, fmt.Errorf("scan crl_number: %w", err)
		}
		out[ca] = n
	}
	return out, rows.Err()
}
