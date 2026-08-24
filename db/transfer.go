// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
)

// TransferTables defines the ordered list of tables to transfer, preserving FK dependencies.
var TransferTables = []string{
	"ca_meta",
	"certificates",
	"key_escrow",
	"ct_logs",
	"acme_accounts",
	"acme_orders",
	"acme_authorizations",
	"acme_challenges",
	"acme_cert_orders",
	"rbac_users",
	"rbac_api_tokens",
	"audit_log",
	"ra_requests",
	"ra_approvals",
	"webhook_subscriptions",
	"cross_certs",
	"trust_anchors",
	"cert_archive",
	"scep_requests",
}

// Transfer copies all data from source DB to target DB.
// target migrations must already be applied (OpenWithDialect handles this).
func TransferTo(target *DB, sourceDSN string) error {
	source, err := Open(sourceDSN)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer source.Close()

	slog.Info("transfer: starting", "from", sourceDSN, "to", target.dialect.DriverName())

	for _, table := range TransferTables {
		if err := transferTable(source, target, table); err != nil {
			return fmt.Errorf("transfer %s: %w", table, err)
		}
	}

	// Update sequences for PostgreSQL after data transfer.
	if target.dialect.DriverName() == "pgx" {
		if err := updatePGSQLSequences(target); err != nil {
			slog.Warn("transfer: failed to update sequences", "error", err)
		}
	}

	slog.Info("transfer: complete")
	return nil
}

// transferTable copies all rows from source table to target table.
func transferTable(src, dst *DB, table string) error {
	// Get column type info from SQLite for BLOB vs TEXT distinction.
	colTypes := sqliteColumnTypes(src, table)

	// Query all rows from source.
	rows, err := src.Query(fmt.Sprintf("SELECT * FROM %s", table))
	if err != nil {
		return fmt.Errorf("select: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("columns: %w", err)
	}

	// Build INSERT statement with explicit columns (preserves auto-inc IDs).
	placeholders := strings.Repeat(",?", len(cols))
	if len(placeholders) > 0 {
		placeholders = placeholders[1:]
	}
	insertSQL := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table, strings.Join(cols, ","), placeholders)

	var count int
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		valPtrs := make([]interface{}, len(cols))
		for i := range vals {
			valPtrs[i] = &vals[i]
		}
		if err := rows.Scan(valPtrs...); err != nil {
			return fmt.Errorf("scan row: %w", err)
		}

		// Convert []byte to string for TEXT columns, keep []byte for BLOB/BYTEA.
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				if colTypes[i] == "BLOB" {
					vals[i] = b // keep as []byte → PG BYTEA / MySQL BLOB
				} else {
					vals[i] = string(b) // TEXT → string
				}
			}
		}

		if _, err := dst.Exec(insertSQL, vals...); err != nil {
			return fmt.Errorf("insert row %d: %w", count, err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}

	slog.Info("transfer: table done", "table", table, "rows", count)
	return nil
}

// sqliteColumnTypes returns the declared column types for a SQLite table.
func sqliteColumnTypes(d *DB, table string) []string {
	rows, err := d.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var types []string
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var defVal *string
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defVal, &pk); err != nil {
			return nil
		}
		// SQLite type affinity: treat BLOB as BLOB, everything else as TEXT.
		if colType == "BLOB" {
			types = append(types, "BLOB")
		} else {
			types = append(types, "TEXT")
		}
	}
	return types
}

// updatePGSQLSequences sets each SERIAL sequence to max(id)+1 after data transfer.
func updatePGSQLSequences(d *DB) error {
	seqTables := []string{
		"acme_accounts", "acme_orders", "acme_authorizations",
		"acme_challenges", "acme_cert_orders", "rbac_users",
		"rbac_api_tokens", "audit_log", "ra_requests",
		"ra_approvals", "webhook_subscriptions", "trust_anchors",
	}
	for _, table := range seqTables {
		// Check if table has an 'id' column with data.
		var maxID sql.NullInt64
		err := d.QueryRow(fmt.Sprintf("SELECT MAX(id) FROM %s", table)).Scan(&maxID)
		if err != nil {
			continue // skip if no id column or table empty
		}
		if maxID.Valid && maxID.Int64 > 0 {
			seqSQL := fmt.Sprintf("SELECT setval('%s_id_seq', %d)", table, maxID.Int64)
			if _, err := d.Exec(seqSQL); err != nil {
				slog.Warn("transfer: setval failed", "table", table, "error", err)
			}
		}
	}
	return nil
}
