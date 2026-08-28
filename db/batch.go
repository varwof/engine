// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"strings"
	"time"
)

// rowCols is the number of columns per row (synchronized with certColumns).
const rowCols = 25

// CertRecordPool reuses CertRecord objects to reduce GC pressure.
var CertRecordPool = &certRecordPoolT{}

type certRecordPoolT struct{}

func (p *certRecordPoolT) Get() *CertRecord {
	return &CertRecord{}
}

// BulkInsertCertRecords bulk-inserts certificate records and returns the actual number inserted.
// Pre-builds placeholder templates to avoid per-row allocation.
// maxSQLVars is SQLite's limit of variables per query.
const maxSQLVars = 999

func (d *DB) BulkInsertCertRecords(records []*CertRecord) (int, error) {
	return d.BulkInsertCertRecordsCtx(context.Background(), records)
}

// BulkInsertCertRecordsCtx is the context-aware variant of
// BulkInsertCertRecords. The write pipeline passes a bounded context so a hung
// backend connection surfaces as an error (context cleanup / driver timeout)
// instead of blocking the flush indefinitely — the record buffer otherwise
// wedges with flushMu held and pending pinned at maxPending.
func (d *DB) BulkInsertCertRecordsCtx(ctx context.Context, records []*CertRecord) (int, error) {
	// Chunk size is dialect-aware: SQLite caps variables per query at 999, while
	// PG (65,535) and MySQL (packet-bounded) tolerate far more placeholders.
	// Using 500-row chunks on PG/MySQL cuts the number of round-trips ~13× vs the
	// 39-row SQLite chunk, which raises both steady-state flush throughput and
	// how fast a huge backlog drains at shutdown. A 500-row MySQL statement is
	// ~1-1.5MB of wire data, well under a 16MB max_allowed_packet.
	chunkSize := certChunkSize(d.dialect)
	if chunkSize <= 0 {
		chunkSize = 45
	}
	var total int
	for len(records) > 0 {
		size := chunkSize
		if size > len(records) {
			size = len(records)
		}
		n, err := d.bulkInsertChunkCtx(ctx, records[:size])
		if err != nil {
			return total + n, err
		}
		total += n
		records = records[size:]
	}
	return total, nil
}

// certChunkSize returns the maximum certificates per bulk INSERT statement for
// a dialect. SQLite is bound by its 999-parameter-per-query limit; PG and MySQL
// allow larger statements and benefit from bigger chunks.
func certChunkSize(d Dialect) int {
	switch d.DriverName() {
	case "pgx", "mysql":
		return 500
	default: // sqlite
		return maxSQLVars / rowCols
	}
}

func (d *DB) bulkInsertChunk(records []*CertRecord) (int, error) {
	return d.bulkInsertChunkCtx(context.Background(), records)
}

func (d *DB) bulkInsertChunkCtx(ctx context.Context, records []*CertRecord) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	n := len(records)

	// Pre-allocate the args slice.
	args := make([]any, 0, n*rowCols)

	// Fill in parameters.
	var buf [32]byte // time formatting buffer
	for _, r := range records {
		var revokedAt any
		if r.RevokedAt != nil {
			revokedAt = r.RevokedAt.UTC().Format(time.RFC3339)
		}
		var invalidityDate any
		if r.InvalidityDate != nil {
			invalidityDate = r.InvalidityDate.UTC().Format(time.RFC3339)
		}
		args = append(args,
			r.SerialNumber, r.CAName, r.Status, r.Subject, r.CommonName,
			string(r.NotBefore.UTC().AppendFormat(buf[:0], time.RFC3339)),
			string(r.NotAfter.UTC().AppendFormat(buf[:0], time.RFC3339)),
			revokedAt, r.RevokeReason, invalidityDate,
			r.CertDER, r.Fingerprint,
			r.SubjectO, r.SubjectC, r.IssuerDN,
			r.KeyAlgo, r.KeySize, r.SigAlgo,
			r.SKI, r.AKI, r.SAN, r.Profile,
			r.SPKIHash, r.PrincipalUid, r.AgentId,
		)
	}

	// Build the final SQL.
	query := bulkInsertSQL(d.dialect, n)

	res, err := d.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n2, _ := res.RowsAffected()
	return int(n2), nil
}

// bulkInsertSQL builds the multi-row INSERT statement for a dialect with n rows
// (n >= 1), including the dialect-specific conflict handling.
func bulkInsertSQL(d Dialect, n int) string {
	if n < 1 {
		return ""
	}
	var query strings.Builder
	query.Grow(100 + rowCols*3*n)
	switch d.DriverName() {
	case "pgx":
		query.WriteString("INSERT INTO certificates (" + certColumns + ") VALUES ")
		for i := 0; i < n; i++ {
			if i > 0 {
				query.WriteByte(',')
			}
			query.WriteByte('(')
			for j := 0; j < rowCols; j++ {
				if j > 0 {
					query.WriteByte(',')
				}
				query.WriteString(d.Placeholder(i*rowCols + j))
			}
			query.WriteByte(')')
		}
		query.WriteString(" ON CONFLICT DO NOTHING")
	case "mysql":
		query.WriteString("INSERT IGNORE INTO certificates (" + certColumns + ") VALUES ")
		for i := 0; i < n; i++ {
			if i > 0 {
				query.WriteByte(',')
			}
			query.WriteByte('(')
			for j := 0; j < rowCols; j++ {
				if j > 0 {
					query.WriteByte(',')
				}
				query.WriteString(d.Placeholder(j))
			}
			query.WriteByte(')')
		}
	default: // sqlite
		query.WriteString("INSERT OR IGNORE INTO certificates (" + certColumns + ") VALUES ")
		for i := 0; i < n; i++ {
			if i > 0 {
				query.WriteByte(',')
			}
			query.WriteByte('(')
			for j := 0; j < rowCols; j++ {
				if j > 0 {
					query.WriteByte(',')
				}
				query.WriteString(d.Placeholder(j))
			}
			query.WriteByte(')')
		}
	}
	return query.String()
}
