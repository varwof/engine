// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"fmt"
	"strings"
	"time"
)

// BulkRevokeCertificates revokes a set of (ca, serial) pairs using one UPDATE
// statement per chunk (a CASE expression carries the per-row reason). Chunking
// keeps the parameter count under the SQL variable limit. Returns the number
// of rows actually updated.
//
// This is the mass-revocation hot path: revoking 100K certificates issues
// ~500 statements instead of 100K serial UPDATEs. Ordering with respect to
// pending INSERTs is preserved by the caller (the engine serializes this
// behind its single writer).
func (d *DB) BulkRevokeCertificates(entries []RevokeBatchEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	// Per-row variables: 3 in CASE (ca, serial, reason) + 2 in WHERE (ca, serial).
	// Fixed: 2 (revoked_at, invalidity_date). Total = 5N + 2 ≤ maxSQLVars.
	chunkSize := (maxSQLVars - 2) / 5
	if chunkSize <= 0 {
		chunkSize = 1
	}
	var total int
	for len(entries) > 0 {
		size := chunkSize
		if size > len(entries) {
			size = len(entries)
		}
		n, err := d.bulkRevokeChunk(entries[:size], now)
		if err != nil {
			return total + n, err
		}
		total += n
		entries = entries[size:]
	}
	if total > 0 {
		notifyCertRevoked("") // bulk: invalidate all cached revocation statuses
	}
	return total, nil
}

func (d *DB) bulkRevokeChunk(entries []RevokeBatchEntry, now string) (int, error) {
	n := len(entries)
	if n == 0 {
		return 0, nil
	}
	args := make([]any, 0, 5*n+2)
	next := 0
	ph := func() string {
		p := d.dialect.Placeholder(next)
		next++
		return p
	}

	args = append(args, now)
	revokedAt := ph()

	var caseSQL strings.Builder
	for i, en := range entries {
		if i > 0 {
			caseSQL.WriteByte(' ')
		}
		caseSQL.WriteString("WHEN (ca_name=" + ph() + " AND serial_number=" + ph() + ") THEN " + ph())
		args = append(args, en.CA, en.Serial, en.Reason)
	}

	invalidity := ph()
	args = append(args, now)

	var whereSQL strings.Builder
	for i, en := range entries {
		if i > 0 {
			whereSQL.WriteString(" OR ")
		}
		whereSQL.WriteString("(ca_name=" + ph() + " AND serial_number=" + ph() + ")")
		args = append(args, en.CA, en.Serial)
	}

	query := "UPDATE certificates SET status='R', revoked_at=" + revokedAt +
		", revoke_reason=CASE " + caseSQL.String() + " ELSE revoke_reason END" +
		", invalidity_date=" + invalidity +
		" WHERE (" + whereSQL.String() + ") AND status='V'"
	res, err := d.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("bulk revoke chunk (%d rows): %w", n, err)
	}
	m, _ := res.RowsAffected()
	return int(m), nil
}
