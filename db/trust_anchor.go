// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"fmt"
	"time"
)

type TrustAnchor struct {
	ID              int
	Name            string
	HashID          string
	CertDER         []byte
	Subject         string
	NotBefore       time.Time
	NotAfter        time.Time
	Issuer          string
	Trusted         bool
	Source          string
	ImportedAt      time.Time
	SubjectO        string
	SubjectC        string
	KeyAlgo         string
	KeySize         int
	SHA1Fingerprint string
	PathLen         int
}

type TrustAnchorFilter struct {
	Trusted  *bool
	Source   string
	Page     int
	Size     int
	HashID   string
	SubjectO string
	SubjectC string
	KeyAlgo  string
}

func (d *DB) InsertTrustAnchor(record *TrustAnchor) error {
	_, err := d.Exec(`
		INSERT OR REPLACE INTO trust_anchors
			(name, hash_id, cert_der, subject, not_before, not_after,
			 issuer, trusted, source,
			 subject_o, subject_c, key_algo, key_size, sha1_fingerprint, path_len)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Name, record.HashID, record.CertDER,
		record.Subject,
		record.NotBefore.UTC().Format(time.RFC3339),
		record.NotAfter.UTC().Format(time.RFC3339),
		record.Issuer, d.boolInt(record.Trusted), record.Source,
		record.SubjectO, record.SubjectC, record.KeyAlgo, record.KeySize,
		record.SHA1Fingerprint, record.PathLen,
	)
	if err != nil {
		return fmt.Errorf("insert trust_anchor: %w", err)
	}
	return nil
}

func (d *DB) DeleteTrustAnchorsBySource(source string) error {
	_, err := d.Exec("DELETE FROM trust_anchors WHERE source = ?", source)
	if err != nil {
		return fmt.Errorf("delete trust_anchors by source %q: %w", source, err)
	}
	return nil
}

func (d *DB) ListTrustAnchors(filter *TrustAnchorFilter) ([]*TrustAnchor, error) {
	query := `SELECT id, name, hash_id, cert_der, subject, not_before, not_after,
	          issuer, trusted, source, imported_at,
	          subject_o, subject_c, key_algo, key_size, sha1_fingerprint, path_len
	          FROM trust_anchors WHERE 1=1`
	var args []interface{}

	if filter != nil {
		if filter.Trusted != nil {
			query += " AND trusted = ?"
			args = append(args, d.boolInt(*filter.Trusted))
		}
		if filter.Source != "" {
			query += " AND source = ?"
			args = append(args, filter.Source)
		}
		if filter.HashID != "" {
			query += " AND hash_id = ?"
			args = append(args, filter.HashID)
		}
		if filter.SubjectO != "" {
			query += " AND " + d.LikeExpr("subject_o")
			args = append(args, filter.SubjectO)
		}
		if filter.SubjectC != "" {
			query += " AND subject_c = ?"
			args = append(args, filter.SubjectC)
		}
		if filter.KeyAlgo != "" {
			query += " AND key_algo = ?"
			args = append(args, filter.KeyAlgo)
		}
	}

	query += " ORDER BY name, not_after DESC"

	if filter != nil && filter.Size > 0 {
		offset := 0
		if filter.Page > 1 {
			offset = (filter.Page - 1) * filter.Size
		}
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", filter.Size, offset)
	}

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list trust_anchors: %w", err)
	}
	defer rows.Close()

	var records []*TrustAnchor
	for rows.Next() {
		r, err := scanTrustAnchor(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (d *DB) GetTrustAnchor(hashID string) (*TrustAnchor, error) {
	row := d.QueryRow(`
		SELECT id, name, hash_id, cert_der, subject, not_before, not_after,
		       issuer, trusted, source, imported_at,
		       subject_o, subject_c, key_algo, key_size, sha1_fingerprint, path_len
		FROM trust_anchors WHERE hash_id = ?`, hashID)
	return scanTrustAnchor(row)
}

func (d *DB) UpdateTrustAnchorTrusted(hashID string, trusted bool) error {
	_, err := d.Exec("UPDATE trust_anchors SET trusted = ? WHERE hash_id = ?",
		d.boolInt(trusted), hashID)
	if err != nil {
		return fmt.Errorf("update trust_anchor trusted: %w", err)
	}
	return nil
}

func (d *DB) DeleteTrustAnchor(hashID string) error {
	_, err := d.Exec("DELETE FROM trust_anchors WHERE hash_id = ?", hashID)
	if err != nil {
		return fmt.Errorf("delete trust_anchor: %w", err)
	}
	return nil
}

func (d *DB) TrustAnchorHashIDs() (map[string]bool, error) {
	rows, err := d.Query("SELECT hash_id FROM trust_anchors")
	if err != nil {
		return nil, fmt.Errorf("list trust_anchor hash_ids: %w", err)
	}
	defer rows.Close()
	result := make(map[string]bool)
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scan hash_id: %w", err)
		}
		result[h] = true
	}
	return result, rows.Err()
}

func (d *DB) TrustAnchorStats() (total, trusted, untrusted int, err error) {
	rows, err := d.Query("SELECT trusted, COUNT(*) FROM trust_anchors GROUP BY trusted")
	if err != nil {
		return 0, 0, 0, fmt.Errorf("trust_anchor stats: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t int
		var count int
		if err := rows.Scan(&t, &count); err != nil {
			return 0, 0, 0, fmt.Errorf("scan stats: %w", err)
		}
		total += count
		if t != 0 {
			trusted = count
		} else {
			untrusted = count
		}
	}
	return total, trusted, untrusted, rows.Err()
}

type trustScannable interface {
	Scan(dest ...any) error
}

func scanTrustAnchor(row trustScannable) (*TrustAnchor, error) {
	var (
		r            TrustAnchor
		notBeforeStr string
		notAfterStr  string
		importedStr  string
		trustedInt   int
	)
	err := row.Scan(
		&r.ID, &r.Name, &r.HashID, &r.CertDER,
		&r.Subject, &notBeforeStr, &notAfterStr,
		&r.Issuer, &trustedInt, &r.Source, &importedStr,
		&r.SubjectO, &r.SubjectC, &r.KeyAlgo, &r.KeySize,
		&r.SHA1Fingerprint, &r.PathLen,
	)
	if err != nil {
		return nil, fmt.Errorf("scan trust_anchor: %w", err)
	}
	r.NotBefore, _ = time.Parse(time.RFC3339, notBeforeStr)
	r.NotAfter, _ = time.Parse(time.RFC3339, notAfterStr)
	r.ImportedAt, _ = time.Parse(time.RFC3339, importedStr)
	r.Trusted = trustedInt != 0
	return &r, nil
}

func (d *DB) boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
