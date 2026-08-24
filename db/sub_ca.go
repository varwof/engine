// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"database/sql"
	"fmt"
)

// SubCAMeta holds metadata for a sub-CA.
type SubCAMeta struct {
	ID           int64
	Name         string
	ParentCA     string
	CertDER      []byte
	KeyEncrypted []byte
	Subject      string
	NotBefore    string
	NotAfter     string
	KeyAlgorithm string
	Fingerprint  string
	Status       string
	Protocol     string
	KeyUsage     string
	MaxPathLen   int
	CreatedAt    string
	RevokedAt    *string
	RevokeReason *int
}

// InsertSubCA inserts a new sub-CA record.
func (d *DB) InsertSubCA(record *SubCAMeta) error {
	keyEnc := record.KeyEncrypted
	if keyEnc == nil {
		keyEnc = []byte{}
	}

	_, err := d.Exec(`
		INSERT INTO sub_cas
			(name, parent_ca, cert_der, key_encrypted, subject, not_before, not_after,
			 key_algorithm, fingerprint, status, protocol, key_usage, max_path_len)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Name, record.ParentCA, record.CertDER, keyEnc,
		record.Subject,
		record.NotBefore,
		record.NotAfter,
		record.KeyAlgorithm, record.Fingerprint, record.Status,
		record.Protocol, record.KeyUsage, record.MaxPathLen,
	)
	if err != nil {
		return fmt.Errorf("insert sub_ca: %w", err)
	}
	return nil
}

// GetSubCA retrieves a sub-CA by name.
func (d *DB) GetSubCA(name string) (*SubCAMeta, error) {
	row := d.QueryRow(`
		SELECT id, name, parent_ca, cert_der, key_encrypted, subject,
		       not_before, not_after, key_algorithm, fingerprint, status,
		       protocol, key_usage, max_path_len, created_at, revoked_at, revoke_reason
		FROM sub_cas WHERE name = ?`, name)

	var r SubCAMeta
	var notBeforeStr, notAfterStr, createdAtStr string
	var revokedAtStr *string
	err := row.Scan(&r.ID, &r.Name, &r.ParentCA, &r.CertDER, &r.KeyEncrypted,
		&r.Subject, &notBeforeStr, &notAfterStr, &r.KeyAlgorithm, &r.Fingerprint,
		&r.Status, &r.Protocol, &r.KeyUsage, &r.MaxPathLen, &createdAtStr,
		&revokedAtStr, &r.RevokeReason)
	if err != nil {
		return nil, fmt.Errorf("get sub_ca %q: %w", name, err)
	}

	r.NotBefore = notBeforeStr
	r.NotAfter = notAfterStr
	r.CreatedAt = createdAtStr
	r.RevokedAt = revokedAtStr

	return &r, nil
}

// ListSubCAs returns all sub-CAs, optionally filtered by protocol.
func (d *DB) ListSubCAs(protocol string) ([]*SubCAMeta, error) {
	var rows *sql.Rows
	var err error

	if protocol != "" {
		rows, err = d.Query(`
			SELECT id, name, parent_ca, cert_der, key_encrypted, subject,
			       not_before, not_after, key_algorithm, fingerprint, status,
			       protocol, key_usage, max_path_len, created_at, revoked_at, revoke_reason
			FROM sub_cas WHERE protocol = ? ORDER BY name`, protocol)
	} else {
		rows, err = d.Query(`
			SELECT id, name, parent_ca, cert_der, key_encrypted, subject,
			       not_before, not_after, key_algorithm, fingerprint, status,
			       protocol, key_usage, max_path_len, created_at, revoked_at, revoke_reason
			FROM sub_cas ORDER BY name`)
	}
	if err != nil {
		return nil, fmt.Errorf("list sub_cas: %w", err)
	}
	defer rows.Close()

	var records []*SubCAMeta
	for rows.Next() {
		var r SubCAMeta
		var notBeforeStr, notAfterStr, createdAtStr string
		var revokedAtStr *string
		if err := rows.Scan(&r.ID, &r.Name, &r.ParentCA, &r.CertDER, &r.KeyEncrypted,
			&r.Subject, &notBeforeStr, &notAfterStr, &r.KeyAlgorithm, &r.Fingerprint,
			&r.Status, &r.Protocol, &r.KeyUsage, &r.MaxPathLen, &createdAtStr,
			&revokedAtStr, &r.RevokeReason); err != nil {
			return nil, fmt.Errorf("scan sub_ca: %w", err)
		}
		r.NotBefore = notBeforeStr
		r.NotAfter = notAfterStr
		r.CreatedAt = createdAtStr
		r.RevokedAt = revokedAtStr
		records = append(records, &r)
	}
	return records, rows.Err()
}

// RevokeSubCA marks a sub-CA as revoked.
func (d *DB) RevokeSubCA(name string, reason int, revokedAt string) error {
	_, err := d.Exec(`
		UPDATE sub_cas SET status = 'revoked', revoked_at = ?, revoke_reason = ?
		WHERE name = ?`, revokedAt, reason, name)
	if err != nil {
		return fmt.Errorf("revoke sub_ca %q: %w", name, err)
	}
	return nil
}

// DeleteSubCA removes a sub-CA record.
func (d *DB) DeleteSubCA(name string) error {
	_, err := d.Exec("DELETE FROM sub_cas WHERE name = ?", name)
	if err != nil {
		return fmt.Errorf("delete sub_ca %q: %w", name, err)
	}
	return nil
}
