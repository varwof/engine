// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"fmt"
	"time"
)

type CAMeta struct {
	Name         string
	CertDER      []byte
	Subject      string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyAlgorithm string
	Fingerprint  string
	KeyEncrypted []byte // PBKDF2+AES-256-CBC encrypted private key DER, optional
}

func (d *DB) InsertCAMeta(record *CAMeta) error {
	keyEnc := record.KeyEncrypted
	if keyEnc == nil {
		keyEnc = []byte{}
	}
	_, err := d.Exec(`
		INSERT OR REPLACE INTO ca_meta
			(name, cert_der, subject, not_before, not_after, key_algorithm, fingerprint, key_encrypted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Name, record.CertDER, record.Subject,
		record.NotBefore.UTC().Format(time.RFC3339),
		record.NotAfter.UTC().Format(time.RFC3339),
		record.KeyAlgorithm, record.Fingerprint, keyEnc,
	)
	if err != nil {
		return fmt.Errorf("insert ca_meta: %w", err)
	}
	return nil
}

func (d *DB) GetCAMeta(name string) (*CAMeta, error) {
	row := d.QueryRow(`
		SELECT name, cert_der, subject, not_before, not_after, key_algorithm, fingerprint, key_encrypted
		FROM ca_meta WHERE name = ?`, name)

	var r CAMeta
	var notBeforeStr, notAfterStr string
	err := row.Scan(&r.Name, &r.CertDER, &r.Subject,
		&notBeforeStr, &notAfterStr, &r.KeyAlgorithm, &r.Fingerprint, &r.KeyEncrypted)
	if err != nil {
		return nil, fmt.Errorf("get ca_meta %q: %w", name, err)
	}

	r.NotBefore, _ = time.Parse(time.RFC3339, notBeforeStr)
	r.NotAfter, _ = time.Parse(time.RFC3339, notAfterStr)

	return &r, nil
}

func (d *DB) ListCAMetas() ([]*CAMeta, error) {
	rows, err := d.Query(`
		SELECT name, cert_der, subject, not_before, not_after, key_algorithm, fingerprint, key_encrypted
		FROM ca_meta ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list ca_meta: %w", err)
	}
	defer rows.Close()

	var records []*CAMeta
	for rows.Next() {
		var r CAMeta
		var notBeforeStr, notAfterStr string
		if err := rows.Scan(&r.Name, &r.CertDER, &r.Subject,
			&notBeforeStr, &notAfterStr, &r.KeyAlgorithm, &r.Fingerprint, &r.KeyEncrypted); err != nil {
			return nil, fmt.Errorf("scan ca_meta: %w", err)
		}
		r.NotBefore, _ = time.Parse(time.RFC3339, notBeforeStr)
		r.NotAfter, _ = time.Parse(time.RFC3339, notAfterStr)
		records = append(records, &r)
	}
	return records, rows.Err()
}

func (d *DB) DeleteCAMeta(name string) error {
	_, err := d.Exec("DELETE FROM ca_meta WHERE name = ?", name)
	if err != nil {
		return fmt.Errorf("delete ca_meta %q: %w", name, err)
	}
	return nil
}
