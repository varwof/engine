// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"fmt"
	"time"
)

type CrossCertRecord struct {
	IssuerCA     string
	SubjectCA    string
	CertDER      []byte
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber string
	Fingerprint  string
	Status       string
	RevokedAt    *time.Time
	RevokeReason *int
}

func (d *DB) InsertCrossCert(record *CrossCertRecord) error {
	_, err := d.Exec(`
		INSERT INTO cross_certs
			(issuer_ca, subject_ca, cert_der, not_before, not_after,
			 serial_number, fingerprint, status, revoked_at, revoke_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.IssuerCA, record.SubjectCA, record.CertDER,
		record.NotBefore.UTC().Format(time.RFC3339),
		record.NotAfter.UTC().Format(time.RFC3339),
		record.SerialNumber, record.Fingerprint,
		record.Status, nil, nil,
	)
	if err != nil {
		return fmt.Errorf("insert cross cert: %w", err)
	}
	return nil
}

func (d *DB) GetCrossCert(issuerCA, serial string) (*CrossCertRecord, error) {
	row := d.QueryRow(`
		SELECT issuer_ca, subject_ca, cert_der, not_before, not_after,
		       serial_number, fingerprint, status, revoked_at, revoke_reason
		FROM cross_certs
		WHERE issuer_ca = ? AND serial_number = ?`, issuerCA, serial)
	return scanCrossCertRecord(row)
}

func (d *DB) ListCrossCerts(issuerCA string) ([]*CrossCertRecord, error) {
	rows, err := d.Query(`
		SELECT issuer_ca, subject_ca, cert_der, not_before, not_after,
		       serial_number, fingerprint, status, revoked_at, revoke_reason
		FROM cross_certs
		WHERE issuer_ca = ?
		ORDER BY not_before DESC`, issuerCA)
	if err != nil {
		return nil, fmt.Errorf("list cross certs: %w", err)
	}
	defer rows.Close()
	var records []*CrossCertRecord
	for rows.Next() {
		r, err := scanCrossCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (d *DB) ListCrossCertsAll() ([]*CrossCertRecord, error) {
	rows, err := d.Query(`
		SELECT issuer_ca, subject_ca, cert_der, not_before, not_after,
		       serial_number, fingerprint, status, revoked_at, revoke_reason
		FROM cross_certs
		ORDER BY issuer_ca, not_before DESC`)
	if err != nil {
		return nil, fmt.Errorf("list all cross certs: %w", err)
	}
	defer rows.Close()
	var records []*CrossCertRecord
	for rows.Next() {
		r, err := scanCrossCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (d *DB) RevokeCrossCert(issuerCA, serial string, reason int) error {
	now := time.Now().UTC()
	res, err := d.Exec(`
		UPDATE cross_certs
		SET status = 'R', revoked_at = ?, revoke_reason = ?
		WHERE issuer_ca = ? AND serial_number = ? AND status = 'V'`,
		now.Format(time.RFC3339), reason, issuerCA, serial)
	if err != nil {
		return fmt.Errorf("revoke cross cert: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("cross cert %s/%s not found or already revoked", issuerCA, serial)
	}
	return nil
}

// GetRevokedCrossCerts returns revoked cross-certs for a given issuer CA,
// mapped to CertRecord for CRL integration.
func (d *DB) GetRevokedCrossCerts(issuerCA string) ([]*CertRecord, error) {
	rows, err := d.Query(`
		SELECT issuer_ca, subject_ca, cert_der, not_before, not_after,
		       serial_number, fingerprint, status, revoked_at, revoke_reason
		FROM cross_certs
		WHERE issuer_ca = ? AND status = 'R'
		ORDER BY revoked_at DESC`, issuerCA)
	if err != nil {
		return nil, fmt.Errorf("list revoked cross certs: %w", err)
	}
	defer rows.Close()
	var records []*CertRecord
	for rows.Next() {
		r, err := scanCrossCertRecord(rows)
		if err != nil {
			return nil, err
		}
		record := &CertRecord{
			SerialNumber: r.SerialNumber,
			CAName:       r.IssuerCA,
			Status:       r.Status,
			Subject:      r.SubjectCA,
			CommonName:   r.SubjectCA,
			NotBefore:    r.NotBefore,
			NotAfter:     r.NotAfter,
			RevokedAt:    r.RevokedAt,
			RevokeReason: r.RevokeReason,
			CertDER:      r.CertDER,
			Fingerprint:  r.Fingerprint,
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

type crossScannable interface {
	Scan(dest ...any) error
}

func scanCrossCertRecord(row crossScannable) (*CrossCertRecord, error) {
	var (
		r            CrossCertRecord
		notBeforeStr string
		notAfterStr  string
		revokedAtStr *string
		revokeReason *int
	)
	err := row.Scan(
		&r.IssuerCA, &r.SubjectCA, &r.CertDER,
		&notBeforeStr, &notAfterStr,
		&r.SerialNumber, &r.Fingerprint,
		&r.Status, &revokedAtStr, &revokeReason,
	)
	if err != nil {
		return nil, fmt.Errorf("scan cross cert: %w", err)
	}
	r.NotBefore, _ = time.Parse(time.RFC3339, notBeforeStr)
	r.NotAfter, _ = time.Parse(time.RFC3339, notAfterStr)
	if revokedAtStr != nil {
		t, err := time.Parse(time.RFC3339, *revokedAtStr)
		if err == nil {
			r.RevokedAt = &t
		}
	}
	r.RevokeReason = revokeReason
	return &r, nil
}
