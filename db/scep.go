// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import "time"

type SCEPRequestRecord struct {
	TransactionID string
	CAName        string
	SerialNumber  string
	CertDER       []byte
	IssuerDER     []byte
	CreatedAt     time.Time
}

func (d *DB) InsertSCEPRequest(rec *SCEPRequestRecord) error {
	_, err := d.Exec(d.Rebind(`
		INSERT OR IGNORE INTO scep_requests
			(transaction_id, ca_name, serial_number, cert_der, issuer_der, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`),
		rec.TransactionID, rec.CAName, rec.SerialNumber, rec.CertDER, rec.IssuerDER,
		rec.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	return nil
}

func (d *DB) GetSCEPRequestByTransactionID(txID string) (*SCEPRequestRecord, error) {
	rec := &SCEPRequestRecord{}
	var createdAt string
	err := d.QueryRow(d.Rebind(`
		SELECT transaction_id, ca_name, serial_number, cert_der, issuer_der, created_at
		FROM scep_requests WHERE transaction_id = ?`), txID).Scan(
		&rec.TransactionID, &rec.CAName, &rec.SerialNumber, &rec.CertDER, &rec.IssuerDER, &createdAt)
	if err != nil {
		return nil, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return rec, nil
}

func (d *DB) GetSCEPRequestBySerial(caName, serialNumber string) (*SCEPRequestRecord, error) {
	rec := &SCEPRequestRecord{}
	var createdAt string
	err := d.QueryRow(d.Rebind(`
		SELECT transaction_id, ca_name, serial_number, cert_der, issuer_der, created_at
		FROM scep_requests WHERE ca_name = ? AND serial_number = ?`), caName, serialNumber).Scan(
		&rec.TransactionID, &rec.CAName, &rec.SerialNumber, &rec.CertDER, &rec.IssuerDER, &createdAt)
	if err != nil {
		return nil, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return rec, nil
}

func (d *DB) DeleteSCEPRequest(txID string) error {
	_, err := d.Exec(d.Rebind("DELETE FROM scep_requests WHERE transaction_id = ?"), txID)
	return err
}
