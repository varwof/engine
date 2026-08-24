// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import "fmt"

type SCTRecord struct {
	CAName       string
	SerialNumber string
	SCTVersion   int
	LogID        string
	Timestamp    uint64
	Signature    []byte
}

func (d *DB) StoreSCT(caName, serial string, sctVersion int, logID string, timestamp uint64, sig []byte) error {
	_, err := d.Exec(`INSERT OR REPLACE INTO ct_logs (ca_name, serial_number, sct_version, log_id, timestamp, signature) VALUES (?, ?, ?, ?, ?, ?)`,
		caName, serial, sctVersion, logID, timestamp, sig)
	if err != nil {
		return fmt.Errorf("store SCT: %w", err)
	}
	return nil
}

func (d *DB) GetSCT(caName, serial string) (*SCTRecord, error) {
	rec := &SCTRecord{CAName: caName, SerialNumber: serial}
	err := d.QueryRow(`SELECT sct_version, log_id, timestamp, signature FROM ct_logs WHERE ca_name = ? AND serial_number = ?`,
		caName, serial).Scan(&rec.SCTVersion, &rec.LogID, &rec.Timestamp, &rec.Signature)
	if err != nil {
		return nil, fmt.Errorf("get SCT: %w", err)
	}
	return rec, nil
}
