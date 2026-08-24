// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import "fmt"

func (d *DB) StoreEscrowedKey(caName, serial string, encryptedKey []byte) error {
	_, err := d.Exec(`INSERT OR REPLACE INTO key_escrow (ca_name, serial_number, encrypted_key) VALUES (?, ?, ?)`,
		caName, serial, encryptedKey)
	if err != nil {
		return fmt.Errorf("store escrowed key: %w", err)
	}
	return nil
}

func (d *DB) GetEscrowedKey(caName, serial string) ([]byte, error) {
	var blob []byte
	err := d.QueryRow(`SELECT encrypted_key FROM key_escrow WHERE ca_name = ? AND serial_number = ?`,
		caName, serial).Scan(&blob)
	if err != nil {
		return nil, fmt.Errorf("get escrowed key: %w", err)
	}
	return blob, nil
}
