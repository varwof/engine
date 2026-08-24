// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"
)

type AcmeAccount struct {
	ID            int64
	JWKThumbprint string
	JWKJSON       string
	Contact       string
	Status        string
	CreatedAt     time.Time
}

type AcmeOrder struct {
	ID          int64
	AccountID   int64
	Status      string
	Identifiers string
	NotBefore   *string
	NotAfter    *string
	Expires     string
	CreatedAt   time.Time
}

type AcmeAuthorization struct {
	ID              int64
	OrderID         int64
	IdentifierType  string
	IdentifierValue string
	Status          string
	Token           string
	Expires         string
	CreatedAt       time.Time
}

type AcmeChallenge struct {
	ID          int64
	AuthzID     int64
	Type        string
	Token       string
	Status      string
	ValidatedAt *string
}

type AcmeCertOrder struct {
	ID           int64
	OrderID      int64
	CertDER      []byte
	SerialNumber string
	CAName       string
	CertSHA256   string
	CreatedAt    time.Time
}

func (d *DB) InsertAcmeAccount(jwkThumbprint, jwkJSON, contact, status string) (int64, error) {
	id, err := d.InsertReturning(`
		INSERT INTO acme_accounts (jwk_thumbprint, jwk_json, contact, status, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		jwkThumbprint, jwkJSON, contact, status, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("insert acme account: %w", err)
	}
	return id, nil
}

func (d *DB) GetAcmeAccountByThumbprint(thumbprint string) (*AcmeAccount, error) {
	row := d.QueryRow(`
		SELECT id, jwk_thumbprint, jwk_json, contact, status, created_at
		FROM acme_accounts WHERE jwk_thumbprint = ?`, thumbprint)
	return scanAcmeAccount(row)
}

func (d *DB) GetAcmeAccountByID(id int64) (*AcmeAccount, error) {
	row := d.QueryRow(`
		SELECT id, jwk_thumbprint, jwk_json, contact, status, created_at
		FROM acme_accounts WHERE id = ?`, id)
	return scanAcmeAccount(row)
}

func (d *DB) UpdateAcmeAccount(id int64, contact, status string) error {
	_, err := d.Exec(`
		UPDATE acme_accounts SET contact = ?, status = ? WHERE id = ?`,
		contact, status, id)
	if err != nil {
		return fmt.Errorf("update acme account: %w", err)
	}
	return nil
}

func (d *DB) UpdateAcmeAccountKey(id int64, jwkThumbprint, jwkJSON string) error {
	_, err := d.Exec(`
		UPDATE acme_accounts SET jwk_thumbprint = ?, jwk_json = ? WHERE id = ?`,
		jwkThumbprint, jwkJSON, id)
	if err != nil {
		return fmt.Errorf("update acme account key: %w", err)
	}
	return nil
}

func (d *DB) InsertAcmeOrder(accountID int64, identifiers, expires string) (int64, error) {
	id, err := d.InsertReturning(`
		INSERT INTO acme_orders (account_id, status, identifiers, expires, created_at)
		VALUES (?, 'pending', ?, ?, ?)`,
		accountID, identifiers, expires, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("insert acme order: %w", err)
	}
	return id, nil
}

func (d *DB) GetAcmeOrder(id int64) (*AcmeOrder, error) {
	row := d.QueryRow(`
		SELECT id, account_id, status, identifiers, not_before, not_after, expires, created_at
		FROM acme_orders WHERE id = ?`, id)
	return scanAcmeOrder(row)
}

func (d *DB) UpdateAcmeOrder(id int64, status string) error {
	_, err := d.Exec(`UPDATE acme_orders SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("update acme order: %w", err)
	}
	return nil
}

func (d *DB) UpdateAcmeOrderFinalize(id int64, status string) error {
	return d.UpdateAcmeOrder(id, status)
}

func (d *DB) InsertAcmeAuthorization(orderID int64, idType, idValue, token, expires string) (int64, error) {
	id, err := d.InsertReturning(`
		INSERT INTO acme_authorizations (order_id, identifier_type, identifier_value, status, token, expires, created_at)
		VALUES (?, ?, ?, 'pending', ?, ?, ?)`,
		orderID, idType, idValue, token, expires, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("insert acme authz: %w", err)
	}
	return id, nil
}

func (d *DB) GetAcmeAuthorization(id int64) (*AcmeAuthorization, error) {
	row := d.QueryRow(`
		SELECT id, order_id, identifier_type, identifier_value, status, token, expires, created_at
		FROM acme_authorizations WHERE id = ?`, id)
	return scanAcmeAuthorization(row)
}

func (d *DB) GetAcmeAuthorizationsByOrder(orderID int64) ([]*AcmeAuthorization, error) {
	rows, err := d.Query(`
		SELECT id, order_id, identifier_type, identifier_value, status, token, expires, created_at
		FROM acme_authorizations WHERE order_id = ?`, orderID)
	if err != nil {
		return nil, fmt.Errorf("list authz: %w", err)
	}
	defer rows.Close()

	var result []*AcmeAuthorization
	for rows.Next() {
		a, err := scanAcmeAuthorization(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

func (d *DB) UpdateAcmeAuthzStatus(id int64, status string) error {
	_, err := d.Exec(`UPDATE acme_authorizations SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("update acme authz: %w", err)
	}
	return nil
}

func (d *DB) InsertAcmeChallenge(authzID int64, challType, token string) (int64, error) {
	id, err := d.InsertReturning(`
		INSERT INTO acme_challenges (authz_id, type, token, status)
		VALUES (?, ?, ?, 'pending')`,
		authzID, challType, token)
	if err != nil {
		return 0, fmt.Errorf("insert acme challenge: %w", err)
	}
	return id, nil
}

func (d *DB) GetAcmeChallenge(id int64) (*AcmeChallenge, error) {
	row := d.QueryRow(`
		SELECT id, authz_id, type, token, status, validated_at
		FROM acme_challenges WHERE id = ?`, id)
	return scanAcmeChallenge(row)
}

func (d *DB) GetAcmeChallengesByAuthz(authzID int64) ([]*AcmeChallenge, error) {
	rows, err := d.Query(`
		SELECT id, authz_id, type, token, status, validated_at
		FROM acme_challenges WHERE authz_id = ?`, authzID)
	if err != nil {
		return nil, fmt.Errorf("list challenges: %w", err)
	}
	defer rows.Close()

	var result []*AcmeChallenge
	for rows.Next() {
		c, err := scanAcmeChallenge(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (d *DB) UpdateAcmeChallenge(id int64, status string, validatedAt *string) error {
	_, err := d.Exec(`
		UPDATE acme_challenges SET status = ?, validated_at = ? WHERE id = ?`,
		status, validatedAt, id)
	if err != nil {
		return fmt.Errorf("update acme challenge: %w", err)
	}
	return nil
}

func (d *DB) InsertAcmeCertOrder(orderID int64, certDER []byte, serialNumber, caName string) (int64, error) {
	hash := fmt.Sprintf("%x", sha256.Sum256(certDER))
	id, err := d.InsertReturning(`
		INSERT INTO acme_cert_orders (order_id, cert_der, serial_number, ca_name, cert_sha256, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		orderID, certDER, serialNumber, caName, hash, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("insert acme cert_order: %w", err)
	}
	return id, nil
}

func (d *DB) GetAcmeCertOrder(orderID int64) (*AcmeCertOrder, error) {
	row := d.QueryRow(`
		SELECT id, order_id, cert_der, serial_number, ca_name, cert_sha256, created_at
		FROM acme_cert_orders WHERE order_id = ?`, orderID)
	return scanAcmeCertOrder(row)
}

// GetAcmeCertOrderByCertHash returns the cert-order row for a given
// lowercase hex SHA-256 of the certificate DER (RFC 9445 renewalInfo key).
func (d *DB) GetAcmeCertOrderByCertHash(hash string) (*AcmeCertOrder, error) {
	row := d.QueryRow(`
		SELECT id, order_id, cert_der, serial_number, ca_name, cert_sha256, created_at
		FROM acme_cert_orders WHERE cert_sha256 = ?`, hash)
	return scanAcmeCertOrder(row)
}

type scannableAcme interface {
	Scan(dest ...any) error
}

func scanAcmeAccount(row scannableAcme) (*AcmeAccount, error) {
	var a AcmeAccount
	var createdAt string
	err := row.Scan(&a.ID, &a.JWKThumbprint, &a.JWKJSON, &a.Contact, &a.Status, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan acme account: %w", err)
	}
	a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &a, nil
}

func scanAcmeOrder(row scannableAcme) (*AcmeOrder, error) {
	var o AcmeOrder
	var createdAt string
	err := row.Scan(&o.ID, &o.AccountID, &o.Status, &o.Identifiers, &o.NotBefore, &o.NotAfter, &o.Expires, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan acme order: %w", err)
	}
	o.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &o, nil
}

func scanAcmeAuthorization(row scannableAcme) (*AcmeAuthorization, error) {
	var a AcmeAuthorization
	var createdAt string
	err := row.Scan(&a.ID, &a.OrderID, &a.IdentifierType, &a.IdentifierValue, &a.Status, &a.Token, &a.Expires, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan acme authz: %w", err)
	}
	a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &a, nil
}

func scanAcmeChallenge(row scannableAcme) (*AcmeChallenge, error) {
	var c AcmeChallenge
	err := row.Scan(&c.ID, &c.AuthzID, &c.Type, &c.Token, &c.Status, &c.ValidatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan acme challenge: %w", err)
	}
	return &c, nil
}

func scanAcmeCertOrder(row scannableAcme) (*AcmeCertOrder, error) {
	var co AcmeCertOrder
	var createdAt string
	err := row.Scan(&co.ID, &co.OrderID, &co.CertDER, &co.SerialNumber, &co.CAName, &co.CertSHA256, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan acme cert_order: %w", err)
	}
	co.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &co, nil
}
