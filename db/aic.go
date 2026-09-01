// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type AICExtension struct {
	ID                 int64   `json:"id,omitempty"`
	CAName             string  `json:"ca_name"`
	SerialNumber       string  `json:"serial_number"`
	AgentID            string  `json:"agent_id"`
	PrincipalUID       string  `json:"principal_uid"`
	CapabilitiesJSON   string  `json:"capabilities_json"`
	DelegationAuthJSON *string `json:"delegation_auth_json,omitempty"`
	AICJSON            string  `json:"aic_json"`
	CreatedAt          string  `json:"created_at,omitempty"`
}

const aicColumns = `ca_name, serial_number, agent_id, principal_uid, capabilities_json, delegation_auth_json, aic_json, created_at`

func (d *DB) InsertAICExtension(a *AICExtension) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.Exec(d.Rebind(`
		INSERT INTO aic_extensions (ca_name, serial_number, agent_id, principal_uid, capabilities_json, delegation_auth_json, aic_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		a.CAName, a.SerialNumber, a.AgentID, a.PrincipalUID, a.CapabilitiesJSON, a.DelegationAuthJSON, a.AICJSON, now)
	return err
}

func (d *DB) GetAICExtensionByCert(caName, serial string) (*AICExtension, error) {
	row := d.QueryRow(d.Rebind(`
		SELECT id, `+aicColumns+` FROM aic_extensions WHERE ca_name=? AND serial_number=?`),
		caName, serial)
	return scanAICExtension(row)
}

func (d *DB) ListAICExtensions(caName string, limit, offset int) ([]*AICExtension, error) {
	var clauses []string
	var args []any
	if caName != "" {
		clauses = append(clauses, "ca_name = ?")
		args = append(args, caName)
	}
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, ` + aicColumns + ` FROM aic_extensions`
	if len(clauses) > 0 {
		query += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	query += ` ORDER BY created_at DESC`
	query = d.Rebind(query + ` LIMIT ? OFFSET ?`)
	args = append(args, limit, offset)

	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list aic extensions: %w", err)
	}
	defer rows.Close()

	var results []*AICExtension
	for rows.Next() {
		a, err := scanAICExtension(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	return results, rows.Err()
}

func (d *DB) SearchAICByAgentID(agentID string, limit, offset int) ([]*AICExtension, error) {
	if limit <= 0 {
		limit = 100
	}
	query := d.Rebind(`SELECT id, ` + aicColumns + ` FROM aic_extensions WHERE agent_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`)
	rows, err := d.Query(query, agentID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("search aic by agent: %w", err)
	}
	defer rows.Close()

	var results []*AICExtension
	for rows.Next() {
		a, err := scanAICExtension(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	return results, rows.Err()
}

func (d *DB) SearchAICByPrincipalUID(principalUID string, limit, offset int) ([]*AICExtension, error) {
	if limit <= 0 {
		limit = 100
	}
	query := d.Rebind(`SELECT id, ` + aicColumns + ` FROM aic_extensions WHERE principal_uid = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`)
	rows, err := d.Query(query, principalUID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("search aic by principal: %w", err)
	}
	defer rows.Close()

	var results []*AICExtension
	for rows.Next() {
		a, err := scanAICExtension(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	return results, rows.Err()
}

func (d *DB) SearchAICByCapability(schemeID string, limit, offset int) ([]*AICExtension, error) {
	if limit <= 0 {
		limit = 100
	}
	query := d.Rebind(`SELECT id, ` + aicColumns + ` FROM aic_extensions WHERE capabilities_json LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?`)
	rows, err := d.Query(query, `%`+EscapeLike(schemeID)+`%`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("search aic by capability: %w", err)
	}
	defer rows.Close()

	var results []*AICExtension
	for rows.Next() {
		a, err := scanAICExtension(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	return results, rows.Err()
}

func (d *DB) DeleteAICExtension(caName, serial string) error {
	_, err := d.Exec(d.Rebind(`DELETE FROM aic_extensions WHERE ca_name=? AND serial_number=?`), caName, serial)
	return err
}

func (d *DB) UpdateAICExtension(a *AICExtension) error {
	_, err := d.Exec(d.Rebind(`
		UPDATE aic_extensions SET agent_id=?, principal_uid=?, capabilities_json=?, delegation_auth_json=?, aic_json=?
		WHERE ca_name=? AND serial_number=?`),
		a.AgentID, a.PrincipalUID, a.CapabilitiesJSON, a.DelegationAuthJSON, a.AICJSON, a.CAName, a.SerialNumber)
	return err
}

func (d *DB) CountAICExtensions(caName string) (int, error) {
	query := `SELECT COUNT(*) FROM aic_extensions`
	var args []any
	if caName != "" {
		query += ` WHERE ca_name = ?`
		args = append(args, caName)
	}
	var count int
	err := d.QueryRow(d.Rebind(query), args...).Scan(&count)
	return count, err
}

func (d *DB) BackfillAICExtensionsFromRefs(refs []AICBackfillRef) (int, error) {
	var count int
	for _, r := range refs {
		existing, err := d.GetAICExtensionByCert(r.CAName, r.Serial)
		if err == nil && existing != nil {
			continue
		}
		a := &AICExtension{
			CAName:             r.CAName,
			SerialNumber:       r.Serial,
			AgentID:            r.AgentID,
			PrincipalUID:       r.PrincipalUID,
			CapabilitiesJSON:   r.CapabilitiesJSON,
			DelegationAuthJSON: r.DelegationAuthJSON,
			AICJSON:            r.AICJSON,
		}
		if err := d.InsertAICExtension(a); err != nil {
			return count, fmt.Errorf("insert backfill %s/%s: %w", r.CAName, r.Serial, err)
		}
		count++
	}
	return count, nil
}

type AICBackfillRef struct {
	CAName             string
	Serial             string
	AgentID            string
	PrincipalUID       string
	CapabilitiesJSON   string
	DelegationAuthJSON *string
	AICJSON            string
}

func (d *DB) ListValidAICCertRefs() ([]struct {
	CAName, Serial string
	CertDER        []byte
}, error) {
	rows, err := d.Query(`SELECT ca_name, serial_number, cert_der FROM certificates WHERE profile_used = 'agent-proxy' AND status = 'V'`)
	if err != nil {
		return nil, fmt.Errorf("query aic certs: %w", err)
	}
	defer rows.Close()
	var results []struct {
		CAName, Serial string
		CertDER        []byte
	}
	for rows.Next() {
		var r struct {
			CAName, Serial string
			CertDER        []byte
		}
		if err := rows.Scan(&r.CAName, &r.Serial, &r.CertDER); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

func scanAICExtension(row scannable) (*AICExtension, error) {
	a := &AICExtension{}
	var daJSON sql.NullString
	if err := row.Scan(&a.ID, &a.CAName, &a.SerialNumber, &a.AgentID, &a.PrincipalUID, &a.CapabilitiesJSON, &daJSON, &a.AICJSON, &a.CreatedAt); err != nil {
		return nil, err
	}
	if daJSON.Valid {
		a.DelegationAuthJSON = &daJSON.String
	}
	return a, nil
}
