// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"database/sql"
	"fmt"
	"time"
)

// GatewayRecord represents a registered gateway instance.
type GatewayRecord struct {
	ID         int64
	Address    string
	CaName     string
	Status     string
	LastSeen   time.Time
	Registered time.Time
}

// nowStr returns the current time in RFC3339 format for SQL.
func nowStr() string { return time.Now().UTC().Format(time.RFC3339) }

// RegisterGateway registers or updates a gateway address.
func (d *DB) RegisterGateway(address, caName string) error {
	if address == "" {
		return fmt.Errorf("register_gateway: address required")
	}
	now := nowStr()
	// Try to update existing record first (preserves registered timestamp)
	res, err := d.Exec(`
		UPDATE gateway_registry
		SET ca_name = ?, status = 'active', last_seen = ?
		WHERE address = ?`, caName, now, address)
	if err != nil {
		return fmt.Errorf("register_gateway: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// New gateway: insert with current registered time
		_, err = d.Exec(`
			INSERT INTO gateway_registry (address, ca_name, status, last_seen, registered)
			VALUES (?, ?, 'active', ?, ?)`, address, caName, now, now)
		if err != nil {
			return fmt.Errorf("register_gateway: %w", err)
		}
	}
	return nil
}

// HeartbeatGateway updates last_seen for a gateway and sets status to active.
func (d *DB) HeartbeatGateway(address string) error {
	if address == "" {
		return fmt.Errorf("heartbeat_gateway: address required")
	}
	res, err := d.Exec(`
		UPDATE gateway_registry
		SET last_seen = ?, status = 'active'
		WHERE address = ?`, nowStr(), address)
	if err != nil {
		return fmt.Errorf("heartbeat_gateway: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrGatewayNotFound
	}
	return nil
}

// ListActiveGateways returns all gateways with status='active'.
func (d *DB) ListActiveGateways() ([]*GatewayRecord, error) {
	return d.listGateways(true)
}

// ListAllGateways returns all registered gateways.
func (d *DB) ListAllGateways() ([]*GatewayRecord, error) {
	return d.listGateways(false)
}

func (d *DB) listGateways(activeOnly bool) ([]*GatewayRecord, error) {
	query := `
		SELECT id, address, ca_name, status, last_seen, registered
		FROM gateway_registry`
	var args []any
	if activeOnly {
		query += " WHERE status = ?"
		args = append(args, "active")
	}
	query += `
		ORDER BY registered`
	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list_gateways: %w", err)
	}
	defer rows.Close()

	var results []*GatewayRecord
	for rows.Next() {
		var g GatewayRecord
		var lastSeen, registered string
		if err := rows.Scan(&g.ID, &g.Address, &g.CaName, &g.Status, &lastSeen, &registered); err != nil {
			return nil, fmt.Errorf("scan gateway: %w", err)
		}
		g.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
		g.Registered, _ = time.Parse(time.RFC3339, registered)
		results = append(results, &g)
	}
	return results, rows.Err()
}

// MarkGatewayInactive sets a gateway's status to inactive.
func (d *DB) MarkGatewayInactive(address string) error {
	_, err := d.Exec(`
		UPDATE gateway_registry SET status = 'inactive' WHERE address = ?`, address)
	return err
}

// CleanupStaleGateways marks gateways as inactive if last_seen exceeds maxAge.
func (d *DB) CleanupStaleGateways(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().Add(-maxAge).UTC().Format("2006-01-02 15:04:05")
	res, err := d.Exec(`
		UPDATE gateway_registry
		SET status = 'inactive'
		WHERE status = 'active' AND last_seen < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleanup_stale_gateways: %w", err)
	}
	return res.RowsAffected()
}

// RemoveGateway deletes a gateway record by address.
func (d *DB) RemoveGateway(address string) error {
	_, err := d.Exec(`DELETE FROM gateway_registry WHERE address = ?`, address)
	return err
}

// GetGateway returns a single gateway record by address.
func (d *DB) GetGateway(address string) (*GatewayRecord, error) {
	var g GatewayRecord
	var lastSeen, registered string
	err := d.QueryRow(`
		SELECT id, address, ca_name, status, last_seen, registered
		FROM gateway_registry WHERE address = ?`, address).Scan(
		&g.ID, &g.Address, &g.CaName, &g.Status, &lastSeen, &registered)
	if err == sql.ErrNoRows {
		return nil, ErrGatewayNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get_gateway: %w", err)
	}
	g.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
	g.Registered, _ = time.Parse(time.RFC3339, registered)
	return &g, nil
}

// DB errors for gateway registry.
var ErrGatewayNotFound = fmt.Errorf("gateway not found")
