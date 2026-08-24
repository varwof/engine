// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"database/sql"
	"fmt"
	"time"
)

type RARequest struct {
	ID                int
	CSRDER            []byte
	CommonName        string
	SANList           string
	Profile           string
	CAName            string
	Status            string
	Requester         string
	RequestedAt       string
	IssuedSerial      *string
	IssuedAt          *string
	RejectReason      *string
	RequiredApprovals int
	ApprovalCount     int
}

type RAApproval struct {
	ID        int
	RequestID int
	Approver  string
	Decision  string
	Comment   *string
	DecidedAt string
}

func (d *DB) CreateRARequest(csrDER []byte, cn, sanList, profile, caName, requester string, requiredApprovals int) (int, error) {
	id, err := d.InsertReturning(`
		INSERT INTO ra_requests (csr_der, common_name, san_list, profile, ca_name, requester, required_approvals)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		csrDER, cn, sanList, profile, caName, requester, requiredApprovals)
	if err != nil {
		return 0, fmt.Errorf("create ra request: %w", err)
	}
	return int(id), nil
}

func (d *DB) GetRARequest(id int) (*RARequest, error) {
	r := &RARequest{}
	var sanList, issuedSerial, issuedAt, rejectReason *string
	err := d.QueryRow(`
		SELECT id, csr_der, common_name, san_list, profile, ca_name, status,
		       requester, requested_at, issued_serial, issued_at, reject_reason, required_approvals
		FROM ra_requests WHERE id = ?`, id).Scan(
		&r.ID, &r.CSRDER, &r.CommonName, &sanList, &r.Profile, &r.CAName, &r.Status,
		&r.Requester, &r.RequestedAt, &issuedSerial, &issuedAt, &rejectReason, &r.RequiredApprovals)
	if err != nil {
		return nil, fmt.Errorf("get ra request: %w", err)
	}
	if sanList != nil {
		r.SANList = *sanList
	}
	r.IssuedSerial = issuedSerial
	r.IssuedAt = issuedAt
	r.RejectReason = rejectReason

	err = d.QueryRow("SELECT COUNT(*) FROM ra_approvals WHERE request_id = ? AND decision = 'approved'", id).Scan(&r.ApprovalCount)
	if err != nil {
		return nil, fmt.Errorf("count approvals: %w", err)
	}
	return r, nil
}

func (d *DB) ListRARequests(statusFilter string, limit, offset int) ([]*RARequest, error) {
	var rows *sql.Rows
	var err error
	if statusFilter != "" {
		rows, err = d.Query(`
			SELECT id, csr_der, common_name, san_list, profile, ca_name, status,
			       requester, requested_at, issued_serial, issued_at, reject_reason, required_approvals
			FROM ra_requests WHERE status = ?
			ORDER BY requested_at DESC LIMIT ? OFFSET ?`, statusFilter, limit, offset)
	} else {
		rows, err = d.Query(`
			SELECT id, csr_der, common_name, san_list, profile, ca_name, status,
			       requester, requested_at, issued_serial, issued_at, reject_reason, required_approvals
			FROM ra_requests
			ORDER BY requested_at DESC LIMIT ? OFFSET ?`, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("list ra requests: %w", err)
	}
	defer rows.Close()

	var requests []*RARequest
	for rows.Next() {
		r := &RARequest{}
		var sanList, issuedSerial, issuedAt, rejectReason *string
		if err := rows.Scan(
			&r.ID, &r.CSRDER, &r.CommonName, &sanList, &r.Profile, &r.CAName, &r.Status,
			&r.Requester, &r.RequestedAt, &issuedSerial, &issuedAt, &rejectReason, &r.RequiredApprovals); err != nil {
			return nil, fmt.Errorf("scan ra request: %w", err)
		}
		if sanList != nil {
			r.SANList = *sanList
		}
		r.IssuedSerial = issuedSerial
		r.IssuedAt = issuedAt
		r.RejectReason = rejectReason
		requests = append(requests, r)
	}
	return requests, rows.Err()
}

func (d *DB) AddRAApproval(requestID int, approver, decision, comment string) (approvedCount, totalRequired int, err error) {
	tx, err := d.Begin()
	if err != nil {
		return 0, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var commentPtr *string
	if comment != "" {
		commentPtr = &comment
	}
	_, err = d.TxExec(tx, `
		INSERT OR IGNORE INTO ra_approvals (request_id, approver, decision, comment)
		VALUES (?, ?, ?, ?)`, requestID, approver, decision, commentPtr)
	if err != nil {
		return 0, 0, fmt.Errorf("insert approval: %w", err)
	}

	err = d.TxQueryRow(tx, "SELECT required_approvals FROM ra_requests WHERE id = ?", requestID).Scan(&totalRequired)
	if err != nil {
		return 0, 0, fmt.Errorf("get required approvals: %w", err)
	}

	err = d.TxQueryRow(tx, "SELECT COUNT(*) FROM ra_approvals WHERE request_id = ? AND decision = 'approved'", requestID).Scan(&approvedCount)
	if err != nil {
		return 0, 0, fmt.Errorf("count approvals: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit tx: %w", err)
	}
	return approvedCount, totalRequired, nil
}

func (d *DB) UpdateRARequestStatus(id int, status, serial, rejectReason string) error {
	if serial != "" {
		now := time.Now().UTC().Format(time.RFC3339)
		_, err := d.Exec(`
			UPDATE ra_requests SET status = ?, issued_serial = ?, issued_at = ?
			WHERE id = ?`, status, serial, now, id)
		if err != nil {
			return fmt.Errorf("update ra request status: %w", err)
		}
	} else if rejectReason != "" {
		_, err := d.Exec(`
			UPDATE ra_requests SET status = ?, reject_reason = ? WHERE id = ?`, status, rejectReason, id)
		if err != nil {
			return fmt.Errorf("update ra request status: %w", err)
		}
	} else {
		_, err := d.Exec(`
			UPDATE ra_requests SET status = ? WHERE id = ?`, status, id)
		if err != nil {
			return fmt.Errorf("update ra request status: %w", err)
		}
	}
	return nil
}

func (d *DB) CountRAPending() (int, error) {
	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM ra_requests WHERE status = 'pending'").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count pending: %w", err)
	}
	return count, nil
}
