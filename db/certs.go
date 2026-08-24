// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrDuplicateSerial = errors.New("duplicate serial number")

const certColumns = `serial_number, ca_name, status, subject, common_name,
	not_before, not_after, revoked_at, revoke_reason, invalidity_date,
	cert_der, fingerprint,
	subject_o, subject_c, issuer_dn, key_algo, key_size, sig_algo, ski, aki, san, profile_used,
	spki_hash, principal_uid, agent_id`

type CertRecord struct {
	SerialNumber   string
	CAName         string
	Status         string
	Subject        string
	CommonName     string
	NotBefore      time.Time
	NotAfter       time.Time
	RevokedAt      *time.Time
	RevokeReason   *int
	InvalidityDate *time.Time
	CertDER        []byte
	Fingerprint    string
	SubjectO       string
	SubjectC       string
	IssuerDN       string
	KeyAlgo        string
	KeySize        int
	SigAlgo        string
	SKI            string
	AKI            string
	SAN            string
	Profile        string
	SPKIHash       string
	PrincipalUid   string
	AgentId        string
}

func (d *DB) InsertCert(record *CertRecord) error {
	var revokedAtStr *string
	if record.RevokedAt != nil {
		s := record.RevokedAt.UTC().Format(time.RFC3339)
		revokedAtStr = &s
	}
	var invalidityDateStr *string
	if record.InvalidityDate != nil {
		s := record.InvalidityDate.UTC().Format(time.RFC3339)
		invalidityDateStr = &s
	}

	res, err := d.Exec(`
		INSERT OR IGNORE INTO certificates
			(serial_number, ca_name, status, subject, common_name,
			 not_before, not_after, revoked_at, revoke_reason, invalidity_date,
			 cert_der, fingerprint,
			 subject_o, subject_c, issuer_dn, key_algo, key_size, sig_algo, ski, aki, san, profile_used,
			 spki_hash, principal_uid, agent_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.SerialNumber, record.CAName, record.Status, record.Subject,
		record.CommonName,
		record.NotBefore.UTC().Format(time.RFC3339),
		record.NotAfter.UTC().Format(time.RFC3339),
		revokedAtStr, record.RevokeReason, invalidityDateStr,
		record.CertDER, record.Fingerprint,
		record.SubjectO, record.SubjectC, record.IssuerDN,
		record.KeyAlgo, record.KeySize, record.SigAlgo,
		record.SKI, record.AKI, record.SAN, record.Profile,
		record.SPKIHash, record.PrincipalUid, record.AgentId,
	)
	if err != nil {
		return fmt.Errorf("insert cert: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("cert %s/%s: %w",
			record.CAName, record.SerialNumber, ErrDuplicateSerial)
	}
	return nil
}

func (d *DB) GetCert(caName, serial string) (*CertRecord, error) {
	row := d.QueryRow(`
		SELECT `+certColumns+`
		FROM certificates
		WHERE ca_name = ? AND serial_number = ?`, caName, serial)

	return scanCertRecord(row)
}

// CertStatus is a lightweight record for OCSP — avoids fetching full CertRecord (cert_der, fingerprint, etc).
type CertStatus struct {
	Status       string
	NotAfter     time.Time
	RevokedAt    *time.Time
	RevokeReason *int
}

// GetPrincipalByCert looks up the issuer-bound record for a client certificate
// forwarded by a trusted gateway (X-Client-Cert-DER passthrough). It returns
// the certificate's status and principal_uid; principalUid is empty for
// non-AIC certificates. sql.ErrNoRows means the certificate is not issued by
// this PKI.
func (d *DB) GetPrincipalByCert(issuerDN, serial string) (status, principalUid string, err error) {
	row := d.QueryRow(`
		SELECT status, principal_uid
		FROM certificates
		WHERE issuer_dn = ? AND serial_number = ?`, issuerDN, serial)

	var uid *string
	if err := row.Scan(&status, &uid); err != nil {
		return "", "", err
	}
	if uid != nil {
		principalUid = *uid
	}
	return status, principalUid, nil
}

func (d *DB) GetCertStatus(caName, serial string) (*CertStatus, error) {
	row := d.QueryRow(`
		SELECT status, not_after, revoked_at, revoke_reason
		FROM certificates
		WHERE ca_name = ? AND serial_number = ?`, caName, serial)

	var s CertStatus
	var notAfterStr string
	var revokedAtStr *string
	if err := row.Scan(&s.Status, &notAfterStr, &revokedAtStr, &s.RevokeReason); err != nil {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, notAfterStr)
	if err != nil {
		return nil, fmt.Errorf("parse not_after: %w", err)
	}
	s.NotAfter = t
	if revokedAtStr != nil {
		t, err := time.Parse(time.RFC3339, *revokedAtStr)
		if err != nil {
			return nil, fmt.Errorf("parse revoked_at: %w", err)
		}
		s.RevokedAt = &t
	}
	return &s, nil
}

// GetCertStatusByIssuer looks up certificate status by issuer DN + serial.
// It is used by TLS client-cert revocation checks, where the issuing CA name
// is not known ahead of time (the issuer DN uniquely identifies the CA).
func (d *DB) GetCertStatusByIssuer(issuerDN, serial string) (*CertStatus, error) {
	row := d.QueryRow(`
		SELECT status, not_after, revoked_at, revoke_reason
		FROM certificates
		WHERE issuer_dn = ? AND serial_number = ?`, issuerDN, serial)

	var s CertStatus
	var notAfterStr string
	var revokedAtStr *string
	if err := row.Scan(&s.Status, &notAfterStr, &revokedAtStr, &s.RevokeReason); err != nil {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, notAfterStr)
	if err != nil {
		return nil, fmt.Errorf("parse not_after: %w", err)
	}
	s.NotAfter = t
	if revokedAtStr != nil {
		t, err := time.Parse(time.RFC3339, *revokedAtStr)
		if err != nil {
			return nil, fmt.Errorf("parse revoked_at: %w", err)
		}
		s.RevokedAt = &t
	}
	return &s, nil
}

// ListAllCerts returns every certificate across all CAs. It is used by the
// memory engine (engine package) for a full in-memory rebuild on startup.
func (d *DB) ListAllCerts() ([]*CertRecord, error) {
	rows, err := d.Query(`
		SELECT ` + certColumns + `
		FROM certificates
		ORDER BY ca_name, not_before`)
	if err != nil {
		return nil, fmt.Errorf("list all certs: %w", err)
	}
	defer rows.Close()

	var records []*CertRecord
	for rows.Next() {
		r, err := scanCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// ListAllCertsPage returns a page of certificates with SQL LIMIT/OFFSET
// pagination, so a full rebuild can avoid materializing every row at once.
// The stable ORDER BY guarantees each page is disjoint across calls. The
// engine uses this on startup instead of ListAllCerts to cap peak memory.
func (d *DB) ListAllCertsPage(limit, offset int) ([]*CertRecord, error) {
	if limit <= 0 {
		return d.ListAllCerts()
	}
	rows, err := d.Query(`
		SELECT `+certColumns+`
		FROM certificates
		ORDER BY ca_name, not_before, serial_number
		LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list all certs page: %w", err)
	}
	defer rows.Close()

	var records []*CertRecord
	for rows.Next() {
		r, err := scanCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (d *DB) ListCerts(caName string) ([]*CertRecord, error) {
	rows, err := d.Query(`
		SELECT `+certColumns+`
		FROM certificates
		WHERE ca_name = ?
		ORDER BY not_before DESC`, caName)
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	defer rows.Close()

	var records []*CertRecord
	for rows.Next() {
		r, err := scanCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// ListCertsFiltered returns certificates for a CA, with optional status/cn filters applied in SQL.
// Empty status or cn means no filter. cn matching is case-insensitive.
func (d *DB) ListCertsFiltered(caName, status, cn string) ([]*CertRecord, error) {
	return d.ListCertsFilteredPage(caName, status, cn, 0, 0)
}

// ListCertsFilteredPage is the same as ListCertsFiltered, but supports
// SQL-level LIMIT/OFFSET pagination.
// limit <= 0 means no pagination (return all matching rows).
func (d *DB) ListCertsFilteredPage(caName, status, cn string, limit, offset int) ([]*CertRecord, error) {
	var clauses []string
	var args []any
	clauses = append(clauses, "ca_name = ?")
	args = append(args, caName)
	if status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}
	if cn != "" {
		clauses = append(clauses, d.LikeExpr("common_name"))
		args = append(args, cn)
	}
	query := fmt.Sprintf(`
		SELECT `+certColumns+`
		FROM certificates
		WHERE %s
		ORDER BY not_before DESC`, strings.Join(clauses, " AND "))
	if limit > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	}
	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list certs filtered: %w", err)
	}
	defer rows.Close()
	var records []*CertRecord
	for rows.Next() {
		r, err := scanCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// CountActiveAICByPrincipalUid counts the number of currently active
// agent-proxy AIC certificates for a given principal (principal_uid),
// i.e. status='V', non-empty agent_id, and not expired.
// Used to enforce DelegationPolicy.MaxAgents concurrency limits (B2).
func (d *DB) CountActiveAICByPrincipalUid(principalUID string, now time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM certificates
		WHERE principal_uid = ? AND status = 'V'
		  AND agent_id IS NOT NULL AND agent_id != ''
		  AND not_before <= ? AND not_after > ?`
	var n int
	if err := d.QueryRow(query, principalUID, now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)).Scan(&n); err != nil {
		return 0, fmt.Errorf("count active aic by principal: %w", err)
	}
	return n, nil
}

// CountCertsByCA counts certificates under a given CA (with optional status filter).
func (d *DB) CountCertsByCA(caName, status string) (int, error) {
	query := "SELECT COUNT(*) FROM certificates WHERE ca_name = ?"
	args := []any{caName}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	var n int
	if err := d.QueryRow(query, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// InsertCertWithDedup checks for duplicate CN in the same transaction as the insert,
// avoiding the race condition between CheckDuplicateCN and InsertCert.
func (d *DB) InsertCertWithDedup(record *CertRecord) error {
	tx, err := d.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check duplicate CN within the transaction. Use equality form (only
	// ca_name/common_name/status) so the planner hits
	// idx_certificates_ca_cn_status for a point lookup; adding
	// not_before/not_after range predicates in SQL would cause SQLite to
	// mischoose idx_certificates_ca_notbefore without ANALYZE stats,
	// degrading to a full range scan per CA (~17ms per 40K rows). Time
	// overlap is checked on the Go side, with identical semantics.
	rows, err := d.TxQuery(tx, `
		SELECT serial_number, not_before, not_after FROM certificates
		WHERE ca_name = ? AND common_name = ? AND status = 'V'`,
		record.CAName, record.CommonName)
	if err != nil {
		return fmt.Errorf("check dup cn: %w", err)
	}
	for rows.Next() {
		var serial string
		var nb, na string
		if err := rows.Scan(&serial, &nb, &na); err != nil {
			rows.Close()
			return fmt.Errorf("check dup cn scan: %w", err)
		}
		notBefore, err1 := time.Parse(time.RFC3339, nb)
		notAfter, err2 := time.Parse(time.RFC3339, na)
		if err1 == nil && err2 == nil &&
			record.NotBefore.Before(notAfter) && record.NotAfter.After(notBefore) {
			rows.Close()
			return fmt.Errorf("duplicate CN %q: active cert %s already exists (valid %s – %s)",
				record.CommonName, serial,
				notBefore.Format("2006-01-02"), notAfter.Format("2006-01-02"))
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("check dup cn: %w", err)
	}
	rows.Close()

	// Insert cert
	var revokedAtStr *string
	if record.RevokedAt != nil {
		s := record.RevokedAt.UTC().Format(time.RFC3339)
		revokedAtStr = &s
	}
	var invalidityDateStr *string
	if record.InvalidityDate != nil {
		s := record.InvalidityDate.UTC().Format(time.RFC3339)
		invalidityDateStr = &s
	}
	res, err := d.TxExec(tx, `
		INSERT OR IGNORE INTO certificates
			(serial_number, ca_name, status, subject, common_name,
			 not_before, not_after, revoked_at, revoke_reason, invalidity_date,
			 cert_der, fingerprint,
			 subject_o, subject_c, issuer_dn, key_algo, key_size, sig_algo, ski, aki, san, profile_used,
			 spki_hash, principal_uid, agent_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.SerialNumber, record.CAName, record.Status, record.Subject,
		record.CommonName,
		record.NotBefore.UTC().Format(time.RFC3339),
		record.NotAfter.UTC().Format(time.RFC3339),
		revokedAtStr, record.RevokeReason, invalidityDateStr,
		record.CertDER, record.Fingerprint,
		record.SubjectO, record.SubjectC, record.IssuerDN,
		record.KeyAlgo, record.KeySize, record.SigAlgo,
		record.SKI, record.AKI, record.SAN, record.Profile,
		record.SPKIHash, record.PrincipalUid, record.AgentId,
	)
	if err != nil {
		return fmt.Errorf("insert cert: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("cert %s/%s: %w",
			record.CAName, record.SerialNumber, ErrDuplicateSerial)
	}
	return tx.Commit()
}

// CheckDuplicateCN returns an error if an active certificate with the same
// common_name already exists under the given CA with overlapping validity.
func (d *DB) ListArchivedCerts(caName string, limit int) ([]*CertRecord, error) {
	query := `SELECT ` + certColumns + ` FROM cert_archive`
	var args []any
	if caName != "" {
		query += " WHERE ca_name = ?"
		args = append(args, caName)
	}
	query += " ORDER BY archived_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := d.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list archived: %w", err)
	}
	defer rows.Close()
	var records []*CertRecord
	for rows.Next() {
		r, err := scanCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (d *DB) CheckDuplicateCN(caName, cn string, notBefore, notAfter time.Time) error {
	rows, err := d.Query(`
		SELECT `+certColumns+`
		FROM certificates
		WHERE ca_name = ? AND common_name = ? AND status = 'V'
		ORDER BY not_before DESC`, caName, cn)
	if err != nil {
		return fmt.Errorf("check dup cn: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		r, err := scanCertRecord(rows)
		if err != nil {
			return err
		}
		// Overlap: existing [r.NotBefore, r.NotAfter] overlaps with [notBefore, notAfter]
		if notBefore.Before(r.NotAfter) && notAfter.After(r.NotBefore) {
			return fmt.Errorf("duplicate CN %q: active cert %s already exists (valid %s – %s)",
				cn, r.SerialNumber, r.NotBefore.Format("2006-01-02"), r.NotAfter.Format("2006-01-02"))
		}
	}
	return rows.Err()
}

func (d *DB) RevokeCert(caName, serial string, reason int) error {
	now := time.Now().UTC()
	res, err := d.Exec(`
		UPDATE certificates
		SET status = 'R', revoked_at = ?, revoke_reason = ?, invalidity_date = revoked_at
		WHERE ca_name = ? AND serial_number = ? AND status = 'V'`,
		now.Format(time.RFC3339), reason, caName, serial)
	if err != nil {
		return fmt.Errorf("revoke cert: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("certificate %s/%s not found or already revoked", caName, serial)
	}
	notifyCertRevoked(serial)
	return nil
}

func (d *DB) GetRevokedCerts(caName string) ([]*CertRecord, error) {
	rows, err := d.Query(`
		SELECT `+certColumns+`
		FROM certificates
		WHERE ca_name = ? AND status = 'R'
		ORDER BY revoked_at DESC`, caName)
	if err != nil {
		return nil, fmt.Errorf("list revoked: %w", err)
	}
	defer rows.Close()

	var records []*CertRecord
	for rows.Next() {
		r, err := scanCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

// RevokedCertEntry is a lightweight record for CRL generation.
type RevokedCertEntry struct {
	SerialNumber   string
	RevokedAt      *time.Time
	RevokeReason   *int
	InvalidityDate *time.Time
}

func (d *DB) GetRevokedCertEntries(caName string) ([]*RevokedCertEntry, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	rows, err := d.Query(`
		SELECT serial_number, revoked_at, revoke_reason, invalidity_date
		FROM certificates
		WHERE ca_name = ? AND status = 'R' AND not_after >= ?
		ORDER BY revoked_at DESC`, caName, now)
	if err != nil {
		return nil, fmt.Errorf("list revoked entries: %w", err)
	}
	defer rows.Close()

	return scanRevokedEntries(rows)
}

// GetRevokedCertEntriesSince returns revoked (non-expired) entries for a CA
// whose revocation happened at or after `since` (RFC 5280 Delta CRL semantics:
// the delta covers certificates revoked since the base CRL thisUpdate).
func (d *DB) GetRevokedCertEntriesSince(caName string, since time.Time) ([]*RevokedCertEntry, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	sinceStr := since.UTC().Format(time.RFC3339)
	rows, err := d.Query(`
		SELECT serial_number, revoked_at, revoke_reason, invalidity_date
		FROM certificates
		WHERE ca_name = ? AND status = 'R' AND not_after >= ? AND revoked_at >= ?
		ORDER BY revoked_at DESC`, caName, now, sinceStr)
	if err != nil {
		return nil, fmt.Errorf("list revoked entries since: %w", err)
	}
	defer rows.Close()

	return scanRevokedEntries(rows)
}

func scanRevokedEntries(rows *sql.Rows) ([]*RevokedCertEntry, error) {
	var entries []*RevokedCertEntry
	for rows.Next() {
		var e RevokedCertEntry
		var revokedAtStr *string
		var invalidityStr *string
		if err := rows.Scan(&e.SerialNumber, &revokedAtStr, &e.RevokeReason, &invalidityStr); err != nil {
			return nil, fmt.Errorf("scan revoked entry: %w", err)
		}
		if revokedAtStr != nil {
			t, err := time.Parse(time.RFC3339, *revokedAtStr)
			if err != nil {
				return nil, fmt.Errorf("parse revoked_at: %w", err)
			}
			e.RevokedAt = &t
		}
		if invalidityStr != nil {
			t, err := time.Parse(time.RFC3339, *invalidityStr)
			if err != nil {
				return nil, fmt.Errorf("parse invalidity_date: %w", err)
			}
			e.InvalidityDate = &t
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// CertRef is a lightweight reference to a certificate with its DER data.
type CertRef struct {
	CAName       string
	SerialNumber string
	CertDER      []byte
} // ListAllValidCertRefs returns all valid (non-revoked, non-expired) certificates
// across all CAs, with their DER data.
func (d *DB) ListAllValidCertRefs() ([]*CertRef, error) {
	rows, err := d.Query(`
		SELECT ca_name, serial_number, cert_der
		FROM certificates
		WHERE status = 'V'
		ORDER BY ca_name, serial_number`)
	if err != nil {
		return nil, fmt.Errorf("list valid cert refs: %w", err)
	}
	defer rows.Close()

	var refs []*CertRef
	for rows.Next() {
		var ref CertRef
		if err := rows.Scan(&ref.CAName, &ref.SerialNumber, &ref.CertDER); err != nil {
			return nil, fmt.Errorf("scan cert ref: %w", err)
		}
		refs = append(refs, &ref)
	}
	return refs, rows.Err()
}

func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return fmt.Sprintf("%x", h)
}

type scannable interface {
	Scan(dest ...any) error
}

func scanCertRecord(row scannable) (*CertRecord, error) {
	var (
		r                 CertRecord
		notBeforeStr      string
		notAfterStr       string
		revokedAtStr      *string
		revokeReason      *int
		invalidityDateStr *string
		profileNull       sql.NullString
		sanNull           sql.NullString
	)

	var spkiHash sql.NullString
	var principalUid sql.NullString
	var agentId sql.NullString
	err := row.Scan(
		&r.SerialNumber, &r.CAName, &r.Status, &r.Subject, &r.CommonName,
		&notBeforeStr, &notAfterStr, &revokedAtStr, &revokeReason,
		&invalidityDateStr,
		&r.CertDER, &r.Fingerprint,
		&r.SubjectO, &r.SubjectC, &r.IssuerDN,
		&r.KeyAlgo, &r.KeySize, &r.SigAlgo,
		&r.SKI, &r.AKI, &sanNull, &profileNull,
		&spkiHash, &principalUid, &agentId,
	)
	r.Profile = profileNull.String
	r.SAN = sanNull.String
	r.SPKIHash = spkiHash.String
	r.PrincipalUid = principalUid.String
	r.AgentId = agentId.String
	if err != nil {
		return nil, fmt.Errorf("scan cert: %w", err)
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
	if invalidityDateStr != nil {
		t, err := time.Parse(time.RFC3339, *invalidityDateStr)
		if err == nil {
			r.InvalidityDate = &t
		}
	}

	return &r, nil
}

func (d *DB) GetCertBySPKIHash(spkiHash, caName, status string) ([]*CertRecord, error) {
	var clauses []string
	var args []any
	clauses = append(clauses, "spki_hash = ?")
	args = append(args, spkiHash)
	if caName != "" {
		clauses = append(clauses, "ca_name = ?")
		args = append(args, caName)
	}
	if status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}
	rows, err := d.Query(`
		SELECT `+certColumns+`
		FROM certificates
		WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY not_before DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("list certs by spki hash: %w", err)
	}
	defer rows.Close()
	var records []*CertRecord
	for rows.Next() {
		r, err := scanCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func SPKIHash(cert *x509.Certificate) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(pubBytes)
	return fmt.Sprintf("%x", h), nil
}

func (d *DB) RevokeCertsByPrincipalUid(principalUid string, reason int) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.Exec(`
		UPDATE certificates SET status='R', revoked_at=?, revoke_reason=?
		WHERE principal_uid=? AND status='V'`, now, reason, principalUid)
	if err != nil {
		return 0, fmt.Errorf("revoke by principal uid: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		notifyCertRevoked("") // bulk: invalidate all cached revocation statuses
	}
	return int(n), nil
}

// RevokeBatchEntry identifies a single certificate to revoke in a bulk
// operation.
type RevokeBatchEntry struct {
	CA     string
	Serial string
	Reason int
}

func (d *DB) RevokeCertsBySubCA(caName string, reason int) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.Exec(`
		UPDATE certificates SET status='R', revoked_at=?, revoke_reason=?
		WHERE ca_name=? AND status='V'`, now, reason, caName)
	if err != nil {
		return 0, fmt.Errorf("revoke by sub-ca: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		notifyCertRevoked("") // bulk: invalidate all cached revocation statuses
	}
	return int(n), nil
}

// RevokeCertsBatch revokes a set of (ca, serial) pairs in a single
// transaction. Used as the non-resident fallback after an engine batch revoke
// (entries the engine could not find in memory are retried here), or as the
// direct path when the memory engine is disabled. Returns the number of rows
// actually updated. A transaction keeps the batch atomic across dialects.
func (d *DB) RevokeCertsBatch(entries []RevokeBatchEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := d.DB.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin batch revoke: %w", err)
	}
	defer tx.Rollback()
	n := 0
	for _, en := range entries {
		res, err := d.TxExec(tx, `
			UPDATE certificates SET status='R', revoked_at=?, revoke_reason=?, invalidity_date=?
			WHERE ca_name=? AND serial_number=? AND status='V'`,
			now, en.Reason, now, en.CA, en.Serial)
		if err != nil {
			return 0, fmt.Errorf("batch revoke %s/%s: %w", en.CA, en.Serial, err)
		}
		if c, _ := res.RowsAffected(); c > 0 {
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit batch revoke: %w", err)
	}
	if n > 0 {
		notifyCertRevoked("") // bulk: invalidate all cached revocation statuses
	}
	return n, nil
}

// OnCertRevoked, if set, is invoked after one or more certificates are marked
// revoked. serial is the revoked certificate's serial (empty for bulk
// revocations where many certificates changed at once). Set by the serve
// command to invalidate the mTLS handshake revocation cache so a freshly
// revoked client certificate fails closed immediately instead of waiting out
// the cache TTL.
var OnCertRevoked func(serial string)

func notifyCertRevoked(serial string) {
	if OnCertRevoked != nil {
		OnCertRevoked(serial)
	}
}

func (d *DB) ListCertsByPrincipalUid(principalUid, status string) ([]*CertRecord, error) {
	var clauses []string
	var args []any
	clauses = append(clauses, "principal_uid = ?")
	args = append(args, principalUid)
	if status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}
	rows, err := d.Query(`
		SELECT `+certColumns+`
		FROM certificates
		WHERE `+strings.Join(clauses, " AND ")+`
		ORDER BY not_before DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("list certs by principal uid: %w", err)
	}
	defer rows.Close()
	var records []*CertRecord
	for rows.Next() {
		r, err := scanCertRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func (d *DB) BackfillAICFieldsFromDer(caName, serial string, principalUid, agentId string) error {
	_, err := d.Exec(d.Rebind(
		"UPDATE certificates SET principal_uid = ?, agent_id = ? WHERE ca_name = ? AND serial_number = ?"),
		principalUid, agentId, caName, serial)
	return err
}

func (d *DB) ListCertsNeedingAICBackfill() ([]struct {
	CAName, Serial string
	CertDER        []byte
}, error) {
	rows, err := d.Query(`SELECT ca_name, serial_number, cert_der FROM certificates WHERE (principal_uid IS NULL OR principal_uid = '') AND profile_used = 'agent-proxy'`)
	if err != nil {
		return nil, fmt.Errorf("query certs for aic backfill: %w", err)
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
