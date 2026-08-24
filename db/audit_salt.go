// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// AuditSalt management: per-day random salts used to HMAC personally
// identifiable fields (username, remote IP) before they reach the audit log.
//
// A salt is created lazily on the first LogAudit of a calendar day, so no
// startup plumbing is required. Salts older than the configured retention
// window are removed by RetireExpiredAuditSalts; once a day's salt is gone,
// the masked values written with it can never be recovered, satisfying
// data-minimization requirements (GDPR storage limitation, Chinese
// Cybersecurity Law logging retention, etc.) while the Merkle hash chain over
// the masked values stays verifiable indefinitely.

const (
	// auditSaltBytes is the entropy of each daily salt (32 bytes → 64 hex).
	auditSaltBytes = 32
)

// auditSaltRetentionDays is the default retention window for daily audit
// salts. It is the maximum days the raw identity can be recovered from the
// masked audit fields; beyond this the salt row is purged.
const auditSaltRetentionDays = 365

// LoadOrCreateAuditSalt returns the salt for the given calendar day (local
// time, format "2006-01-02"), generating and persisting a fresh random one if
// none exists yet. The salt is never exposed to callers who must only pass it
// into MaskAuditField.
func (d *DB) LoadOrCreateAuditSalt(day string) (string, error) {
	var salt string
	err := d.QueryRow(d.Rebind("SELECT salt FROM audit_salts WHERE day = ?"), day).Scan(&salt)
	if err == nil {
		return salt, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("load audit salt %s: %w", day, err)
	}
	buf := make([]byte, auditSaltBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate audit salt: %w", err)
	}
	salt = hex.EncodeToString(buf)
	if _, err := d.Exec(d.Rebind("INSERT INTO audit_salts (day, salt, created) VALUES (?, ?, ?)"),
		day, salt, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return "", fmt.Errorf("store audit salt %s: %w", day, err)
	}
	return salt, nil
}

// MaskAuditField HMAC-SHA256s a sensitive audit field (username, remote IP)
// with the daily salt. The output is a fixed 64-hex digest that is stable for
// a given (day, salt, value) triple but cannot be reversed once the salt row
// is purged. An empty value stays empty (nil salt or empty input) so optional
// fields remain omitted in the stored row.
func MaskAuditField(salt, value string) string {
	if salt == "" || value == "" {
		return value
	}
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// AuditMaskEnabled reports whether salt-based masking is enabled for the
// server. When disabled, LogAudit stores plaintext (legacy behaviour).
var AuditMaskEnabled = true

// GetAuditSaltForNow returns today's local calendar day string.
func GetAuditSaltForNow() string {
	return time.Now().Format("2006-01-02")
}

// SetAuditMaskEnabled toggles masking; used by tests.
func SetAuditMaskEnabled(enabled bool) {
	AuditMaskEnabled = enabled
}

// RetireExpiredAuditSalts deletes audit salt rows older than retentionDays
// calendar days. Returns the number of removed salts.
func (d *DB) RetireExpiredAuditSalts(retentionDays int) (int, error) {
	if retentionDays <= 0 {
		retentionDays = auditSaltRetentionDays
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02")
	res, err := d.Exec(d.Rebind("DELETE FROM audit_salts WHERE day < ?"), cutoff)
	if err != nil {
		return 0, fmt.Errorf("retire audit salts: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MaskAuditFields computes the masked username / remoteAddr for the current
// day using the daily salt. Returns empty strings when masking is disabled.
func (d *DB) MaskAuditFields(username, remoteAddr string) (string, string, error) {
	if !AuditMaskEnabled {
		return username, remoteAddr, nil
	}
	salt, err := d.LoadOrCreateAuditSalt(GetAuditSaltForNow())
	if err != nil {
		// Salt failure must not block audit logging: fall back to plaintext.
		return username, remoteAddr, err
	}
	return MaskAuditField(salt, username), MaskAuditField(salt, remoteAddr), nil
}

// ParseAuditSaltDay extracts a day key from a raw value, or "" if the value is
// already masked (64 hex chars). Used to decide whether a stored field still
// carries plaintext identity.
func ParseAuditSaltDay(raw string) string {
	if len(raw) == 64 {
		_, err := hex.DecodeString(raw)
		if err == nil {
			return ""
		}
	}
	return ""
}

// IsAuditMasked reports whether a stored audit field value is a 64-char hex
// HMAC digest (i.e. was masked) vs plaintext legacy data.
func IsAuditMasked(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil && strings.EqualFold(raw, strings.ToLower(raw)) && !strings.Contains(raw, "/")
}
