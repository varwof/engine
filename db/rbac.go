// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/argon2"
	"time"
)

type RBACUser struct {
	ID           int
	Username     string
	PasswordHash string
	Salt         string
	Role         string
	CAScopes     string
	// OperatorCertPEM holds the management certificate (m-* profile) linked
	// to this account. When set, the account's effective CA scope is derived
	// from this certificate (SAN URI + OID) on every authentication, becoming
	// the cryptographic source of truth for the account's scope.
	OperatorCertPEM string
	Enabled         bool
	CreatedAt       string
}

type UserInfo struct {
	ID        int
	Username  string
	Role      string
	Enabled   bool
	CreatedAt string
}

type RBACToken struct {
	ID          int
	UserID      int
	Token       string
	Description string
	CreatedAt   string
	ExpiresAt   *string
}

type TokenInfo struct {
	UserID   int
	Username string
	Role     string
}

type AuditEntry struct {
	ID         int
	Timestamp  string
	Username   string
	RemoteAddr string
	Method     string
	Path       string
	Action     string
	Detail     string
	EntryHash  string
	PrevHash   string
}

func HashPassword(password, salt string) string {
	// Argon2id parameters: time=1, mem=64MB, threads=4
	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

func GenerateSalt() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// TokenHash returns the SHA-256 digest of a token. Only the digest is stored
// in the database so a DB leak does not expose usable credentials.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func HashAuditEntry(prevHash, timestamp, username, remoteAddr, method, path, action, detail string) string {
	// The Merkle chain covers remote_addr/method/path too so an attacker with
	// DB write access cannot alter those fields without breaking detection.
	h := sha256.Sum256([]byte(prevHash + "|" + timestamp + "|" + username + "|" + remoteAddr + "|" + method + "|" + path + "|" + action + "|" + detail))
	return hex.EncodeToString(h[:])
}

func (d *DB) CreateUser(username, passwordHash, salt, role string) error {
	_, err := d.Exec("INSERT INTO rbac_users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
		username, passwordHash, salt, role)
	return err
}

func (d *DB) GetUserByUsername(username string) (*RBACUser, error) {
	u := &RBACUser{}
	var enabled int
	err := d.QueryRow("SELECT id, username, password_hash, salt, role, COALESCE(ca_scopes, ''), COALESCE(operator_cert_pem, ''), enabled, created_at FROM rbac_users WHERE username = ?", username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.Role, &u.CAScopes, &u.OperatorCertPEM, &enabled, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.Enabled = enabled == 1
	return u, nil
}

func (d *DB) ListUsers() ([]UserInfo, error) {
	rows, err := d.Query("SELECT id, username, role, enabled, created_at FROM rbac_users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []UserInfo
	for rows.Next() {
		var u UserInfo
		var enabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &enabled, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.Enabled = enabled == 1
		users = append(users, u)
	}
	return users, rows.Err()
}

// ListRBACUsers returns the full user rows (including credential columns and CA
// scopes) — the startup source for the engine's in-memory user index.
func (d *DB) ListRBACUsers() ([]RBACUser, error) {
	rows, err := d.Query(`
		SELECT id, username, password_hash, salt, role,
		       COALESCE(ca_scopes, ''), COALESCE(operator_cert_pem, ''), enabled, created_at
		FROM rbac_users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []RBACUser
	for rows.Next() {
		var u RBACUser
		var enabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.Role,
			&u.CAScopes, &u.OperatorCertPEM, &enabled, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.Enabled = enabled == 1
		users = append(users, u)
	}
	return users, rows.Err()
}

func (d *DB) DeleteUser(id int) error {
	d.Exec("DELETE FROM rbac_api_tokens WHERE user_id = ?", id)
	_, err := d.Exec("DELETE FROM rbac_users WHERE id = ?", id)
	return err
}

func (d *DB) UpdateUserPassword(id int, passwordHash, salt string) error {
	// Password change invalidates all previously issued API tokens for this
	// user (AUTH-013): an attacker holding a stolen token must not retain
	// access after the password rotates.
	d.Exec("DELETE FROM rbac_api_tokens WHERE user_id = ?", id)
	_, err := d.Exec("UPDATE rbac_users SET password_hash = ?, salt = ? WHERE id = ?", passwordHash, salt, id)
	return err
}

func (d *DB) UpdateUserCAScopes(id int, caScopes string) error {
	_, err := d.Exec("UPDATE rbac_users SET ca_scopes = ? WHERE id = ?", caScopes, id)
	return err
}

// UpdateUserOperatorCert links (or clears) the management certificate whose
// scope proxies this account's CA permissions. An empty pem unbinds it.
func (d *DB) UpdateUserOperatorCert(id int, pem string) error {
	_, err := d.Exec("UPDATE rbac_users SET operator_cert_pem = ? WHERE id = ?", pem, id)
	return err
}

func (d *DB) CreateAPIToken(userID int, description, expiresAt string) (*RBACToken, error) {
	token, err := GenerateToken()
	if err != nil {
		return nil, err
	}
	var expiry *string
	if expiresAt != "" {
		expiry = &expiresAt
	} else {
		// Default token expiry: 7 days.
		defaultExpiry := time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)
		expiry = &defaultExpiry
	}
	id, err := d.InsertReturning(
		"INSERT INTO rbac_api_tokens (user_id, token, description, expires_at) VALUES (?, ?, ?, ?)",
		userID, TokenHash(token), description, expiry,
	)
	if err != nil {
		return nil, err
	}
	t := &RBACToken{
		ID:          int(id),
		Token:       token,
		UserID:      userID,
		Description: description,
		ExpiresAt:   expiry,
	}
	return t, nil
}

func (d *DB) GetToken(token string) (*TokenInfo, error) {
	t := &TokenInfo{}
	now := time.Now().UTC().Format(time.RFC3339)
	err := d.QueryRow(`
		SELECT u.id, u.username, u.role
		FROM rbac_api_tokens t
		JOIN rbac_users u ON u.id = t.user_id
		WHERE t.token = ? AND u.enabled = 1
		AND (t.expires_at IS NULL OR t.expires_at > ?)
	`, TokenHash(token), now).Scan(&t.UserID, &t.Username, &t.Role)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (d *DB) ListTokens(userID int) ([]RBACToken, error) {
	rows, err := d.Query("SELECT id, user_id, token, description, created_at, expires_at FROM rbac_api_tokens WHERE user_id = ? ORDER BY created_at DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []RBACToken
	for rows.Next() {
		var t RBACToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Token, &t.Description, &t.CreatedAt, &t.ExpiresAt); err != nil {
			return nil, err
		}
		// Never leak token material; expose a masked preview of the hash only.
		if len(t.Token) > 8 {
			t.Token = "••••••••" + t.Token[len(t.Token)-8:]
		} else {
			t.Token = ""
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (d *DB) DeleteToken(id int) error {
	_, err := d.Exec("DELETE FROM rbac_api_tokens WHERE id = ?", id)
	return err
}

// DeleteTokenByHash deletes a token by its stored SHA-256 hash.
func (d *DB) DeleteTokenByHash(hash string) error {
	_, err := d.Exec("DELETE FROM rbac_api_tokens WHERE token = ?", hash)
	return err
}

// TokenHashRow is a single rbac_api_tokens row exposing only the SHA-256 token
// hash (never raw token material) — the startup source for the engine's
// in-memory token index.
type TokenHashRow struct {
	ID        int
	TokenHash string
	UserID    int
	ExpiresAt *string
}

// ListAllTokenHashes returns every API token row (hash + owner + expiry). Used
// by the engine to rebuild its in-memory token index on startup.
func (d *DB) ListAllTokenHashes() ([]TokenHashRow, error) {
	return d.ListAllTokenHashesPage(0, 0)
}

// ListAllTokenHashesPage returns a page of API token rows (hash + owner +
// expiry) ordered by id, for the engine's paginated startup rebuild (finding
// 17). limit <= 0 returns the full set.
func (d *DB) ListAllTokenHashesPage(limit, offset int) ([]TokenHashRow, error) {
	query := "SELECT id, token, user_id, expires_at FROM rbac_api_tokens ORDER BY id"
	if limit > 0 {
		query += " LIMIT ? OFFSET ?"
	}
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = d.Query(query, limit, offset)
	} else {
		rows, err = d.Query(query)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenHashRow
	for rows.Next() {
		var t TokenHashRow
		if err := rows.Scan(&t.ID, &t.TokenHash, &t.UserID, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) LogAudit(username, remoteAddr, method, path, action, detail string) error {
	maskedUser, maskedIP, err := d.MaskAuditFields(username, remoteAddr)
	if err != nil {
		// Fail closed: never store plaintext identity when masking is enabled.
		// A salt-load failure must surface as an error on the audited
		// operation instead of silently persisting PII in the clear (finding 10).
		return fmt.Errorf("audit mask: %w", err)
	}
	lastHash, err := d.GetLastAuditHash()
	if err != nil {
		return err
	}
	ts := time.Now().UTC().Format("2006-01-02 15:04:05")
	h := HashAuditEntry(lastHash, ts, maskedUser, maskedIP, method, path, action, detail)
	_, err = d.Exec("INSERT INTO audit_log (timestamp, username, remote_addr, method, path, action, detail, entry_hash, prev_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		ts, maskedUser, maskedIP, method, path, action, detail, h, lastHash)
	return err
}

func (d *DB) GetLastAuditHash() (string, error) {
	var hash sql.NullString
	err := d.QueryRow("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return hash.String, nil
}

func (d *DB) GetAllAuditEntries() ([]AuditEntry, error) {
	rows, err := d.Query("SELECT id, timestamp, username, remote_addr, method, path, action, detail, entry_hash, prev_hash FROM audit_log ORDER BY id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Username, &e.RemoteAddr, &e.Method, &e.Path, &e.Action, &e.Detail, &e.EntryHash, &e.PrevHash); err != nil {
			return nil, err
		}
		e.Timestamp = ts
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// VerifyAuditChain recomputes the Merkle hash chain over all audit entries
// and returns the number of verified entries. Any tampering (missing entry,
// altered username/action/detail, or broken prev_hash link) yields an error
// naming the offending entry ID. Empty audit log is not an error.
func (d *DB) VerifyAuditChain() (int, error) {
	entries, err := d.GetAllAuditEntries()
	if err != nil {
		return 0, fmt.Errorf("get audit entries: %w", err)
	}
	var prevHash string
	for _, e := range entries {
		expected := HashAuditEntry(prevHash, e.Timestamp, e.Username, e.RemoteAddr, e.Method, e.Path, e.Action, e.Detail)
		if e.EntryHash != expected {
			return 0, fmt.Errorf("audit chain broken at entry %d: hash mismatch", e.ID)
		}
		if e.PrevHash != prevHash {
			return 0, fmt.Errorf("audit chain broken at entry %d: prev_hash mismatch", e.ID)
		}
		prevHash = e.EntryHash
	}
	return len(entries), nil
}

func (d *DB) QueryAudit(limit, offset int) ([]AuditEntry, error) {
	rows, err := d.Query("SELECT id, timestamp, username, remote_addr, method, path, action, detail, entry_hash, prev_hash FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Username, &e.RemoteAddr, &e.Method, &e.Path, &e.Action, &e.Detail, &e.EntryHash, &e.PrevHash); err != nil {
			return nil, err
		}
		e.Timestamp = ts
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (d *DB) backfillAuditHashes() error {
	rows, err := d.Query("SELECT id, timestamp, username, remote_addr, method, path, action, detail FROM audit_log WHERE entry_hash IS NULL ORDER BY id ASC")
	if err != nil {
		return fmt.Errorf("query unhashed audit entries: %w", err)
	}
	defer rows.Close()
	var prevHash string
	for rows.Next() {
		var id int
		var ts, username, remoteAddr, method, path, action, detail string
		if err := rows.Scan(&id, &ts, &username, &remoteAddr, &method, &path, &action, &detail); err != nil {
			return err
		}
		h := HashAuditEntry(prevHash, ts, username, remoteAddr, method, path, action, detail)
		if _, err := d.Exec("UPDATE audit_log SET entry_hash = ?, prev_hash = ? WHERE id = ?", h, prevHash, id); err != nil {
			return err
		}
		prevHash = h
	}
	return rows.Err()
}
