// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	h := HashPassword("testpass", "salt123")
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}
}

func TestGenerateSalt(t *testing.T) {
	s1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	s2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if s1 == s2 {
		t.Fatal("salts should be unique")
	}
	if len(s1) != 16 {
		t.Fatalf("expected 16 hex chars, got %d", len(s1))
	}
}

func TestGenerateToken(t *testing.T) {
	t1, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	t2, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if t1 == t2 {
		t.Fatal("tokens should be unique")
	}
	if len(t1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(t1))
	}
}

func TestHashAuditEntry(t *testing.T) {
	h := HashAuditEntry("", "2024-01-01", "admin", "create", "test")
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}

	h2 := HashAuditEntry(h, "2024-01-02", "admin", "revoke", "serial=1")
	if h2 == h {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestCreateAndGetUser(t *testing.T) {
	d := newTestDB(t)

	salt, _ := GenerateSalt()
	hash := HashPassword("secret", salt)
	if err := d.CreateUser("testuser", hash, salt, "operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	u, err := d.GetUserByUsername("testuser")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if u.Username != "testuser" {
		t.Fatalf("expected testuser, got %q", u.Username)
	}
	if u.Role != "operator" {
		t.Fatalf("expected operator, got %q", u.Role)
	}
	if !u.Enabled {
		t.Fatal("expected user to be enabled")
	}
}

func TestGetUserNotFound(t *testing.T) {
	d := newTestDB(t)

	_, err := d.GetUserByUsername("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestListUsers(t *testing.T) {
	d := newTestDB(t)

	salt, _ := GenerateSalt()
	d.CreateUser("user-a", HashPassword("p1", salt), salt, "admin")
	d.CreateUser("user-b", HashPassword("p2", salt), salt, "operator")

	users, err := d.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestDeleteUser(t *testing.T) {
	d := newTestDB(t)

	salt, _ := GenerateSalt()
	d.CreateUser("delete-me", HashPassword("p", salt), salt, "auditor")

	u, _ := d.GetUserByUsername("delete-me")
	if err := d.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	_, err := d.GetUserByUsername("delete-me")
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestUpdateUserOperatorCert(t *testing.T) {
	d := newTestDB(t)

	salt, _ := GenerateSalt()
	d.CreateUser("cert-user", HashPassword("p", salt), salt, "operator")

	u, _ := d.GetUserByUsername("cert-user")
	if u.OperatorCertPEM != "" {
		t.Fatalf("expected empty operator cert, got %q", u.OperatorCertPEM)
	}

	const pem = "-----BEGIN CERTIFICATE-----\nMIIB----\n-----END CERTIFICATE-----\n"
	if err := d.UpdateUserOperatorCert(u.ID, pem); err != nil {
		t.Fatalf("UpdateUserOperatorCert: %v", err)
	}

	got, err := d.GetUserByUsername("cert-user")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.OperatorCertPEM != pem {
		t.Fatalf("expected operator cert %q, got %q", pem, got.OperatorCertPEM)
	}

	// Unbind (empty string clears the cert)
	if err := d.UpdateUserOperatorCert(u.ID, ""); err != nil {
		t.Fatalf("UpdateUserOperatorCert(unbind): %v", err)
	}
	got, _ = d.GetUserByUsername("cert-user")
	if got.OperatorCertPEM != "" {
		t.Fatalf("expected empty operator cert after unbind, got %q", got.OperatorCertPEM)
	}
}

func TestUpdateUserPassword(t *testing.T) {
	d := newTestDB(t)

	salt, _ := GenerateSalt()
	d.CreateUser("changeme", HashPassword("old", salt), salt, "operator")

	u, _ := d.GetUserByUsername("changeme")

	tok, err := d.CreateAPIToken(u.ID, "login", "")
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	// GetToken should resolve the token before the password change.
	if _, err := d.GetToken(tok.Token); err != nil {
		t.Fatalf("token should be valid before password change: %v", err)
	}

	newSalt, _ := GenerateSalt()
	newHash := HashPassword("newpass", newSalt)
	if err := d.UpdateUserPassword(u.ID, newHash, newSalt); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}

	u2, _ := d.GetUserByUsername("changeme")
	if u2.PasswordHash == u.PasswordHash {
		t.Fatal("password hash should have changed")
	}

	// AUTH-013: password change must invalidate all previously issued tokens.
	if _, err := d.GetToken(tok.Token); err == nil {
		t.Fatal("token must be revoked after password change")
	}
	tokens, _ := d.ListTokens(u.ID)
	if len(tokens) != 0 {
		t.Fatalf("expected no remaining tokens, got %d", len(tokens))
	}
}

func TestCreateAPIToken(t *testing.T) {
	d := newTestDB(t)

	salt, _ := GenerateSalt()
	d.CreateUser("tokenuser", HashPassword("p", salt), salt, "admin")
	u, _ := d.GetUserByUsername("tokenuser")

	tok, err := d.CreateAPIToken(u.ID, "test-token", "")
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if tok.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if tok.Description != "test-token" {
		t.Fatalf("expected test-token, got %q", tok.Description)
	}

	info, err := d.GetToken(tok.Token)
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if info.Username != "tokenuser" {
		t.Fatalf("expected tokenuser, got %q", info.Username)
	}
	if info.Role != "admin" {
		t.Fatalf("expected admin, got %q", info.Role)
	}
}

func TestGetTokenInvalid(t *testing.T) {
	d := newTestDB(t)

	_, err := d.GetToken("nonexistent-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestListTokens(t *testing.T) {
	d := newTestDB(t)

	salt, _ := GenerateSalt()
	d.CreateUser("tokenowner", HashPassword("p", salt), salt, "operator")
	u, _ := d.GetUserByUsername("tokenowner")

	d.CreateAPIToken(u.ID, "tok1", "")
	d.CreateAPIToken(u.ID, "tok2", "")

	tokens, err := d.ListTokens(u.ID)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestDeleteToken(t *testing.T) {
	d := newTestDB(t)

	salt, _ := GenerateSalt()
	d.CreateUser("tokdel", HashPassword("p", salt), salt, "auditor")
	u, _ := d.GetUserByUsername("tokdel")
	tok, _ := d.CreateAPIToken(u.ID, "delete-me", "")

	if err := d.DeleteToken(tok.ID); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}

	_, err := d.GetToken(tok.Token)
	if err == nil {
		t.Fatal("expected error after token deletion")
	}
}

func TestLogAndGetAudit(t *testing.T) {
	d := newTestDB(t)

	if err := d.LogAudit("admin", "127.0.0.1", "GET", "/api/cas", "list_cas", "listed all CAs"); err != nil {
		t.Fatalf("LogAudit: %v", err)
	}

	if err := d.LogAudit("admin", "127.0.0.1", "POST", "/api/certs", "issue_cert", "issued cert"); err != nil {
		t.Fatal(err)
	}

	entries, err := d.GetAllAuditEntries()
	if err != nil {
		t.Fatalf("GetAllAuditEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].EntryHash == "" {
		t.Fatal("expected non-empty entry_hash")
	}
	if entries[0].PrevHash != "" {
		t.Fatalf("expected empty prev_hash for first entry, got %q", entries[0].PrevHash)
	}
	if entries[1].PrevHash != entries[0].EntryHash {
		t.Fatal("second entry should chain to first")
	}
}

func TestQueryAudit(t *testing.T) {
	d := newTestDB(t)

	for i := 0; i < 5; i++ {
		d.LogAudit("admin", "10.0.0.1", "GET", "/api/cas", "list", "")
	}

	entries, err := d.QueryAudit(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	entries2, err := d.QueryAudit(3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries2) != 2 {
		t.Fatalf("expected 2 entries on page 2, got %d", len(entries2))
	}
}

// AUTH-016: VerifyAuditChain recomputes the Merkle chain and detects tampering.
func TestVerifyAuditChain(t *testing.T) {
	d := newTestDB(t)

	// Empty log is not an error.
	if n, err := d.VerifyAuditChain(); err != nil {
		t.Fatalf("empty chain: %v", err)
	} else if n != 0 {
		t.Fatalf("empty chain count = %d, want 0", n)
	}

	d.LogAudit("admin", "127.0.0.1", "GET", "/api/cas", "list_cas", "a")
	d.LogAudit("admin", "127.0.0.1", "POST", "/api/certs", "issue_cert", "b")
	if n, err := d.VerifyAuditChain(); err != nil {
		t.Fatalf("intact chain: %v", err)
	} else if n != 2 {
		t.Fatalf("intact chain count = %d, want 2", n)
	}
}

func TestVerifyAuditChainDetectsTampering(t *testing.T) {
	d := newTestDB(t)
	d.LogAudit("admin", "127.0.0.1", "GET", "/api/cas", "list_cas", "original")
	d.LogAudit("admin", "127.0.0.1", "POST", "/api/certs", "issue_cert", "b")

	// Alter a stored detail out-of-band: hash must no longer match.
	if _, err := d.Exec("UPDATE audit_log SET detail = 'tampered' WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.VerifyAuditChain(); err == nil {
		t.Fatal("tampered chain should fail verification")
	}
}

func TestVerifyAuditChainDetectsDeletedRow(t *testing.T) {
	d := newTestDB(t)
	d.LogAudit("admin", "127.0.0.1", "GET", "/api/cas", "list_cas", "a")
	d.LogAudit("admin", "127.0.0.1", "POST", "/api/certs", "issue_cert", "b")

	// Deleting the middle row breaks the prev_hash link.
	if _, err := d.Exec("DELETE FROM audit_log WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.VerifyAuditChain(); err == nil {
		t.Fatal("deleted row should fail verification")
	}
}
