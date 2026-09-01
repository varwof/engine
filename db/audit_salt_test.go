// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"strings"
	"testing"
	"time"
)

func TestLoadOrCreateAuditSalt(t *testing.T) {
	d := newTestDB(t)
	s1, err := d.LoadOrCreateAuditSalt("2026-08-04")
	if err != nil {
		t.Fatalf("LoadOrCreateAuditSalt: %v", err)
	}
	if len(s1) != 64 {
		t.Fatalf("expected 64-hex salt, got %q (len=%d)", s1, len(s1))
	}
	// Same day returns identical salt.
	s2, err := d.LoadOrCreateAuditSalt("2026-08-04")
	if err != nil {
		t.Fatalf("LoadOrCreateAuditSalt again: %v", err)
	}
	if s1 != s2 {
		t.Fatal("same-day salt should be stable")
	}
	// Different day returns a different salt.
	s3, err := d.LoadOrCreateAuditSalt("2026-08-05")
	if err != nil {
		t.Fatalf("LoadOrCreateAuditSalt next day: %v", err)
	}
	if s1 == s3 {
		t.Fatal("different-day salts should differ")
	}
}

func TestMaskAuditField(t *testing.T) {
	salt := "aa" // short salt for test
	// Same (salt, value) → stable digest.
	a := MaskAuditField(salt, "alice")
	b := MaskAuditField(salt, "alice")
	if a != b || len(a) != 64 {
		t.Fatalf("expected stable 64-hex digest, got %q vs %q", a, b)
	}
	// Different values → different digests.
	c := MaskAuditField(salt, "bob")
	if a == c {
		t.Fatal("different values should produce different digests")
	}
	// Empty value stays empty (optional field omitted).
	if MaskAuditField(salt, "") != "" {
		t.Fatal("empty value should stay empty")
	}
	// Empty salt → value unchanged.
	if MaskAuditField("", "alice") != "alice" {
		t.Fatal("empty salt should leave value unchanged")
	}
}

func TestLogAuditMasking(t *testing.T) {
	d := newTestDB(t)
	SetAuditMaskEnabled(true)
	defer SetAuditMaskEnabled(true)

	if err := d.LogAudit("alice", "10.0.0.5", "GET", "/api/cas", "list", "detail"); err != nil {
		t.Fatalf("LogAudit: %v", err)
	}
	entries, err := d.GetAllAuditEntries()
	if err != nil {
		t.Fatalf("GetAllAuditEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Username == "alice" {
		t.Fatal("username should be masked, got plaintext")
	}
	if !IsAuditMasked(e.Username) {
		t.Fatalf("username should be a 64-hex HMAC digest, got %q", e.Username)
	}
	if e.RemoteAddr == "10.0.0.5" {
		t.Fatal("remote_addr should be masked, got plaintext")
	}
	if !IsAuditMasked(e.RemoteAddr) {
		t.Fatalf("remote_addr should be a 64-hex HMAC digest, got %q", e.RemoteAddr)
	}
	// Chain still verifies with the masked value.
	expected := HashAuditEntry("", e.Timestamp, e.Username, e.RemoteAddr, e.Method, e.Path, e.Action, e.Detail)
	if e.EntryHash != expected {
		t.Fatalf("chain hash mismatch: got %q want %q", e.EntryHash, expected)
	}
}

func TestLogAuditMaskingDisabled(t *testing.T) {
	d := newTestDB(t)
	SetAuditMaskEnabled(false)
	defer SetAuditMaskEnabled(true)

	if err := d.LogAudit("carol", "10.1.2.3", "GET", "/api", "act", ""); err != nil {
		t.Fatalf("LogAudit: %v", err)
	}
	entries, err := d.GetAllAuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Username != "carol" || entries[0].RemoteAddr != "10.1.2.3" {
		t.Fatalf("masking disabled should store plaintext, got %q/%q", entries[0].Username, entries[0].RemoteAddr)
	}
}

func TestRetireExpiredAuditSalts(t *testing.T) {
	d := newTestDB(t)
	// Use relative dates so the test is deterministic regardless of when it
	// runs: retention 1 day keeps yesterday, purges anything older.
	old1 := time.Now().AddDate(0, 0, -10).Format("2006-01-02")
	old2 := time.Now().AddDate(0, 0, -5).Format("2006-01-02")
	fresh := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	// Create salts for the three days (via the loader).
	if _, err := d.LoadOrCreateAuditSalt(old1); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadOrCreateAuditSalt(old2); err != nil {
		t.Fatal(err)
	}
	// retention 1 day → the two old days are purged, yesterday stays.
	if _, err := d.LoadOrCreateAuditSalt(fresh); err != nil {
		t.Fatal(err)
	}
	n, err := d.RetireExpiredAuditSalts(1)
	if err != nil {
		t.Fatalf("RetireExpiredAuditSalts: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 retired salts, got %d", n)
	}
	// Verify remaining.
	var remaining int
	if err := d.QueryRow("SELECT COUNT(*) FROM audit_salts").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("expected 1 remaining salt, got %d", remaining)
	}
}

func TestIsAuditMasked(t *testing.T) {
	if !IsAuditMasked("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("64-hex string should be detected as masked")
	}
	if IsAuditMasked("alice") {
		t.Fatal("plaintext should not be detected as masked")
	}
	if IsAuditMasked(strings.Repeat("g", 64)) {
		t.Fatal("non-hex 64-char string should not be masked")
	}
	if IsAuditMasked("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("63-char string should not be masked")
	}
}
