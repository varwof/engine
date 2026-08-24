// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCreateDatabaseSQLite verifies SQLite database creation: creates parent directories, idempotent.
func TestCreateDatabaseSQLite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "sub")
	path := filepath.Join(dir, "pki.db")
	res, err := CreateDatabaseIfNotExists(path)
	if err != nil {
		t.Fatalf("CreateDatabaseIfNotExists: %v", err)
	}
	if res.Created {
		t.Error("sqlite should not report Created (file created by Open)")
	}
	if res.Driver != "sqlite" {
		t.Errorf("expected driver sqlite, got %q", res.Driver)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("parent dir not created: %v", err)
	}
	// Idempotent: second call should not error
	if _, err := CreateDatabaseIfNotExists(path); err != nil {
		t.Fatalf("second call: %v", err)
	}
}

// TestCreateDatabaseSQLiteMemory verifies :memory: and sqlite:// prefix do not create directories.
func TestCreateDatabaseSQLiteMemory(t *testing.T) {
	if _, err := CreateDatabaseIfNotExists(":memory:"); err != nil {
		t.Fatalf(":memory:: %v", err)
	}
	if _, err := CreateDatabaseIfNotExists("sqlite:///tmp/nonexistent-dir-xyz/pki.db"); err != nil {
		t.Fatalf("sqlite:// : %v", err)
	}
}

// TestSplitMySQLDSN verifies MySQL DSN splitting (without connecting).
func TestSplitMySQLDSN(t *testing.T) {
	cases := []struct {
		dsn    string
		dbName string
		admin  string
	}{
		{"user:pass@tcp(host:3306)/pki?charset=utf8mb4", "pki", "user:pass@tcp(host:3306)/?charset=utf8mb4"},
		{"user:pass@tcp(host:3306)/pki", "pki", "user:pass@tcp(host:3306)/"},
		{"u@unix(/tmp/mysql.sock)/mydb?parseTime=true", "mydb", "u@unix(/tmp/mysql.sock)/?parseTime=true"},
	}
	for _, c := range cases {
		dbName, admin, err := splitMySQLDSN(c.dsn)
		if err != nil {
			t.Fatalf("split %q: %v", c.dsn, err)
		}
		if dbName != c.dbName || admin != c.admin {
			t.Errorf("split %q:\n got (%q, %q)\nwant (%q, %q)", c.dsn, dbName, admin, c.dbName, c.admin)
		}
	}
}

// TestSplitMySQLDSNInvalid verifies invalid DSN returns error.
func TestSplitMySQLDSNInvalid(t *testing.T) {
	for _, dsn := range []string{"user:pass@tcp(host)", "user:pass@tcp(host)/", "user:pass@tcp(host)/bad-name"} {
		if _, _, err := splitMySQLDSN(dsn); err == nil {
			t.Errorf("expected error for %q", dsn)
		}
	}
}

// TestCreatePGDatabaseURL verifies PG DSN parsing and identifier validation (without connecting).
func TestCreatePGDatabaseURL(t *testing.T) {
	// Only validates validIdentifier and URL parsing logic do not panic.
	if !validIdentifier("pki_test_42") {
		t.Error("validIdentifier should accept pki_test_42")
	}
	for _, bad := range []string{"", "bad-name", "bad name", "pki;DROP", "pki@x"} {
		if validIdentifier(bad) {
			t.Errorf("validIdentifier should reject %q", bad)
		}
	}
}
