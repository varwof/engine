// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build postgres

package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestCreatePGDatabaseReal verifies database creation + idempotency on a real PostgreSQL instance.
// Run: go test -tags postgres -run TestCreatePGDatabaseReal ./db/
func TestCreatePGDatabaseReal(t *testing.T) {
	base := pgTestDSN(t)
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/pki_create_test_" + fmt.Sprint(os.Getpid())

	// Clean up stale test databases: use a raw connection (no migration trigger) to connect to the postgres maintenance DB.
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		t.Fatalf("open pgx admin: %v", err)
	}
	defer admin.Close()
	if _, err := admin.Exec("DROP DATABASE IF EXISTS " + strings.TrimPrefix(u.Path, "/")); err != nil {
		t.Fatalf("drop stale test db: %v", err)
	}

	// First creation → Created=true
	res, err := CreateDatabaseIfNotExists(u.String())
	if err != nil {
		t.Fatalf("CreateDatabaseIfNotExists: %v", err)
	}
	if !res.Created {
		t.Error("expected Created=true on first call")
	}
	if res.Driver != "pgx" || res.Database != "pki_create_test_"+fmt.Sprint(os.Getpid()) {
		t.Errorf("unexpected result: %+v", res)
	}

	// Second call → Created=false (idempotent)
	res, err = CreateDatabaseIfNotExists(u.String())
	if err != nil {
		t.Fatalf("CreateDatabaseIfNotExists (2nd): %v", err)
	}
	if res.Created {
		t.Error("expected Created=false on second call")
	}

	// Verify the database can be opened and migrated to the latest version
	d := openPG(t, u.String())
	if d == nil {
		t.Fatal("nil db")
	}
}
