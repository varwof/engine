// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build mysql

package db

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestCreateMySQLDatabaseReal verifies database creation + idempotency on a real MariaDB/MySQL instance.
// Run: go test -tags mysql -run TestCreateMySQLDatabaseReal ./db/
func TestCreateMySQLDatabaseReal(t *testing.T) {
	baseDSN := os.Getenv("MYSQL_TEST_DSN")
	if baseDSN == "" {
		t.Skip("MYSQL_TEST_DSN not set, skipping MySQL integration test")
	}
	admin, err := sql.Open("mysql", baseDSN[:strings.Index(baseDSN, "/")+1]+"?"+baseDSN[strings.Index(baseDSN, "?")+1:])
	if err != nil {
		t.Fatalf("open mysql admin: %v", err)
	}
	defer admin.Close()
	name := fmt.Sprintf("pki_create_test_%d", os.Getpid())
	if _, err := admin.Exec("DROP DATABASE IF EXISTS " + name); err != nil {
		t.Fatalf("drop stale test db: %v", err)
	}

	dsn := baseDSN[:strings.Index(baseDSN, "/")+1] + name
	if idx := strings.Index(baseDSN, "?"); idx != -1 {
		dsn += baseDSN[idx:]
	}
	res, err := CreateDatabaseIfNotExists(dsn)
	if err != nil {
		t.Fatalf("CreateDatabaseIfNotExists: %v", err)
	}
	if !res.Created {
		t.Error("expected Created=true on first call")
	}
	if res.Driver != "mysql" || res.Database != name {
		t.Errorf("unexpected result: %+v", res)
	}

	res, err = CreateDatabaseIfNotExists(dsn)
	if err != nil {
		t.Fatalf("CreateDatabaseIfNotExists (2nd): %v", err)
	}
	if res.Created {
		t.Error("expected Created=false on second call")
	}

	// Verify the database can be opened and migrated
	d, err := OpenWithDialect("", NewMySQLDialect(dsn))
	if err != nil {
		t.Fatalf("open MySQL %s: %v", name, err)
	}
	d.Close()

	admin.Exec("DROP DATABASE IF EXISTS " + name)
}
