// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build mysql

package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mysqlAdminDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("MYSQL_TEST_DSN not set, skipping MySQL integration test")
	}
	return dsn
}

func mysqlAdmin(t *testing.T) *sql.DB {
	t.Helper()
	dsn := mysqlAdminDSN(t)
	// Strip database name to connect as admin
	admin, err := sql.Open("mysql", dsn[:strings.Index(dsn, "/")+1]+"?"+dsn[strings.Index(dsn, "?")+1:])
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	t.Cleanup(func() { admin.Close() })
	return admin
}

// freshMySQL creates a uniquely-named database and returns an opened (migrated)
// DB on it, so repeated runs never collide on leftover rows.
func freshMySQL(t *testing.T) *DB {
	t.Helper()
	admin := mysqlAdmin(t)
	baseDSN := mysqlAdminDSN(t)
	name := fmt.Sprintf("pki_mysql_t%d", os.Getpid())
	if _, err := admin.Exec("DROP DATABASE IF EXISTS " + name); err != nil {
		t.Fatalf("drop test db: %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name)
	})
	// Replace database name in DSN
	dsn := baseDSN[:strings.Index(baseDSN, "/")+1] + name
	if idx := strings.Index(baseDSN, "?"); idx != -1 {
		dsn += baseDSN[idx:]
	}
	d, err := OpenWithDialect("", NewMySQLDialect(dsn))
	if err != nil {
		t.Fatalf("open MySQL %s: %v", name, err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestMySQLConnect runs the full migrations against a real MariaDB and checks
// the resulting schema version.
func TestMySQLConnect(t *testing.T) {
	d := freshMySQL(t)
	ver, err := d.CurrentVersion()
	if err != nil {
		t.Fatalf("current version: %v", err)
	}
	t.Logf("MySQL schema version: %d/%d", ver, SchemaVersion())
	if ver != SchemaVersion() {
		t.Errorf("expected schema v%d, got v%d", SchemaVersion(), ver)
	}
}

// TestMySQLCertRoundtrip exercises insert/read/status/revoke/CRL on MariaDB,
// covering the dialect's placeholder and rebind paths end to end.
func TestMySQLCertRoundtrip(t *testing.T) {
	d := freshMySQL(t)
	rec := makeTestCert(t, 424242, "mysql-roundtrip.example.com")
	if err := d.InsertCert(rec); err != nil {
		t.Fatalf("InsertCert: %v", err)
	}

	got, err := d.GetCert("issuing", rec.SerialNumber)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if got.CAName != "issuing" || got.CommonName != "mysql-roundtrip.example.com" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	st, err := d.GetCertStatus("issuing", rec.SerialNumber)
	if err != nil {
		t.Fatalf("GetCertStatus: %v", err)
	}
	if st.Status != "V" {
		t.Fatalf("status = %q, want V", st.Status)
	}

	if err := d.RevokeCert("issuing", rec.SerialNumber, 1); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	entries, err := d.GetRevokedCertEntries("issuing")
	if err != nil {
		t.Fatalf("GetRevokedCertEntries: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.SerialNumber == rec.SerialNumber {
			found = true
		}
	}
	if !found {
		t.Fatalf("revoked entry missing for %s", rec.SerialNumber)
	}
}

// TestMySQLTransferTo transfers a SQLite source into a fresh MariaDB target,
// covering the generic transferTable path on a real MySQL driver.
func TestMySQLTransferTo(t *testing.T) {
	admin := mysqlAdmin(t)
	baseDSN := mysqlAdminDSN(t)
	targetName := "pki_mysql_transfer_test"
	if _, err := admin.Exec("DROP DATABASE IF EXISTS " + targetName); err != nil {
		t.Fatalf("drop test db: %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE " + targetName); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + targetName)
	})
	dsn := baseDSN[:strings.Index(baseDSN, "/")+1] + targetName
	if idx := strings.Index(baseDSN, "?"); idx != -1 {
		dsn += baseDSN[idx:]
	}
	target, err := OpenWithDialect("", NewMySQLDialect(dsn))
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	t.Cleanup(func() { target.Close() })

	srcPath := filepath.Join(t.TempDir(), "src.db")
	src, err := Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	rec := makeTestCert(t, 777, "mysql-transfer.example.com")
	if err := src.InsertCert(rec); err != nil {
		t.Fatalf("seed source: %v", err)
	}

	if err := TransferTo(target, srcPath); err != nil {
		t.Fatalf("TransferTo: %v", err)
	}

	var cnt int
	if err := target.QueryRow("SELECT COUNT(*) FROM certificates WHERE serial_number = ?", rec.SerialNumber).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("certificates count for %s = %d, want 1", rec.SerialNumber, cnt)
	}
}

// TestMySQLBulkInsert exercises the 999-variable chunked bulk insert path.
func TestMySQLBulkInsert(t *testing.T) {
	d := freshMySQL(t)
	const n = 2000 // > maxSQLVars/columns so it spans multiple chunks
	recs := make([]*CertRecord, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, makeTestCert(t, int64(i+1), fmt.Sprintf("bulk-%d.example.com", i)))
	}
	inserted, err := d.BulkInsertCertRecords(recs)
	if err != nil {
		t.Fatalf("BulkInsertCertRecords: %v", err)
	}
	if inserted != n {
		t.Fatalf("inserted = %d, want %d", inserted, n)
	}
}

// TestMySQLBulkStoreDANonces verifies the R1 batch DA nonce sink dialect branch
// (INSERT IGNORE multi-row) on a real MariaDB: batch store, duplicate ignore,
// and 32-byte validation.
func TestMySQLBulkStoreDANonces(t *testing.T) {
	d := freshMySQL(t)
	const n = 50
	nonces := make([][]byte, n)
	for i := range nonces {
		nonces[i] = make([]byte, 32)
		nonces[i][0] = byte(i + 1)
	}
	stored, err := d.BulkStoreDANonces(nonces)
	if err != nil {
		t.Fatalf("BulkStoreDANonces: %v", err)
	}
	if stored != n {
		t.Fatalf("stored = %d, want %d", stored, n)
	}
	for i, nc := range nonces {
		used, err := d.IsDANonceUsed(nc)
		if err != nil {
			t.Fatalf("IsDANonceUsed %d: %v", i, err)
		}
		if !used {
			t.Fatalf("nonce %d not persisted", i)
		}
	}
	// Duplicates are ignored (replay path), not an error.
	n2, err := d.BulkStoreDANonces(nonces)
	if err != nil {
		t.Fatalf("duplicate batch: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("duplicate batch stored %d, want 0", n2)
	}
	if _, err := d.BulkStoreDANonces([][]byte{make([]byte, 16)}); err == nil {
		t.Fatal("expected 32-byte validation error")
	}
}

// TestMySQLBulkRevokeCertificates verifies the R3 single-statement bulk revoke
// dialect branch (CASE UPDATE with ? placeholders) on a real MariaDB.
func TestMySQLBulkRevokeCertificates(t *testing.T) {
	d := freshMySQL(t)
	const total = 250 // spans 2 chunks
	entries := make([]RevokeBatchEntry, total)
	for i := 0; i < total; i++ {
		serial := int64(0x2000 + i)
		rec := makeTestCert(t, serial, fmt.Sprintf("mysqlbulk%d.example.com", i))
		if err := d.InsertCert(rec); err != nil {
			t.Fatal(err)
		}
		entries[i] = RevokeBatchEntry{CA: "issuing", Serial: fmt.Sprintf("%X", serial), Reason: i % 3}
	}
	n, err := d.BulkRevokeCertificates(entries)
	if err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Fatalf("revoked = %d, want %d", n, total)
	}
	for i, en := range entries {
		rec, err := d.GetCert(en.CA, en.Serial)
		if err != nil {
			t.Fatalf("get %s: %v", en.Serial, err)
		}
		if rec.Status != "R" {
			t.Fatalf("serial %s status = %s, want R", en.Serial, rec.Status)
		}
		if rec.RevokeReason == nil || *rec.RevokeReason != i%3 {
			t.Fatalf("serial %s reason = %v, want %d", en.Serial, rec.RevokeReason, i%3)
		}
	}
	// Idempotent re-run.
	n2, err := d.BulkRevokeCertificates(entries)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("re-run revoked %d, want 0", n2)
	}
}
