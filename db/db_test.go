// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/test.db"
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func makeTestCert(t *testing.T, serial int64, cn string) *CertRecord {
	t.Helper()
	now := time.Now()
	rec := &CertRecord{
		SerialNumber: fmt.Sprintf("%X", serial),
		CAName:       "issuing",
		Status:       "V",
		Subject:      "CN=" + cn + ",O=test",
		CommonName:   cn,
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		CertDER:      []byte("fake-der-cert-" + cn),
	}
	rec.Fingerprint = Fingerprint(rec.CertDER)
	return rec
}

func TestGetCertStatusByIssuer(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 42, "client.example.com")
	rec.IssuerDN = "CN=Varwof Issuing CA,O=Varwof"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	// Valid cert lookup by issuer DN + serial.
	st, err := d.GetCertStatusByIssuer("CN=Varwof Issuing CA,O=Varwof", "2A")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "V" {
		t.Fatalf("expected V, got %q", st.Status)
	}

	// Unknown issuer → ErrNoRows.
	if _, err := d.GetCertStatusByIssuer("CN=Unknown,O=x", "2A"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}

	// Revoked cert → status R + RevokedAt set.
	if err := d.RevokeCert("issuing", "2A", 1); err != nil {
		t.Fatal(err)
	}
	st, err = d.GetCertStatusByIssuer("CN=Varwof Issuing CA,O=Varwof", "2A")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "R" || st.RevokedAt == nil {
		t.Fatalf("expected revoked, got status=%q revoked_at=%v", st.Status, st.RevokedAt)
	}
}

func TestGetPrincipalByCert(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 42, "client.example.com")
	rec.IssuerDN = "CN=Varwof Issuing CA,O=Varwof"
	rec.PrincipalUid = "varwof:alice:"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	// Valid AIC cert → status + principal_uid.
	status, uid, err := d.GetPrincipalByCert("CN=Varwof Issuing CA,O=Varwof", "2A")
	if err != nil {
		t.Fatal(err)
	}
	if status != "V" {
		t.Fatalf("expected V, got %q", status)
	}
	if uid != "varwof:alice:" {
		t.Fatalf("expected varwof:alice:, got %q", uid)
	}

	// Unknown issuer → ErrNoRows.
	if _, _, err := d.GetPrincipalByCert("CN=Unknown,O=x", "2A"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func TestOpenAndMigrate(t *testing.T) {
	d := newTestDB(t)
	if d == nil {
		t.Fatal("db is nil")
	}
	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM _migrations").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("migrations not applied")
	}
}

func TestInsertAndGetCert(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 1, "test.example.com")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetCert("issuing", "1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CommonName != "test.example.com" {
		t.Fatalf("expected test.example.com, got %q", got.CommonName)
	}
	if got.Status != "V" {
		t.Fatalf("expected V, got %q", got.Status)
	}
	if got.Fingerprint != rec.Fingerprint {
		t.Fatal("fingerprint mismatch")
	}
}

func TestRevokeCert(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 42, "revocable.example.com")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeCert("issuing", "ZZ", 1); err == nil {
		t.Fatal("expected error for non-existent serial")
	}

	serial := fmt.Sprintf("%X", 42)
	if err := d.RevokeCert("issuing", serial, 1); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetCert("issuing", serial)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "R" {
		t.Fatalf("expected R, got %q", got.Status)
	}
	if got.RevokedAt == nil {
		t.Fatal("revoked_at should not be nil")
	}
	if got.RevokeReason == nil || *got.RevokeReason != 1 {
		t.Fatalf("expected reason 1, got %v", got.RevokeReason)
	}
}

func TestGetRevokedCerts(t *testing.T) {
	d := newTestDB(t)
	for i := int64(1); i <= 3; i++ {
		d.InsertCert(makeTestCert(t, i, fmt.Sprintf("srv%d.test", i)))
	}
	d.RevokeCert("issuing", "1", 0)
	d.RevokeCert("issuing", "3", 1)

	revoked, err := d.GetRevokedCerts("issuing")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 2 {
		t.Fatalf("expected 2 revoked, got %d", len(revoked))
	}
}

func TestListCerts(t *testing.T) {
	d := newTestDB(t)
	for i := 1; i <= 3; i++ {
		d.InsertCert(makeTestCert(t, int64(i), fmt.Sprintf("srv%d.test", i)))
	}
	list, err := d.ListCerts("issuing")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3, got %d", len(list))
	}
}

func TestDuplicateInsert(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 1, "unique.example.com")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	if err := d.InsertCert(rec); err == nil {
		t.Fatal("expected error on duplicate insert")
	}
	list, _ := d.ListCerts("issuing")
	if len(list) != 1 {
		t.Fatalf("duplicate insert created %d records", len(list))
	}
}

func TestOpenInvalidPath(t *testing.T) {
	_, err := Open("/nonexistent/dir/db.sqlite")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestRevokeAlreadyRevoked(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 10, "double-revoke.test")
	d.InsertCert(rec)
	d.RevokeCert("issuing", "A", 0)
	err := d.RevokeCert("issuing", "A", 1)
	if err == nil {
		t.Fatal("expected error revoking already revoked cert")
	}
}

func TestFingerprint(t *testing.T) {
	h := Fingerprint([]byte("test-data"))
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}
}

func TestDBBackupTo(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 1, "backup.test")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	backupPath := t.TempDir() + "/backup.db"
	if err := d.BackupTo(backupPath); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}

	backupDB, err := Open(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backupDB.Close() })

	got, err := backupDB.GetCert("issuing", "1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CommonName != "backup.test" {
		t.Fatalf("expected backup.test, got %q", got.CommonName)
	}

	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("backup file is empty")
	}
}

func TestRawDB(t *testing.T) {
	d := newTestDB(t)
	raw := d.RawDB()
	if raw == nil {
		t.Fatal("RawDB returned nil")
	}
	if err := raw.Ping(); err != nil {
		t.Fatalf("Ping on raw DB: %v", err)
	}
}

func TestListCertsFiltered(t *testing.T) {
	d := newTestDB(t)
	for i := 1; i <= 3; i++ {
		if err := d.InsertCert(makeTestCert(t, int64(i), fmt.Sprintf("srv%d.test", i))); err != nil {
			t.Fatal(err)
		}
	}
	// Revoke the third cert
	if err := d.RevokeCert("issuing", fmt.Sprintf("%X", 3), 1); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		status string
		cn     string
		want   int
	}{
		{"all certs", "", "", 3},
		{"active only", "V", "", 2},
		{"revoked only", "R", "", 1},
		{"cn filter", "", "srv1", 1},
		{"cn filter no match", "V", "nonexistent", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.ListCertsFiltered("issuing", tt.status, tt.cn)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, len(got))
			}
		})
	}
}

func TestListCertsFilteredPage(t *testing.T) {
	d := newTestDB(t)
	for i := 1; i <= 10; i++ {
		if err := d.InsertCert(makeTestCert(t, int64(i), fmt.Sprintf("page%d.test", i))); err != nil {
			t.Fatal(err)
		}
	}

	got, err := d.ListCertsFilteredPage("issuing", "", "", 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("limit=3: expected 3, got %d", len(got))
	}

	page2, err := d.ListCertsFilteredPage("issuing", "", "", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 3 {
		t.Fatalf("offset=3: expected 3, got %d", len(page2))
	}
	if got[0].SerialNumber == page2[0].SerialNumber {
		t.Fatal("offset not applied: same first serial on both pages")
	}

	tail, err := d.ListCertsFilteredPage("issuing", "", "", 3, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 1 {
		t.Fatalf("offset=9: expected 1 (last row), got %d", len(tail))
	}

	// limit<=0 → no pagination
	all, err := d.ListCertsFilteredPage("issuing", "", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 10 {
		t.Fatalf("no limit: expected 10, got %d", len(all))
	}

	// Status filter combined with pagination
	// (test dataset has no revoked certs, status=V should return all 10)
	valid, err := d.ListCertsFilteredPage("issuing", "V", "", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(valid) != 2 {
		t.Fatalf("status=V limit=2: expected 2, got %d", len(valid))
	}
}

func TestCountCertsByCA(t *testing.T) {
	d := newTestDB(t)
	for i := 1; i <= 5; i++ {
		if err := d.InsertCert(makeTestCert(t, int64(i), fmt.Sprintf("cnt%d.test", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.RevokeCert("issuing", fmt.Sprintf("%X", 5), 1); err != nil {
		t.Fatal(err)
	}

	n, err := d.CountCertsByCA("issuing", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("count all: expected 5, got %d", n)
	}
	n, err = d.CountCertsByCA("issuing", "V")
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("count active: expected 4, got %d", n)
	}
	n, err = d.CountCertsByCA("other-ca", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("count other ca: expected 0, got %d", n)
	}
}

func TestInsertCertWithDedup(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()

	// 1. Insert a cert → success
	rec1 := makeTestCert(t, 1, "dedup.test")
	rec1.NotBefore = now
	rec1.NotAfter = now.Add(1 * time.Hour)
	if err := d.InsertCertWithDedup(rec1); err != nil {
		t.Fatalf("InsertCertWithDedup: %v", err)
	}

	// 2. Insert same serial → error ErrDuplicateSerial
	rec2 := makeTestCert(t, 1, "different.cn")
	rec2.NotBefore = now
	rec2.NotAfter = now.Add(1 * time.Hour)
	err := d.InsertCertWithDedup(rec2)
	if err == nil {
		t.Fatal("expected error for duplicate serial")
	}
	if !errors.Is(err, ErrDuplicateSerial) {
		t.Fatalf("expected ErrDuplicateSerial, got %v", err)
	}

	// 3. Insert different serial but overlapping CN → error about duplicate CN
	rec3 := makeTestCert(t, 2, "dedup.test")
	rec3.NotBefore = now
	rec3.NotAfter = now.Add(1 * time.Hour)
	err = d.InsertCertWithDedup(rec3)
	if err == nil {
		t.Fatal("expected error for duplicate CN")
	}
	if !strings.Contains(err.Error(), "duplicate CN") {
		t.Fatalf("expected duplicate CN error, got %v", err)
	}

	// 4. Insert with non-overlapping validity → success
	rec4 := makeTestCert(t, 3, "dedup.test")
	rec4.NotBefore = now.Add(2 * time.Hour)
	rec4.NotAfter = now.Add(3 * time.Hour)
	if err := d.InsertCertWithDedup(rec4); err != nil {
		t.Fatalf("InsertCertWithDedup non-overlapping: %v", err)
	}
}

func TestCheckDuplicateCN(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()

	rec := makeTestCert(t, 1, "dup.test")
	rec.NotBefore = now
	rec.NotAfter = now.Add(1 * time.Hour)
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	// Overlapping validity → error
	if err := d.CheckDuplicateCN("issuing", "dup.test", now.Add(30*time.Minute), now.Add(90*time.Minute)); err == nil {
		t.Fatal("expected error for overlapping CN")
	}

	// Non-overlapping validity → nil
	if err := d.CheckDuplicateCN("issuing", "dup.test", now.Add(2*time.Hour), now.Add(3*time.Hour)); err != nil {
		t.Fatalf("unexpected error for non-overlapping: %v", err)
	}

	// Non-existent CN → nil
	if err := d.CheckDuplicateCN("issuing", "nonexistent", now, now.Add(1*time.Hour)); err != nil {
		t.Fatalf("unexpected error for non-existent CN: %v", err)
	}
}

func TestMigrateTo(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	// Fresh DB at SchemaVersion
	ver, err := d.CurrentVersion()
	if err != nil {
		t.Fatal(err)
	}
	if ver != SchemaVersion() {
		t.Fatalf("expected version %d, got %d", SchemaVersion(), ver)
	}

	// MigrateTo(0) → roll back all
	if err := d.MigrateTo(0); err != nil {
		t.Fatalf("MigrateTo(0): %v", err)
	}
	// After full rollback, _migrations table is dropped → CurrentVersion errors
	_, err = d.CurrentVersion()
	if err == nil {
		t.Fatal("expected CurrentVersion error after full rollback")
	}

	// MigrateTo(-1) → error
	if err := d.MigrateTo(-1); err == nil {
		t.Fatal("expected error for negative version")
	}

	// MigrateTo(SchemaVersion()+1) → error (before rollback it would test the bound check)
	// After rollback, CurrentVersion itself fails, so this also returns an error.

	// Re-open to re-apply all migrations
	d.Close()
	d2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d2.Close() })

	ver2, err := d2.CurrentVersion()
	if err != nil {
		t.Fatal(err)
	}
	if ver2 != SchemaVersion() {
		t.Fatalf("expected version %d after re-open, got %d", SchemaVersion(), ver2)
	}

	// Verify beyond-max check on a healthy DB
	d3, err := Open(dir + "/test2.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d3.Close() })
	if err := d3.MigrateTo(SchemaVersion() + 1); err == nil {
		t.Fatal("expected error for version beyond max")
	}
}
