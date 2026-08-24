// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"
	"time"
)

// ---------- BulkInsertCertRecords / Get ----------

func TestBulkInsertCertRecords(t *testing.T) {
	d := newTestDB(t)
	var records []*CertRecord
	for i := 0; i < 100; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubDER, _ := encodePubKey(&key.PublicKey)
		fpr := fmt.Sprintf("%x", sha256.Sum256(pubDER))
		records = append(records, &CertRecord{
			SerialNumber: fmt.Sprintf("%04X", i),
			CAName:       "bulk-ca",
			Status:       "V",
			Subject:      fmt.Sprintf("CN=bulk-%d", i),
			CommonName:   fmt.Sprintf("bulk-%d", i),
			NotBefore:    time.Now().Add(-24 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			CertDER:      pubDER,
			Fingerprint:  fpr,
		})
	}
	n, err := d.BulkInsertCertRecords(records)
	if err != nil {
		t.Fatal(err)
	}
	if n != 100 {
		t.Fatalf("expected 100 inserted, got %d", n)
	}

	refs, err := d.ListAllValidCertRefs()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 100 {
		t.Fatalf("expected 100 valid refs, got %d", len(refs))
	}
}

func TestBulkInsertCertRecords_Duplicates(t *testing.T) {
	d := newTestDB(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := encodePubKey(&key.PublicKey)
	fpr := fmt.Sprintf("%x", sha256.Sum256(pubDER))

	rec := &CertRecord{
		SerialNumber: "DUP1", CAName: "dup-ca", Status: "V",
		Subject: "CN=dup", CommonName: "dup",
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		CertDER: pubDER, Fingerprint: fpr,
	}
	n1, _ := d.BulkInsertCertRecords([]*CertRecord{rec})
	n2, _ := d.BulkInsertCertRecords([]*CertRecord{rec})
	if n1 != 1 {
		t.Fatalf("first insert: expected 1, got %d", n1)
	}
	if n2 != 0 {
		t.Fatalf("second insert: expected 0 (dup), got %d", n2)
	}
}

func TestBulkInsertCertRecords_Empty(t *testing.T) {
	d := newTestDB(t)
	n, err := d.BulkInsertCertRecords([]*CertRecord{})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
}

func TestCertRecordPool_Get(t *testing.T) {
	r := CertRecordPool.Get()
	if r == nil {
		t.Fatal("expected non-nil")
	}
	if r.SerialNumber != "" {
		t.Fatal("expected empty SerialNumber")
	}
}

// ---------- ListArchivedCerts ----------

func TestListArchivedCerts_Empty(t *testing.T) {
	d := newTestDB(t)
	records, err := d.ListArchivedCerts("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0, got %d", len(records))
	}
}

func insertArchivedCert(t *testing.T, d *DB, caName, serial string) {
	t.Helper()
	now := time.Now()
	pubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := encodePubKey(&pubKey.PublicKey)
	fpr := fmt.Sprintf("%x", sha256.Sum256(pubDER))
	_, err := d.Exec(`
		INSERT INTO cert_archive (serial_number, ca_name, status, subject, common_name,
			not_before, not_after, cert_der, fingerprint,
			subject_o, subject_c, issuer_dn, key_algo, key_size, sig_algo, ski, aki, san, profile_used,
			archived_at)
		VALUES (?, ?, 'V', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serial, caName, "CN=test", "test",
		now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339),
		pubDER, fpr,
		"test-org", "US", "CN=test-ca", "ecdsa", 256, "SHA256WithECDSA", "ski1", "aki1", "",
		"", now.Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
}

func TestListArchivedCerts_WithCAFilter(t *testing.T) {
	d := newTestDB(t)

	insertArchivedCert(t, d, "ca-a", "ARCH1")
	insertArchivedCert(t, d, "ca-b", "ARCH2")

	records, err := d.ListArchivedCerts("ca-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1, got %d", len(records))
	}
	if records[0].CAName != "ca-a" {
		t.Fatalf("expected ca-a, got %q", records[0].CAName)
	}
}

func TestListArchivedCerts_WithLimit(t *testing.T) {
	d := newTestDB(t)

	for i := 0; i < 5; i++ {
		insertArchivedCert(t, d, "lim-ca", fmt.Sprintf("LIM%d", i))
	}

	records, err := d.ListArchivedCerts("", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3, got %d", len(records))
	}
}

func TestListArchivedCerts_All(t *testing.T) {
	d := newTestDB(t)

	insertArchivedCert(t, d, "ca-a", "ALL1")
	insertArchivedCert(t, d, "ca-b", "ALL2")

	records, err := d.ListArchivedCerts("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2, got %d", len(records))
	}
}

// ---------- ListAllValidCertRefs ----------

func TestListAllValidCertRefs(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()

	d.InsertCert(&CertRecord{
		SerialNumber: "VR1", CAName: "v-ca", Status: "V",
		Subject: "CN=valid1", CommonName: "valid1",
		NotBefore: now, NotAfter: now.Add(time.Hour),
		CertDER: []byte{0x01}, Fingerprint: "f1",
	})
	d.InsertCert(&CertRecord{
		SerialNumber: "VR2", CAName: "v-ca", Status: "R",
		Subject: "CN=revoked1", CommonName: "revoked1",
		NotBefore: now, NotAfter: now.Add(time.Hour),
		CertDER: []byte{0x02}, Fingerprint: "f2",
	})
	d.InsertCert(&CertRecord{
		SerialNumber: "VR3", CAName: "v-ca", Status: "V",
		Subject: "CN=valid2", CommonName: "valid2",
		NotBefore: now, NotAfter: now.Add(time.Hour),
		CertDER: []byte{0x03}, Fingerprint: "f3",
	})

	refs, err := d.ListAllValidCertRefs()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 valid refs, got %d", len(refs))
	}
}

func TestListAllValidCertRefs_Empty(t *testing.T) {
	d := newTestDB(t)
	refs, err := d.ListAllValidCertRefs()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected 0, got %d", len(refs))
	}
}

// ---------- UpdateUserCAScopes ----------

func TestUpdateUserCAScopes(t *testing.T) {
	d := newTestDB(t)
	d.CreateUser("scopeuser", "hash", "salt", "admin")
	err := d.UpdateUserCAScopes(1, "ca-a,ca-b")
	if err != nil {
		t.Fatal(err)
	}

	user, err := d.GetUserByUsername("scopeuser")
	if err != nil {
		t.Fatal(err)
	}
	if user.CAScopes != "ca-a,ca-b" {
		t.Fatalf("expected 'ca-a,ca-b', got %q", user.CAScopes)
	}
}

func TestUpdateUserCAScopes_NonExistentUser(t *testing.T) {
	d := newTestDB(t)
	err := d.UpdateUserCAScopes(99999, "ca-x")
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- backfillAuditHashes ----------

func TestBackfillAuditHashes(t *testing.T) {
	d := newTestDB(t)
	d.CreateUser("hashuser", "hash", "salt", "admin")

	d.LogAudit("hashuser", "127.0.0.1", "POST", "/api/test", "test-action", "detail-1")
	d.LogAudit("hashuser", "127.0.0.1", "POST", "/api/test", "test-action", "detail-2")
	d.LogAudit("hashuser", "127.0.0.1", "POST", "/api/test", "test-action", "detail-3")

	err := d.backfillAuditHashes()
	if err != nil {
		t.Fatal(err)
	}

	entries, _ := d.GetAllAuditEntries()
	if len(entries) < 3 {
		t.Fatalf("expected at least 3 entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.EntryHash == "" {
			t.Fatal("expected non-empty entry_hash")
		}
	}
}

func TestBackfillAuditHashes_AlreadyHashed(t *testing.T) {
	d := newTestDB(t)
	d.CreateUser("hashuser2", "hash", "salt", "admin")

	d.LogAudit("hashuser2", "127.0.0.1", "POST", "/api/test", "action", "detail")
	d.backfillAuditHashes()

	err := d.backfillAuditHashes()
	if err != nil {
		t.Fatal(err)
	}
}

func TestBackfillAuditHashes_Empty(t *testing.T) {
	d := newTestDB(t)
	err := d.backfillAuditHashes()
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- splitSQL ----------

func TestSplitSQL_Simple(t *testing.T) {
	result := splitSQL("SELECT 1; SELECT 2;")
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if result[0] != "SELECT 1" || result[1] != " SELECT 2" {
		t.Fatalf("unexpected: %v", result)
	}
}

func TestSplitSQL_NoTrailingSemicolon(t *testing.T) {
	result := splitSQL("SELECT 1; SELECT 2")
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
}

func TestSplitSQL_SingleStatement(t *testing.T) {
	result := splitSQL("SELECT 1")
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0] != "SELECT 1" {
		t.Fatalf("unexpected: %q", result[0])
	}
}

func TestSplitSQL_Empty(t *testing.T) {
	result := splitSQL("")
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}

func TestSplitSQL_QuotedString(t *testing.T) {
	result := splitSQL("SELECT 'a;b'; SELECT 2;")
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if result[0] != "SELECT 'a;b'" {
		t.Fatalf("unexpected: %q", result[0])
	}
}

func TestSplitSQL_DoubleQuoted(t *testing.T) {
	result := splitSQL(`SELECT "a;b"; SELECT 2;`)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if result[0] != `SELECT "a;b"` {
		t.Fatalf("unexpected: %q", result[0])
	}
}

func TestSplitSQL_BacktickQuoted(t *testing.T) {
	result := splitSQL("SELECT `a;b`; SELECT 2;")
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if result[0] != "SELECT `a;b`" {
		t.Fatalf("unexpected: %q", result[0])
	}
}

func TestSplitSQL_EscapedQuote(t *testing.T) {
	result := splitSQL(`SELECT 'a''b'; SELECT 2;`)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
}

func TestSplitSQL_BackslashEscape(t *testing.T) {
	result := splitSQL(`SELECT 'a\b'; SELECT 2;`)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
}

func TestSplitSQL_MultipleStatements(t *testing.T) {
	result := splitSQL("CREATE TABLE a (id INT); CREATE TABLE b (id INT); INSERT INTO a VALUES (1);")
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
}

// ---------- helpers ----------

func encodePubKey(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	return der, err
}
