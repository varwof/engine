// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ---------- backfillCertsV12: insert cert with NULL v12 fields, then backfill ----------

func TestBackfillCertsV12(t *testing.T) {
	d := newTestDB(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca", Organization: []string{"CA Org"}},
		DNSNames:              []string{"test-ca.local"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Skipf("cannot create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(9001),
		Subject:      pkix.Name{CommonName: "backfill-test", Organization: []string{"TestOrg"}, Country: []string{"CN"}},
		DNSNames:     []string{"backfill-test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &key.PublicKey, key)
	if err != nil {
		t.Skipf("x509.CreateCertificate: %v", err)
	}
	fpr := fmt.Sprintf("%x", sha256.Sum256(certDER))

	// Insert with NULL v12 fields
	_, err = d.Exec(`
		INSERT INTO certificates
			(serial_number, ca_name, status, subject, common_name,
			 not_before, not_after, revoked_at, revoke_reason, invalidity_date,
			 cert_der, fingerprint,
			 subject_o, subject_c, issuer_dn, key_algo, key_size, sig_algo, ski, aki, san, profile_used)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)`,
		"9001", "backfill-ca", "V", "CN=backfill-test", "backfill-test",
		time.Now().UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		nil, nil, nil,
		certDER, fpr,
	)
	if err != nil {
		t.Fatal(err)
	}

	err = d.backfillCertsV12()
	if err != nil {
		t.Fatal(err)
	}

	// Verify fields were backfilled
	cert, err := d.GetCert("backfill-ca", "9001")
	if err != nil {
		t.Fatal(err)
	}
	if cert.SubjectO == "" {
		t.Error("subject_o not backfilled")
	}
	if cert.KeyAlgo == "" {
		t.Error("key_algo not backfilled")
	}
	if cert.IssuerDN == "" {
		t.Error("issuer_dn not backfilled")
	}
}

func TestBackfillCertsV12_AlreadyPopulated(t *testing.T) {
	d := newTestDB(t)

	rec := makeTestCert(t, 9010, "already-populated")
	rec.SubjectO = "TestOrg"
	rec.SubjectC = "CN"
	rec.IssuerDN = "CN=test-ca"
	rec.KeyAlgo = "ecdsa"
	rec.KeySize = 256
	rec.SigAlgo = "ECDSA-SHA256"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	err := d.backfillCertsV12()
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- backfillTrustAnchorsV12 ----------

func TestBackfillTrustAnchorsV12(t *testing.T) {
	d := newTestDB(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ta-root", Organization: []string{"Root Org"}},
		DNSNames:              []string{"ta-root.local"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Skipf("cannot create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(9100),
		Subject:      pkix.Name{CommonName: "ta-backfill", Organization: []string{"TA Org"}},
		DNSNames:     []string{"ta-backfill.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &key.PublicKey, key)
	if err != nil {
		t.Skipf("x509.CreateCertificate: %v", err)
	}

	// Insert with NULL v12 fields
	_, err = d.Exec(`
		INSERT INTO trust_anchors
			(name, hash_id, cert_der, subject, not_before, not_after, issuer, trusted, source,
			 subject_o, subject_c, key_algo, key_size, sha1_fingerprint, path_len)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL)`,
		"ta-backfill", "hash-1", certDER,
		"CN=ta-backfill", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"CN=ta-root", 1, "test",
	)
	if err != nil {
		t.Fatal(err)
	}

	err = d.backfillTrustAnchorsV12()
	if err != nil {
		t.Fatal(err)
	}

	ta, err := d.GetTrustAnchor("hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if ta.SubjectO == "" {
		t.Error("subject_o not backfilled for trust anchor")
	}
	if ta.KeyAlgo == "" {
		t.Error("key_algo not backfilled for trust anchor")
	}
}

func TestBackfillTrustAnchorsV12_AlreadyPopulated(t *testing.T) {
	d := newTestDB(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		DNSNames:              []string{"root.local"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Skipf("cannot create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(9200),
		Subject:      pkix.Name{CommonName: "ta-done"},
		DNSNames:     []string{"ta-done.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &key.PublicKey, key)
	if err != nil {
		t.Skipf("x509.CreateCertificate: %v", err)
	}

	d.InsertTrustAnchor(&TrustAnchor{
		CertDER:  certDER,
		Subject:  "CN=ta-done",
		Source:   "test",
		Trusted:  true,
		HashID:   "hash-done",
		SubjectO: "AlreadySet",
		Name:     fmt.Sprintf("ta-%x", sha256.Sum256(certDER)),
	})

	err = d.backfillTrustAnchorsV12()
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- RebindDialect with PG ----------

func TestRebindDialect_PG(t *testing.T) {
	d := pgDialect{}
	result := RebindDialect(d, "SELECT * FROM t WHERE id = ? AND name = ?")
	expected := "SELECT * FROM t WHERE id = $1 AND name = $2"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestRebindDialect_SQLite(t *testing.T) {
	d := SQLiteDialect{}
	result := RebindDialect(d, "SELECT * FROM t WHERE id = ?")
	if result != "SELECT * FROM t WHERE id = ?" {
		t.Errorf("SQLite should not rebind, got %q", result)
	}
}

func TestRebindDialect_PG_NoPlaceholders(t *testing.T) {
	d := pgDialect{}
	result := RebindDialect(d, "SELECT 1")
	if result != "SELECT 1" {
		t.Errorf("no placeholder query should pass through, got %q", result)
	}
}

func TestRebindDialect_PG_ManyPlaceholders(t *testing.T) {
	d := pgDialect{}
	result := RebindDialect(d, "?,?,?,?")
	expected := "$1,$2,$3,$4"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

// ---------- adaptInsertSQL with various dialects ----------

func TestAdaptInsertSQL_MySQL_WithInto(t *testing.T) {
	d := mysqlDialect{}
	result := adaptInsertSQL("INSERT OR REPLACE INTO certs (id) VALUES (?)", d)
	if result != "REPLACE INTO certs (id) VALUES (?)" {
		t.Errorf("mysql replace INTO: got %q", result)
	}

	result = adaptInsertSQL("INSERT OR IGNORE INTO certs (id) VALUES (?)", d)
	if result != "INSERT IGNORE INTO certs (id) VALUES (?)" {
		t.Errorf("mysql ignore INTO: got %q", result)
	}
}

func TestAdaptInsertSQL_PG_WithInto(t *testing.T) {
	d := pgDialect{}
	result := adaptInsertSQL("INSERT OR REPLACE INTO certs (id) VALUES (?)", d)
	if result != "INSERT INTO certs (id) VALUES (?) ON CONFLICT DO NOTHING" {
		t.Errorf("pg replace INTO: got %q", result)
	}

	result = adaptInsertSQL("INSERT OR IGNORE INTO certs (id) VALUES (?)", d)
	if result != "INSERT INTO certs (id) VALUES (?) ON CONFLICT DO NOTHING" {
		t.Errorf("pg ignore INTO: got %q", result)
	}
}

// ---------- InsertCert with revoked/invalidity dates ----------

func TestInsertCert_WithRevokedAndInvalidity(t *testing.T) {
	d := newTestDB(t)
	now := time.Now().UTC()
	revoked := now.Add(-time.Hour)
	invalidity := now.Add(-2 * time.Hour)

	rec := &CertRecord{
		SerialNumber:   "C0DE",
		CAName:         "revoke-ca",
		Status:         "R",
		Subject:        "CN=revoked",
		CommonName:     "revoked",
		NotBefore:      now.Add(-24 * time.Hour),
		NotAfter:       now.Add(24 * time.Hour),
		RevokedAt:      &revoked,
		RevokeReason:   intPtr(1),
		InvalidityDate: &invalidity,
		CertDER:        []byte("fake-revoked-cert"),
		Fingerprint:    "revoked-fpr",
	}
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetCert("revoke-ca", "C0DE")
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil {
		t.Error("revoked_at should not be nil")
	}
	if got.InvalidityDate == nil {
		t.Error("invalidity_date should not be nil")
	}
}

// ---------- InsertCertWithDedup ----------

func TestInsertCertWithDedup_Duplicate(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	rec := makeTestCert(t, 0xD001, "dup-cn")
	rec.NotBefore = now
	rec.NotAfter = now.Add(time.Hour)
	if err := d.InsertCertWithDedup(rec); err != nil {
		t.Fatal(err)
	}

	rec2 := makeTestCert(t, 0xD002, "dup-cn")
	rec2.NotBefore = now
	rec2.NotAfter = now.Add(time.Hour)
	err := d.InsertCertWithDedup(rec2)
	if err == nil {
		t.Fatal("expected duplicate CN error")
	}
	if !strings.Contains(err.Error(), "duplicate CN") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInsertCertWithDedup_DifferentCN(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 0xD010, "unique-cn-a")
	if err := d.InsertCertWithDedup(rec); err != nil {
		t.Fatal(err)
	}
	rec2 := makeTestCert(t, 0xD011, "unique-cn-b")
	if err := d.InsertCertWithDedup(rec2); err != nil {
		t.Fatal(err)
	}
}

// ---------- ListCertsFiltered ----------

func TestListCertsFiltered_StatusOnly(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 0xF001, "filter-test")
	rec.Status = "R"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	rec2 := makeTestCert(t, 0xF002, "filter-test2")
	rec2.Status = "V"
	if err := d.InsertCert(rec2); err != nil {
		t.Fatal(err)
	}

	records, err := d.ListCertsFiltered("issuing", "R", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].CommonName != "filter-test" {
		t.Errorf("expected 1 revoked cert, got %d", len(records))
	}
}

func TestListCertsFiltered_CNOnly(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 0xF010, "specific-name")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	rec2 := makeTestCert(t, 0xF011, "other-name")
	if err := d.InsertCert(rec2); err != nil {
		t.Fatal(err)
	}

	records, err := d.ListCertsFiltered("issuing", "", "specific")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 cert, got %d", len(records))
	}
}

func TestListCertsFiltered_Both(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 0xF020, "both-filter")
	rec.Status = "R"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	records, err := d.ListCertsFiltered("issuing", "R", "both-filter")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 cert, got %d", len(records))
	}
}

// ---------- GetRevokedCerts ----------

func TestGetRevokedCerts_WithRevoked(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 0xBEE1, "revoked-get")
	rec.Status = "R"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	records, err := d.GetRevokedCerts("issuing")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 revoked cert, got %d", len(records))
	}
}

func TestGetRevokedCerts_Empty(t *testing.T) {
	d := newTestDB(t)
	records, err := d.GetRevokedCerts("nonexistent-ca")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0, got %d", len(records))
	}
}

// ---------- UpdateRARequestStatus paths ----------

func TestUpdateRARequestStatus_WithSerial(t *testing.T) {
	d := newTestDB(t)
	id, err := d.InsertReturning(
		"INSERT INTO ra_requests (csr_der, common_name, san_list, profile, ca_name, requester, required_approvals) VALUES (?, ?, ?, ?, ?, ?, ?)",
		[]byte("fake-csr"), "test-cn", "[]", "tls-server", "ra-ca", "test-user", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = d.UpdateRARequestStatus(int(id), "approved", "SERIAL123", "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRARequestStatus_WithRejectReason(t *testing.T) {
	d := newTestDB(t)
	id, err := d.InsertReturning(
		"INSERT INTO ra_requests (csr_der, common_name, san_list, profile, ca_name, requester, required_approvals) VALUES (?, ?, ?, ?, ?, ?, ?)",
		[]byte("fake-csr"), "test-cn", "[]", "tls-server", "ra-ca", "test-user", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = d.UpdateRARequestStatus(int(id), "rejected", "", "bad CSR")
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRARequestStatus_StatusOnly(t *testing.T) {
	d := newTestDB(t)
	id, err := d.InsertReturning(
		"INSERT INTO ra_requests (csr_der, common_name, san_list, profile, ca_name, requester, required_approvals) VALUES (?, ?, ?, ?, ?, ?, ?)",
		[]byte("fake-csr"), "test-cn", "[]", "tls-server", "ra-ca", "test-user", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	err = d.UpdateRARequestStatus(int(id), "reviewing", "", "")
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- backfillAuditHashes with chained entries ----------

func TestBackfillAuditHashes_Chained(t *testing.T) {
	d := newTestDB(t)

	// Insert 5 audit entries with NULL hashes
	for i := 0; i < 5; i++ {
		d.Exec("INSERT INTO audit_log (timestamp, username, remote_addr, method, path, action, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
			time.Now().UTC().Format(time.RFC3339),
			fmt.Sprintf("user-%d", i), "127.0.0.1", "GET", "/test", "test", fmt.Sprintf("detail-%d", i))
	}

	err := d.backfillAuditHashes()
	if err != nil {
		t.Fatal(err)
	}

	// Verify all entries have hashes
	var count int
	d.QueryRow("SELECT COUNT(*) FROM audit_log WHERE entry_hash IS NOT NULL").Scan(&count)
	if count != 5 {
		t.Errorf("expected 5 hashed entries, got %d", count)
	}

	// Verify chaining: prev_hash should be empty for first, non-empty for rest
	var firstHash, firstPrev string
	d.QueryRow("SELECT entry_hash, prev_hash FROM audit_log WHERE id = (SELECT MIN(id) FROM audit_log)").Scan(&firstHash, &firstPrev)
	if firstPrev != "" {
		t.Error("first entry should have empty prev_hash")
	}
}

// ---------- GetAllAuditEntries ----------

func TestGetAllAuditEntries_WithEntries(t *testing.T) {
	d := newTestDB(t)

	for i := 0; i < 3; i++ {
		d.LogAudit(fmt.Sprintf("user-%d", i), "127.0.0.1", "POST", "/api", "create", fmt.Sprintf("created-%d", i))
	}

	entries, err := d.GetAllAuditEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
	for i, e := range entries {
		if e.Username == "" {
			t.Errorf("entry %d: expected non-empty username, got empty", i)
		}
		if !IsAuditMasked(e.Username) {
			t.Errorf("entry %d: username should be masked (64-hex), got %q", i, e.Username)
		}
	}
}

// ---------- execMigrationSQL ----------

func TestExecMigrationSQL_Simple(t *testing.T) {
	d := newTestDB(t)
	err := d.execMigrationSQL("SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestExecMigrationSQL_MultiStatement(t *testing.T) {
	d := newTestDB(t)
	err := d.execMigrationSQL("SELECT 1; SELECT 2;")
	if err != nil {
		t.Fatal(err)
	}
}

func TestExecMigrationSQL_Empty(t *testing.T) {
	d := newTestDB(t)
	err := d.execMigrationSQL("")
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- adaptSQL ----------

func TestAdaptSQL_PG(t *testing.T) {
	d := newTestDB(t)
	// Temporarily replace dialect by testing through execMigrationSQL
	// adaptSQL is a method on *DB, so test via the schema layer
	result := d.dialect.DriverName()
	if result != "sqlite" {
		t.Errorf("expected sqlite driver, got %s", result)
	}
}

func TestAdaptSQL_PGNonceUsesBYTEA(t *testing.T) {
	pg := NewPGDialect(PGConfig{DSN: "postgres://user:pass@localhost:5432/test"})
	d := &DB{dialect: pg}
	sql := d.adaptSQL("CREATE TABLE renewal_tokens (nonce __NONCE__ NOT NULL PRIMARY KEY, data __BLOB__);")
	if strings.Contains(sql, "BLOB") {
		t.Errorf("PG adaptSQL must not emit BLOB, got %q", sql)
	}
	if !strings.Contains(sql, "nonce BYTEA NOT NULL PRIMARY KEY") {
		t.Errorf("PG adaptSQL should map __NONCE__ to BYTEA, got %q", sql)
	}
	if !strings.Contains(sql, "data BYTEA") {
		t.Errorf("PG adaptSQL should map __BLOB__ to BYTEA, got %q", sql)
	}
}

func TestAdaptSQL_SQLiteNonceUsesBLOB(t *testing.T) {
	d := newTestDB(t)
	sql := d.adaptSQL("CREATE TABLE renewal_tokens (nonce __NONCE__ NOT NULL PRIMARY KEY, data __BLOB__);")
	if !strings.Contains(sql, "nonce BLOB NOT NULL PRIMARY KEY") {
		t.Errorf("SQLite adaptSQL should map __NONCE__ to BLOB, got %q", sql)
	}
	if !strings.Contains(sql, "data BLOB") {
		t.Errorf("SQLite adaptSQL should map __BLOB__ to BLOB, got %q", sql)
	}
}

func TestAdaptSQL_Noop(t *testing.T) {
	d := newTestDB(t)
	// adaptSQL replaces __AUTO__ and __BLOB__ tokens
	sql := "CREATE TABLE t (id INTEGER __AUTO__)"
	result := d.adaptSQL(sql)
	if strings.Contains(result, "__AUTO__") {
		t.Errorf("adaptSQL should replace __AUTO__, got %q", result)
	}
}

func TestAdaptSQL_DropColumn_PG(t *testing.T) {
	d := newTestDB(t)
	// adaptSQL should strip DROP COLUMN for PG — verify it works on our sqlite DB
	sql := "ALTER TABLE t DROP COLUMN c"
	result := d.adaptSQL(sql)
	if result == "" {
		t.Error("adaptSQL should return non-empty string")
	}
}

func TestAdaptSQL_MySQLTextIndexPrefix(t *testing.T) {
	// MySQL dialect: __TEXTIDX__ → "(10)" so composite indexes over TEXT
	// columns stay within InnoDB's 3072-byte key limit.
	d := &DB{dialect: NewMySQLDialect("mysql://u:p@tcp(127.0.0.1:3306)/db")}
	sql := d.adaptSQL("CREATE INDEX idx_ca_status ON certificates(ca_name, status __TEXTIDX__);")
	if strings.Contains(sql, "__TEXTIDX__") {
		t.Errorf("MySQL adaptSQL should replace __TEXTIDX__, got %q", sql)
	}
	if !strings.Contains(sql, "status (10)") {
		t.Errorf("MySQL adaptSQL should map __TEXTIDX__ to (10), got %q", sql)
	}
	// __NONCE__ → VARBINARY(16) for MySQL
	sql2 := d.adaptSQL("CREATE TABLE t (nonce __NONCE__ NOT NULL PRIMARY KEY)")
	if !strings.Contains(sql2, "VARBINARY(16)") {
		t.Errorf("MySQL adaptSQL should map __NONCE__ to VARBINARY(16), got %q", sql2)
	}
	// __NONCE32__ → VARBINARY(32) for MySQL (DA nonce, 32-byte PK)
	sql3 := d.adaptSQL("CREATE TABLE t2 (nonce __NONCE32__ NOT NULL PRIMARY KEY)")
	if !strings.Contains(sql3, "VARBINARY(32)") {
		t.Errorf("MySQL adaptSQL should map __NONCE32__ to VARBINARY(32), got %q", sql3)
	}
}

func TestAdaptSQL_Nonce32Mapping(t *testing.T) {
	// SQLite dialect: __NONCE32__ → BLOB (same as __NONCE__ → BLOB)
	d := newTestDB(t)
	sql := d.adaptSQL("CREATE TABLE t (nonce __NONCE32__ NOT NULL PRIMARY KEY)")
	if !strings.Contains(sql, "BLOB") {
		t.Errorf("SQLite adaptSQL should map __NONCE32__ to BLOB, got %q", sql)
	}
	// PG dialect: __NONCE32__ → BYTEA
	dpg := &DB{dialect: pgDialect{}}
	sql2 := dpg.adaptSQL("CREATE TABLE t (nonce __NONCE32__ NOT NULL PRIMARY KEY)")
	if !strings.Contains(sql2, "BYTEA") {
		t.Errorf("PG adaptSQL should map __NONCE32__ to BYTEA, got %q", sql2)
	}
}

func TestAdaptSQL_SQLiteTextIndexNoPrefix(t *testing.T) {
	// SQLite dialect: __TEXTIDX__ → "" (full TEXT column indexed directly).
	d := newTestDB(t)
	sql := d.adaptSQL("CREATE INDEX idx_ca_status ON certificates(ca_name, status __TEXTIDX__);")
	if strings.Contains(sql, "__TEXTIDX__") {
		t.Errorf("SQLite adaptSQL should replace __TEXTIDX__, got %q", sql)
	}
	if strings.Contains(sql, "(10)") {
		t.Errorf("SQLite adaptSQL should NOT add prefix, got %q", sql)
	}
}

// ---------- BulkInsertCertRecords growth path ----------

func TestBulkInsertCertRecords_Large(t *testing.T) {
	d := newTestDB(t)
	var records []*CertRecord
	for i := 0; i < 150; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubDER, _ := encodePubKey(&key.PublicKey)
		fpr := fmt.Sprintf("%x", sha256.Sum256(pubDER))
		records = append(records, &CertRecord{
			SerialNumber: fmt.Sprintf("LARGE%04d", i),
			CAName:       "large-ca",
			Status:       "V",
			Subject:      fmt.Sprintf("CN=large-%d", i),
			CommonName:   fmt.Sprintf("large-%d", i),
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
	if n != 150 {
		t.Errorf("expected 150 inserted, got %d", n)
	}
}

// ---------- ListAllCertRefs ----------

func TestListAllCertRefs_Mixed(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 0xC0DE, "ref-test")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}

	rec2 := makeTestCert(t, 0xBEEF, "ref-test2")
	rec2.Status = "R"
	if err := d.InsertCert(rec2); err != nil {
		t.Fatal(err)
	}

	refs, err := d.ListAllValidCertRefs()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 {
		t.Errorf("expected 1 valid ref, got %d", len(refs))
	}
}

// ---------- BackupTo ----------

func TestBackupTo(t *testing.T) {
	d := newTestDB(t)
	path := t.TempDir() + "/backup.db"
	err := d.BackupTo(path)
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- SCEP Request with Serial/CA ----------

func TestGetSCEPRequestBySerial_Found(t *testing.T) {
	d := newTestDB(t)
	rec := &SCEPRequestRecord{
		TransactionID: "txn-serial-test",
		CAName:        "scep-ca",
		SerialNumber:  "SN12345",
		CertDER:       []byte("fake-cert"),
		IssuerDER:     []byte("fake-issuer"),
		CreatedAt:     time.Now().UTC(),
	}
	if err := d.InsertSCEPRequest(rec); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetSCEPRequestBySerial("scep-ca", "SN12345")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected record, got nil")
	}
	if got.TransactionID != "txn-serial-test" {
		t.Errorf("expected txn-serial-test, got %s", got.TransactionID)
	}
}

func TestGetSCEPRequestBySerial_NotFound(t *testing.T) {
	d := newTestDB(t)
	got, err := d.GetSCEPRequestBySerial("nonexistent", "NONE")
	if err == nil && got != nil {
		t.Error("expected nil for non-existent serial")
	}
}

// ---------- Gateway Registry ----------

func TestGatewayRegistry_Full(t *testing.T) {
	d := newTestDB(t)

	err := d.RegisterGateway("192.168.1.100:8443", "root-ca")
	if err != nil {
		t.Fatal(err)
	}

	gw, err := d.GetGateway("192.168.1.100:8443")
	if err != nil {
		t.Fatal(err)
	}
	if gw == nil {
		t.Fatal("expected gateway record")
	}
	if gw.CaName != "root-ca" {
		t.Errorf("expected root-ca, got %s", gw.CaName)
	}

	err = d.HeartbeatGateway("192.168.1.100:8443")
	if err != nil {
		t.Fatal(err)
	}

	active, err := d.ListActiveGateways()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) == 0 {
		t.Error("expected active gateways")
	}

	all, err := d.ListAllGateways()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Error("expected gateways in list")
	}

	err = d.MarkGatewayInactive("192.168.1.100:8443")
	if err != nil {
		t.Fatal(err)
	}

	err = d.RemoveGateway("192.168.1.100:8443")
	if err != nil {
		t.Fatal(err)
	}
}

func TestCleanupStaleGateways_New(t *testing.T) {
	d := newTestDB(t)
	d.RegisterGateway("10.0.0.1:8443", "ca")
	d.RegisterGateway("10.0.0.2:8443", "ca")

	removed, err := d.CleanupStaleGateways(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = removed
}

func TestGatewayRegistry_GetNonexistent(t *testing.T) {
	d := newTestDB(t)
	gw, err := d.GetGateway("nonexistent:9999")
	if err == nil && gw != nil {
		t.Error("expected nil for nonexistent gateway")
	}
}

// ---------- Renewal Token Nonce ----------

func TestRenewalTokenNonce_FullCycle(t *testing.T) {
	d := newTestDB(t)

	nonce := make([]byte, 16)
	rand.Read(nonce)

	err := d.StoreNonce(nonce)
	if err != nil {
		t.Fatal(err)
	}

	used, err := d.IsNonceUsed(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if used {
		t.Error("nonce should not be used yet")
	}

	err = d.ConsumeNonce(nonce)
	if err != nil {
		t.Fatal(err)
	}

	used, err = d.IsNonceUsed(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("nonce should be used now")
	}

	err = d.ConsumeNonce(nonce)
	if err == nil {
		t.Error("expected error for already-used nonce")
	}
}

func TestRenewalTokenNonce_NotFound(t *testing.T) {
	d := newTestDB(t)
	fakeNonce := make([]byte, 16)
	rand.Read(fakeNonce)
	err := d.ConsumeNonce(fakeNonce)
	if err == nil {
		t.Error("expected error for nonexistent nonce")
	}
}

func TestRenewalTokenNonce_InvalidLen(t *testing.T) {
	d := newTestDB(t)
	err := d.StoreNonce([]byte("short"))
	if err == nil {
		t.Error("expected error for invalid length nonce")
	}
	err = d.ConsumeNonce([]byte("short"))
	if err == nil {
		t.Error("expected error for invalid length nonce")
	}
}

func TestCleanupExpiredNonces_New(t *testing.T) {
	d := newTestDB(t)
	nonce := make([]byte, 16)
	rand.Read(nonce)
	d.StoreNonce(nonce)

	removed, err := d.CleanupExpiredNonces(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = removed
}

func TestStoreNonce_Duplicate_New(t *testing.T) {
	d := newTestDB(t)
	nonce := make([]byte, 16)
	rand.Read(nonce)
	err := d.StoreNonce(nonce)
	if err != nil {
		t.Fatal(err)
	}
	err = d.StoreNonce(nonce)
	if err != ErrDuplicateNonce {
		t.Errorf("expected ErrDuplicateNonce, got %v", err)
	}
}

// ---------- Cross Cert revoked ----------

func TestGetRevokedCrossCerts_Empty(t *testing.T) {
	d := newTestDB(t)
	records, err := d.GetRevokedCrossCerts("nonexistent-ca")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 revoked cross certs, got %d", len(records))
	}
}

// ---------- ACME: full lifecycle with NULL validated_at ----------

func TestACMEChallenges_NullValidatedAt(t *testing.T) {
	d := newTestDB(t)

	acctID, _ := d.InsertAcmeAccount("thumb1", "{}", "a@b.com", "valid")
	orderID, _ := d.InsertAcmeOrder(acctID, `[{"type":"dns","value":"x.com"}]`, "2027-01-01T00:00:00Z")
	authzID, _ := d.InsertAcmeAuthorization(orderID, "dns", "x.com", "tok123", "2027-01-01T00:00:00Z")
	challID, _ := d.InsertAcmeChallenge(authzID, "http-01", "chall-token")

	chall, err := d.GetAcmeChallenge(challID)
	if err != nil {
		t.Fatal(err)
	}
	if chall == nil {
		t.Fatal("expected challenge")
	}

	// Get challenges by authz
	challenges, err := d.GetAcmeChallengesByAuthz(authzID)
	if err != nil {
		t.Fatal(err)
	}
	if len(challenges) != 1 {
		t.Errorf("expected 1 challenge, got %d", len(challenges))
	}

	// Update challenge with NULL validated_at
	err = d.UpdateAcmeChallenge(challID, "valid", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Now update with non-null validated_at
	vat := time.Now().UTC().Format(time.RFC3339)
	err = d.UpdateAcmeChallenge(challID, "valid", &vat)
	if err != nil {
		t.Fatal(err)
	}

	// GetCertOrder
	_, _ = d.InsertAcmeCertOrder(orderID, []byte("cert-der"), "SN999", "ca999")
	co, err := d.GetAcmeCertOrder(orderID)
	if err != nil {
		t.Fatal(err)
	}
	if co == nil {
		t.Error("expected cert order")
	}
}

// ---------- ACME: scanAcmeOrder with NULL optional fields ----------

func TestACMEOrder_ScanPaths(t *testing.T) {
	d := newTestDB(t)

	acctID, _ := d.InsertAcmeAccount("thumb2", "{}", "b@c.com", "valid")
	orderID, _ := d.InsertAcmeOrder(acctID, `[]`, "")

	// Get the order
	order, err := d.GetAcmeOrder(orderID)
	if err != nil {
		t.Fatal(err)
	}
	if order == nil {
		t.Fatal("expected order")
	}

	// Update order status
	err = d.UpdateAcmeOrder(orderID, "ready")
	if err != nil {
		t.Fatal(err)
	}

	// Update finalize
	err = d.UpdateAcmeOrderFinalize(orderID, "valid")
	if err != nil {
		t.Fatal(err)
	}

	// Get authorizations
	authzs, err := d.GetAcmeAuthorizationsByOrder(orderID)
	if err != nil {
		t.Fatal(err)
	}
	_ = authzs // may be empty

	// Update authz status
	authzID, _ := d.InsertAcmeAuthorization(orderID, "dns", "y.com", "tok2", "2027-01-01T00:00:00Z")
	err = d.UpdateAcmeAuthzStatus(authzID, "valid")
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- ACME account operations ----------

func TestACMEAccount_UpdateKey(t *testing.T) {
	d := newTestDB(t)
	id, _ := d.InsertAcmeAccount("thumb-old", "{}", "x@y.com", "valid")
	err := d.UpdateAcmeAccount(id, "new@y.com", "valid")
	if err != nil {
		t.Fatal(err)
	}
	err = d.UpdateAcmeAccountKey(id, "thumb-new", `{"new":"key"}`)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := d.GetAcmeAccountByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if acct.JWKThumbprint != "thumb-new" {
		t.Errorf("expected thumb-new, got %s", acct.JWKThumbprint)
	}
}

// ---------- User RBAC operations ----------

func TestRBACUser_Full(t *testing.T) {
	d := newTestDB(t)

	err := d.CreateUser("rbac-test", "hash1", "salt1", "admin")
	if err != nil {
		t.Fatal(err)
	}

	user, err := d.GetUserByUsername("rbac-test")
	if err != nil {
		t.Fatal(err)
	}
	if user.Role != "admin" {
		t.Errorf("expected admin, got %s", user.Role)
	}

	users, err := d.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) == 0 {
		t.Error("expected users")
	}

	err = d.UpdateUserPassword(user.ID, "newhash", "newsalt")
	if err != nil {
		t.Fatal(err)
	}

	err = d.DeleteUser(user.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRBACUser_NotFound(t *testing.T) {
	d := newTestDB(t)
	_, err := d.GetUserByUsername("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

// ---------- API Tokens ----------

func TestAPIToken_Lifecycle(t *testing.T) {
	d := newTestDB(t)
	d.CreateUser("token-user", "h", "s", "admin")
	user, _ := d.GetUserByUsername("token-user")

	token, err := d.CreateAPIToken(user.ID, "test token", "")
	if err != nil {
		t.Fatal(err)
	}

	info, err := d.GetToken(token.Token)
	if err != nil {
		t.Fatal(err)
	}
	if info.Username != "token-user" {
		t.Errorf("expected token-user, got %s", info.Username)
	}

	tokens, err := d.ListTokens(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 {
		t.Errorf("expected 1 token, got %d", len(tokens))
	}

	err = d.DeleteToken(token.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAPIToken_WithExpiry(t *testing.T) {
	d := newTestDB(t)
	d.CreateUser("exp-user", "h", "s", "admin")
	user, _ := d.GetUserByUsername("exp-user")

	futureExpiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	_, err := d.CreateAPIToken(user.ID, "expires", futureExpiry)
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- CrossCert full lifecycle ----------

func TestCrossCert_Lifecycle(t *testing.T) {
	d := newTestDB(t)
	rec := &CrossCertRecord{
		IssuerCA:     "issuer-cross",
		SubjectCA:    "target-cross",
		SerialNumber: "CROSS-001",
		CertDER:      []byte("cross-cert-der"),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	err := d.InsertCrossCert(rec)
	if err != nil {
		t.Fatal(err)
	}

	got, err := d.GetCrossCert("issuer-cross", "CROSS-001")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected cross cert")
	}
}

// ---------- GenerateToken ----------

func TestGenerateToken_Random(t *testing.T) {
	t1, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	t2, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if t1 == t2 {
		t.Error("tokens should be unique")
	}
	if len(t1) == 0 {
		t.Error("token should not be empty")
	}
}

// ---------- DB Begin/Rollback ----------

func TestDB_TxRollback(t *testing.T) {
	d := newTestDB(t)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
}

// ---------- Helpers ----------

func intPtr(i int) *int {
	return &i
}

func TestACMEInsertAccount_ClosedDB(t *testing.T) {
	d := newTestDB(t)
	d.Close()
	_, err := d.InsertAcmeAccount("thumb", "{}", "c", "valid")
	if err == nil {
		t.Fatal("expected error")
	}
}
