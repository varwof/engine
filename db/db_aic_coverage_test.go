// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ---- aic.go coverage ----

func makeAICExtension(t *testing.T, caName, serial, agentID string) *AICExtension {
	t.Helper()
	capJSON := `[{"scheme_id":"mysql-v1","capability_id":"mysql-exec"}]`
	daJSON := `{"reason":"ROTATION"}`
	return &AICExtension{
		CAName:             caName,
		SerialNumber:       serial,
		AgentID:            agentID,
		PrincipalUID:       "varwof:user@example.com:abc",
		CapabilitiesJSON:   capJSON,
		DelegationAuthJSON: &daJSON,
		AICJSON:            `{"version":1}`,
	}
}

func TestAICExtensionCRUD(t *testing.T) {
	d := newTestDB(t)
	a := makeAICExtension(t, "issuing", "ABC", "agent-1")

	// Insert + Get by cert
	if err := d.InsertAICExtension(a); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := d.GetAICExtensionByCert("issuing", "ABC")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AgentID != "agent-1" || got.PrincipalUID != "varwof:user@example.com:abc" {
		t.Fatalf("got: %+v", got)
	}
	if got.DelegationAuthJSON == nil || *got.DelegationAuthJSON != `{"reason":"ROTATION"}` {
		t.Fatalf("delegation auth: %+v", got.DelegationAuthJSON)
	}

	// Get nonexistent → ErrNoRows
	if _, err := d.GetAICExtensionByCert("issuing", "ZZZ"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}

	// List (with + without caName filter)
	list, err := d.ListAICExtensions("", 0, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("list all: %v %d", err, len(list))
	}
	list, err = d.ListAICExtensions("issuing", 10, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("list filtered: %v %d", err, len(list))
	}
	list, err = d.ListAICExtensions("other", 10, 0)
	if err != nil || len(list) != 0 {
		t.Fatalf("list other ca: %v %d", err, len(list))
	}

	// Searches
	if got, err := d.SearchAICByAgentID("agent-1", 0, 0); err != nil || len(got) != 1 {
		t.Fatalf("search agent: %v %d", err, len(got))
	}
	if got, err := d.SearchAICByPrincipalUID("varwof:user@example.com:abc", 0, 0); err != nil || len(got) != 1 {
		t.Fatalf("search principal: %v %d", err, len(got))
	}
	if got, err := d.SearchAICByCapability("mysql-v1", 0, 0); err != nil || len(got) != 1 {
		t.Fatalf("search capability: %v %d", err, len(got))
	}
	if got, err := d.SearchAICByCapability("nonexistent-scheme", 0, 0); err != nil || len(got) != 0 {
		t.Fatalf("search missing capability: %v %d", err, len(got))
	}

	// Count
	if n, err := d.CountAICExtensions(""); err != nil || n != 1 {
		t.Fatalf("count all: %d %v", n, err)
	}
	if n, err := d.CountAICExtensions("issuing"); err != nil || n != 1 {
		t.Fatalf("count filtered: %d %v", n, err)
	}
	if n, err := d.CountAICExtensions("other"); err != nil || n != 0 {
		t.Fatalf("count other: %d %v", n, err)
	}

	// Update
	upd := makeAICExtension(t, "issuing", "ABC", "agent-1-updated")
	if err := d.UpdateAICExtension(upd); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = d.GetAICExtensionByCert("issuing", "ABC")
	if got.AgentID != "agent-1-updated" {
		t.Fatalf("after update: %+v", got)
	}

	// Delete
	if err := d.DeleteAICExtension("issuing", "ABC"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n, _ := d.CountAICExtensions(""); n != 0 {
		t.Fatalf("after delete count: %d", n)
	}
}

func TestBackfillAICExtensionsFromRefs(t *testing.T) {
	d := newTestDB(t)
	daJSON := `{"reason":"test"}`
	refs := []AICBackfillRef{
		{CAName: "issuing", Serial: "A1", AgentID: "a-1", PrincipalUID: "p-1", CapabilitiesJSON: `[]`, AICJSON: `{}`},
		{CAName: "issuing", Serial: "A2", AgentID: "a-2", PrincipalUID: "p-2", CapabilitiesJSON: `[]`, DelegationAuthJSON: &daJSON, AICJSON: `{}`},
	}
	n, err := d.BackfillAICExtensionsFromRefs(refs)
	if err != nil || n != 2 {
		t.Fatalf("backfill: %d %v", n, err)
	}
	// Already existing entries are skipped
	n, err = d.BackfillAICExtensionsFromRefs(refs)
	if err != nil || n != 0 {
		t.Fatalf("backfill duplicate: %d %v", n, err)
	}
	// Entries without delegationAuth JSON are not backfilled (in normal scenarios None is treated as already existing or re-inserted)
	if got, err := d.SearchAICByAgentID("a-2", 0, 0); err != nil || len(got) != 1 {
		t.Fatalf("search a-2: %v %d", err, len(got))
	}
}

func TestListValidAICCertRefs(t *testing.T) {
	d := newTestDB(t)
	// Insert two agent-proxy certificates: one V (valid), one R (revoked)
	valid := makeTestCert(t, 100, "agent-valid")
	valid.Profile = "agent-proxy"
	valid.PrincipalUid = "varwof:u:1"
	if err := d.InsertCert(valid); err != nil {
		t.Fatal(err)
	}
	revoked := makeTestCert(t, 101, "agent-revoked")
	revoked.Profile = "agent-proxy"
	if err := d.InsertCert(revoked); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeCert("issuing", "65", 1); err != nil {
		t.Fatal(err)
	}
	refs, err := d.ListValidAICCertRefs()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Serial != "64" {
		t.Fatalf("expected 1 valid ref (serial 64), got %+v", refs)
	}
}

// ---- certs.go uncovered functions ----

func TestGetCertStatus(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 42, "status.example.com")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	st, err := d.GetCertStatus("issuing", "2A")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "V" {
		t.Fatalf("status: %q", st.Status)
	}

	// Already revoked → RevokedAt is non-nil
	if err := d.RevokeCert("issuing", "2A", 3); err != nil {
		t.Fatal(err)
	}
	st, err = d.GetCertStatus("issuing", "2A")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "R" || st.RevokedAt == nil {
		t.Fatalf("revoked: %+v", st)
	}

	// Not found → ErrNoRows
	if _, err := d.GetCertStatus("issuing", "NOPE"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func TestGetRevokedCertEntries(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 42, "revoked.example.com")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeCert("issuing", "2A", 1); err != nil {
		t.Fatal(err)
	}
	entries, err := d.GetRevokedCertEntries("issuing")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].SerialNumber != "2A" {
		t.Fatalf("entries: %+v", entries)
	}
	// Other CA → empty
	if entries, err := d.GetRevokedCertEntries("other"); err != nil || len(entries) != 0 {
		t.Fatalf("other ca: %v %d", err, len(entries))
	}
}

func TestGetRevokedCertEntriesSince(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 42, "delta.example.com")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeCert("issuing", "2A", 1); err != nil {
		t.Fatal(err)
	}

	// since = now+1h → excludes all (revocation happened before this point)
	future := time.Now().Add(time.Hour)
	entries, err := d.GetRevokedCertEntriesSince("issuing", future)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("future since: expected 0, got %d", len(entries))
	}

	// since = 1 hour ago → includes this revocation
	past := time.Now().Add(-time.Hour)
	entries, err = d.GetRevokedCertEntriesSince("issuing", past)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].SerialNumber != "2A" {
		t.Fatalf("past since: %+v", entries)
	}
}

func TestGetCertBySPKIHash(t *testing.T) {
	d := newTestDB(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(key *ecdsa.PrivateKey, serial int64, status string) *CertRecord {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			SubjectKeyId: []byte{1, 2, 3},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		h, err := SPKIHash(cert)
		if err != nil {
			t.Fatal(err)
		}
		rec := makeTestCert(t, serial, fmt.Sprintf("spki-%d", serial))
		rec.SPKIHash = h
		rec.Status = status
		rec.CertDER = der
		return rec
	}

	rec1 := mk(key, 200, "V")
	if err := d.InsertCert(rec1); err != nil {
		t.Fatal(err)
	}
	rec2 := mk(key2, 201, "V")
	if err := d.InsertCert(rec2); err != nil {
		t.Fatal(err)
	}

	// Query by hash (no filter)
	got, err := d.GetCertBySPKIHash(rec1.SPKIHash, "", "")
	if err != nil || len(got) != 1 {
		t.Fatalf("by hash: %v %d", err, len(got))
	}
	// CA filter
	got, err = d.GetCertBySPKIHash(rec1.SPKIHash, "issuing", "")
	if err != nil || len(got) != 1 {
		t.Fatalf("by hash+ca: %v %d", err, len(got))
	}
	got, err = d.GetCertBySPKIHash(rec1.SPKIHash, "other", "")
	if err != nil || len(got) != 0 {
		t.Fatalf("by hash+wrong ca: %v %d", err, len(got))
	}
	// Status filter
	got, err = d.GetCertBySPKIHash(rec1.SPKIHash, "", "R")
	if err != nil || len(got) != 0 {
		t.Fatalf("by hash+status: %v %d", err, len(got))
	}
	// Not found
	got, err = d.GetCertBySPKIHash("deadbeef", "", "")
	if err != nil || len(got) != 0 {
		t.Fatalf("by missing hash: %v %d", err, len(got))
	}
}

func TestSPKIHash(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	h, err := SPKIHash(cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 64 {
		t.Fatalf("hash len: %d", len(h))
	}
}

func TestRevokeCertsByPrincipalUid(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 300, "principal-cert")
	rec.PrincipalUid = "varwof:alice:abc"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	other := makeTestCert(t, 301, "other-cert")
	other.PrincipalUid = "varwof:bob:def"
	if err := d.InsertCert(other); err != nil {
		t.Fatal(err)
	}

	n, err := d.RevokeCertsByPrincipalUid("varwof:alice:abc", 5)
	if err != nil || n != 1 {
		t.Fatalf("revoke principal: %d %v", n, err)
	}
	// All revoked → 0
	n, err = d.RevokeCertsByPrincipalUid("varwof:alice:abc", 5)
	if err != nil || n != 0 {
		t.Fatalf("revoke again: %d %v", n, err)
	}
	// Not found → 0
	n, err = d.RevokeCertsByPrincipalUid("varwof:nobody:xyz", 5)
	if err != nil || n != 0 {
		t.Fatalf("revoke nobody: %d %v", n, err)
	}
	// bob is unaffected
	st, _ := d.GetCertStatus("issuing", "12D")
	if st.Status != "V" {
		t.Fatalf("bob should be valid, got %q", st.Status)
	}
}

func TestRevokeCertsBySubCA(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 400, "subca-cert")
	rec.CAName = "business-ca"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	other := makeTestCert(t, 401, "other-cert")
	if err := d.InsertCert(other); err != nil {
		t.Fatal(err)
	}

	n, err := d.RevokeCertsBySubCA("business-ca", 2)
	if err != nil || n != 1 {
		t.Fatalf("revoke subca: %d %v", n, err)
	}
	n, err = d.RevokeCertsBySubCA("business-ca", 2)
	if err != nil || n != 0 {
		t.Fatalf("revoke subca again: %d %v", n, err)
	}
	st, _ := d.GetCertStatus("issuing", "191")
	if st.Status != "V" {
		t.Fatalf("issuing cert should be valid, got %q", st.Status)
	}
}

// ---- audit_salt.go ----

func TestParseAuditSaltDay(t *testing.T) {
	// 64 hex characters → treated as already masked, returns ""
	raw := strings.Repeat("ab", 32)
	if got := ParseAuditSaltDay(raw); got != "" {
		t.Fatalf("64-hex: %q", got)
	}
	// Non-64 length → ""
	if got := ParseAuditSaltDay("2026-08-05"); got != "" {
		t.Fatalf("plaintext: %q", got)
	}
}

// ---- dialect helpers exercised via Rebind / DSN builders ----

func TestPGDialectPlaceholder(t *testing.T) {
	var p pgDialect
	if got := p.Placeholder(0); got != "$1" {
		t.Fatalf("placeholder: %s", got)
	}
	if got := p.InsertOrReplace("t", "a,b", "?,?"); !strings.Contains(got, "ON CONFLICT ON CONSTRAINT t_pkey") {
		t.Fatalf("insert or replace: %s", got)
	}
	if got := p.InsertOrIgnore("t", "a", "?"); !strings.Contains(got, "ON CONFLICT DO NOTHING") {
		t.Fatalf("insert or ignore: %s", got)
	}
	if p.SupportsColumnDrop() {
		t.Fatal("pg should not support column drop")
	}
	if p.BoolInt(true) != 1 || p.BoolInt(false) != 0 {
		t.Fatal("BoolInt")
	}
	if p.NowExpr() != "NOW()" || p.AutoIncrement() != "SERIAL PRIMARY KEY" || p.BlobType() != "BYTEA" {
		t.Fatal("pg constants")
	}
}

func TestMySQLDialect(t *testing.T) {
	var m mysqlDialect
	if m.DriverName() != "mysql" {
		t.Fatalf("driver: %s", m.DriverName())
	}
	if got := m.Placeholder(3); got != "?" {
		t.Fatalf("placeholder: %s", got)
	}
	if !m.SupportsColumnDrop() {
		t.Fatal("mysql should support column drop")
	}
	if got := m.InsertOrReplace("t", "a,b", "?,?"); !strings.Contains(got, "ON DUPLICATE KEY UPDATE") {
		t.Fatalf("insert or replace: %s", got)
	}
	if got := m.InsertOrIgnore("t", "a", "?"); !strings.Contains(got, "INSERT IGNORE") {
		t.Fatalf("insert or ignore: %s", got)
	}
	if m.BoolInt(true) != 1 {
		t.Fatal("BoolInt")
	}
}

func TestPGDSNBuilder(t *testing.T) {
	var p pgDialect
	dsn := p.DSNOld(&PGConfig{
		Host:     "db.example.com",
		Port:     5432,
		User:     "pki",
		Password: "secret",
		DBName:   "pki",
		SSLMode:  "require",
	})
	if !strings.Contains(dsn, "host=db.example.com") || !strings.Contains(dsn, "port=5432") ||
		!strings.Contains(dsn, "sslmode=require") {
		t.Fatalf("dsn: %s", dsn)
	}
	// No SSLMode → disable
	dsn = p.DSNOld(&PGConfig{Host: "h", Port: 1, User: "u", DBName: "d"})
	if !strings.Contains(dsn, "sslmode=disable") {
		t.Fatalf("dsn default ssl: %s", dsn)
	}
	// Existing DSN → return directly
	dsn = p.DSNOld(&PGConfig{DSN: "prebuilt-dsn"})
	if dsn != "prebuilt-dsn" {
		t.Fatalf("dsn passthrough: %s", dsn)
	}
}

func TestNewPGDialectWithConfig(t *testing.T) {
	cfg := PGConfig{DSN: "custom-pg-dsn"}
	d := NewPGDialect(cfg)
	if d.DriverName() != "pgx" {
		t.Fatalf("driver: %s", d.DriverName())
	}
	if got := d.DSN(); got != "custom-pg-dsn" {
		t.Fatalf("dsn: %s", got)
	}
	// No DSN → assemble
	cfg2 := PGConfig{Host: "h", Port: 5432, User: "u", Password: "pw", DBName: "db", SSLMode: "verify-full"}
	d2 := NewPGDialect(cfg2)
	dsn := d2.DSN()
	if !strings.Contains(dsn, "password=pw") || !strings.Contains(dsn, "sslmode=verify-full") {
		t.Fatalf("dsn2: %s", dsn)
	}
	if d2.OpenSuffix() != "" {
		t.Fatalf("open suffix: %s", d2.OpenSuffix())
	}
}

func TestNewMySQLDialectWithConfig(t *testing.T) {
	d := NewMySQLDialect("user:pw@tcp(host:3306)/db?parseTime=true")
	if d.DSN() != "user:pw@tcp(host:3306)/db?parseTime=true" {
		t.Fatalf("dsn: %s", d.DSN())
	}
}

// ---- certs.go: ListCertsByPrincipalUid / AIC backfill fields ----

func TestListCertsByPrincipalUid(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 500, "puid-cert")
	rec.PrincipalUid = "varwof:alice:abc"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	rec2 := makeTestCert(t, 501, "puid-cert-2")
	rec2.PrincipalUid = "varwof:alice:abc"
	if err := d.InsertCert(rec2); err != nil {
		t.Fatal(err)
	}
	other := makeTestCert(t, 502, "puid-other")
	other.PrincipalUid = "varwof:bob:def"
	if err := d.InsertCert(other); err != nil {
		t.Fatal(err)
	}

	// All entries
	got, err := d.ListCertsByPrincipalUid("varwof:alice:abc", "")
	if err != nil || len(got) != 2 {
		t.Fatalf("list all: %v %d", err, len(got))
	}
	// With status filter
	got, err = d.ListCertsByPrincipalUid("varwof:alice:abc", "R")
	if err != nil || len(got) != 0 {
		t.Fatalf("list status R: %v %d", err, len(got))
	}
	// Not found
	got, err = d.ListCertsByPrincipalUid("varwof:nobody:xyz", "")
	if err != nil || len(got) != 0 {
		t.Fatalf("list nobody: %v %d", err, len(got))
	}
}

func TestBackfillAICFieldsFromDer(t *testing.T) {
	d := newTestDB(t)
	rec := makeTestCert(t, 600, "backfill-cert")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	if err := d.BackfillAICFieldsFromDer("issuing", "258", "varwof:alice:abc", "agent-99"); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetCert("issuing", "258")
	if err != nil {
		t.Fatal(err)
	}
	if got.PrincipalUid != "varwof:alice:abc" || got.AgentId != "agent-99" {
		t.Fatalf("backfilled: %+v", got)
	}
}

func TestListCertsNeedingAICBackfill(t *testing.T) {
	d := newTestDB(t)
	// agent-proxy certificate without principal_uid → needs backfill
	rec := makeTestCert(t, 700, "agent-proxy-cert")
	rec.Profile = "agent-proxy"
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	// Plain certificate, not involved
	plain := makeTestCert(t, 701, "plain-cert")
	if err := d.InsertCert(plain); err != nil {
		t.Fatal(err)
	}
	// Agent-proxy that already has principal_uid does not need backfill
	filled := makeTestCert(t, 702, "filled-agent-cert")
	filled.Profile = "agent-proxy"
	filled.PrincipalUid = "varwof:alice:abc"
	if err := d.InsertCert(filled); err != nil {
		t.Fatal(err)
	}

	rows, err := d.ListCertsNeedingAICBackfill()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Serial != "2BC" {
		t.Fatalf("expected 1 backfill row (serial 2BC), got %+v", rows)
	}
}

// ---- db.go / dialect.go extra coverage ----

func TestCheckpointWAL(t *testing.T) {
	d := newTestDB(t)
	d.CheckpointWAL() // sqlite → executes PRAGMA, no panic
}

func TestSQLiteDialectBase(t *testing.T) {
	var s SQLiteDialect
	if s.DriverName() != "sqlite" || s.DSN() != "" {
		t.Fatalf("sqlite dialect")
	}
	if !strings.Contains(s.OpenSuffix(), "journal_mode(WAL)") {
		t.Fatalf("suffix: %s", s.OpenSuffix())
	}
	if s.NowExpr() == "" || s.AutoIncrement() == "" || s.BlobType() == "" {
		t.Fatal("sqlite constants")
	}
	if s.EnableFKs() == "" {
		t.Fatal("sqlite FKs")
	}
	if s.VacuumInto("/tmp/x.db") == "" {
		t.Fatal("sqlite vacuum")
	}
	if s.Placeholder(5) != "?" || !s.SupportsColumnDrop() {
		t.Fatal("sqlite misc")
	}
}

func TestPgDialectBase(t *testing.T) {
	var p pgDialect
	if p.DSN() != "" {
		t.Fatalf("pg base dsn should be empty, got %s", p.DSN())
	}
	if p.OpenSuffix() != "?sslmode=disable" {
		t.Fatalf("pg suffix: %s", p.OpenSuffix())
	}
	if p.VacuumInto("/tmp/x") != "" {
		t.Fatal("pg vacuum should be empty")
	}
	if p.EnableFKs() != "" {
		t.Fatal("pg fks")
	}
	if !strings.Contains(p.InsertOrReplace("t", "a,b", "?,?"), "EXCLUDED.b") {
		t.Fatal("pg conflict set")
	}
	if !strings.Contains(p.InsertOrIgnore("t", "a", "?"), "DO NOTHING") {
		t.Fatal("pg insert ignore")
	}
}

func TestMySQLDialectBase(t *testing.T) {
	var m mysqlDialect
	if m.DSN() != "" {
		t.Fatalf("mysql base dsn should be empty, got %s", m.DSN())
	}
	if m.OpenSuffix() != "?charset=utf8mb4&parseTime=true" {
		t.Fatalf("mysql suffix: %s", m.OpenSuffix())
	}
	if m.VacuumInto("/tmp/x") != "" {
		t.Fatal("mysql vacuum should be empty")
	}
	if m.NowExpr() == "" || m.AutoIncrement() == "" || m.BlobType() == "" || m.EnableFKs() != "" {
		t.Fatal("mysql constants")
	}
	if !strings.Contains(m.InsertOrReplace("t", "a,b", "?,?"), "ON DUPLICATE KEY UPDATE") {
		t.Fatal("mysql insert or replace")
	}
}

func TestSplitJoinCSV(t *testing.T) {
	cols := splitCSV(" a,  b,c ")
	if len(cols) != 3 || cols[0] != "a" || cols[1] != "b" || cols[2] != "c" {
		t.Fatalf("split: %v", cols)
	}
	joined := joinCSV([]string{"a", "b"})
	if joined != "a, b" {
		t.Fatalf("join: %q", joined)
	}
	_ = mysqlConflictSet("a,b")
	_ = conflictSet("a,b")
}

// ---- rbac.go: DeleteTokenByHash ----

func TestDeleteTokenByHash(t *testing.T) {
	d := newTestDB(t)
	if err := d.CreateUser("alice", "hash", "salt", "admin"); err != nil {
		t.Fatal(err)
	}
	user, err := d.GetUserByUsername("alice")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := d.CreateAPIToken(user.ID, "test-token", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteTokenByHash(TokenHash(tok.Token)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetToken(tok.Token); err == nil {
		t.Fatal("token should be deleted")
	}
}

// ---- schema.go: migrateRange ----

func TestMigrateRangeForward(t *testing.T) {
	// With a single consolidated v1 migration, migrateRange(1, 1) is a no-op on a
	// DB that already applied v1; verify the full schema via the normal Open path.
	dir := t.TempDir()
	path := dir + "/mr.db"
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	cur, err := d.CurrentVersion()
	if err != nil || cur != SchemaVersion() {
		t.Fatalf("version: %d %v", cur, err)
	}
	if err := d.migrateRange(1, SchemaVersion()); err != nil {
		t.Fatalf("migrateRange: %v", err)
	}
	// aic_extensions table should exist after migration
	if err := d.InsertAICExtension(makeAICExtension(t, "issuing", "AFTER", "agent-x")); err != nil {
		t.Fatalf("insert after migrate: %v", err)
	}
}

// ---- sub_ca.go ----

func TestSubCA(t *testing.T) {
	d := newTestDB(t)
	sub := &SubCAMeta{
		Name:         "business-ca",
		ParentCA:     "issuing",
		CertDER:      []byte("der"),
		KeyEncrypted: nil,
		Subject:      "CN=business-ca",
		NotBefore:    "2026-01-01",
		NotAfter:     "2036-01-01",
		KeyAlgorithm: "ECDSA",
		Fingerprint:  "abc123",
		Status:       "active",
		Protocol:     "est",
		KeyUsage:     "digitalSignature",
		MaxPathLen:   1,
	}
	if err := d.InsertSubCA(sub); err != nil {
		t.Fatal(err)
	}
	// KeyEncrypted nil → stored as empty
	got, err := d.GetSubCA("business-ca")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "business-ca" || got.ParentCA != "issuing" || len(got.KeyEncrypted) != 0 {
		t.Fatalf("got: %+v", got)
	}
	// Not found
	if _, err := d.GetSubCA("nope"); err == nil {
		t.Fatal("expected error for missing sub-ca")
	}
	// ListSubCAs (with/without protocol filter)
	list, err := d.ListSubCAs("")
	if err != nil || len(list) != 1 {
		t.Fatalf("list all: %v %d", err, len(list))
	}
	list, err = d.ListSubCAs("est")
	if err != nil || len(list) != 1 {
		t.Fatalf("list est: %v %d", err, len(list))
	}
	list, err = d.ListSubCAs("scep")
	if err != nil || len(list) != 0 {
		t.Fatalf("list scep: %v %d", err, len(list))
	}
	// RevokeSubCA
	if err := d.RevokeSubCA("business-ca", 1, "2026-08-08"); err != nil {
		t.Fatal(err)
	}
	got, _ = d.GetSubCA("business-ca")
	if got.Status != "revoked" || got.RevokedAt == nil || got.RevokeReason == nil || *got.RevokeReason != 1 {
		t.Fatalf("after revoke: %+v", got)
	}
	// DeleteSubCA
	if err := d.DeleteSubCA("business-ca"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetSubCA("business-ca"); err == nil {
		t.Fatal("sub-ca should be deleted")
	}
}

// ---- transfer.go ----

func TestTransferTo(t *testing.T) {
	target := newTestDB(t)
	// Source DB: separate sqlite file, insert one certificate
	dir := t.TempDir()
	srcPath := dir + "/src.db"
	src, err := Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	srcRec := makeTestCert(t, 1000, "transfer-cert")
	srcRec.CAName = "transfer-ca"
	if err := src.InsertCert(srcRec); err != nil {
		t.Fatal(err)
	}

	if err := TransferTo(target, srcPath); err != nil {
		t.Fatalf("transfer: %v", err)
	}

	got, err := target.GetCert("transfer-ca", "3E8")
	if err != nil {
		t.Fatalf("get transferred cert: %v", err)
	}
	if got.CommonName != "transfer-cert" {
		t.Fatalf("got: %+v", got)
	}
}

func TestSQLiteColumnTypes(t *testing.T) {
	d := newTestDB(t)
	types := sqliteColumnTypes(d, "certificates")
	if len(types) == 0 {
		t.Fatal("no column types")
	}
	// cert_der is BLOB
	var foundBlob, foundText bool
	for _, ty := range types {
		if ty == "BLOB" {
			foundBlob = true
		}
		if ty == "TEXT" {
			foundText = true
		}
	}
	if !foundBlob || !foundText {
		t.Fatalf("types: %v", types)
	}
	// Table does not exist → nil
	if types := sqliteColumnTypes(d, "no_such_table"); types != nil {
		t.Fatalf("expected nil, got %v", types)
	}
}

// ---- lock.go ----

func TestNewDistLockSQLite(t *testing.T) {
	d := newTestDB(t)
	lock := d.NewDistLock()
	if err := lock.Lock(t.Context(), 42); err != nil {
		t.Fatal(err)
	}
	if ok, err := lock.TryLock(t.Context(), 43); err != nil || !ok {
		t.Fatalf("trylock: %v %v", ok, err)
	}
	if err := lock.Unlock(42); err != nil {
		t.Fatal(err)
	}
	// noopLock path: reentrant + release
	if err := lock.Unlock(99); err != nil {
		t.Fatal(err)
	}
}

func TestNewDistLockMySQL(t *testing.T) {
	// Dialect dispatch is tested without a live server: NewDistLock only
	// switches on the dialect type and must never open a connection.
	d := &DB{dialect: mysqlDialect{}}
	lock := d.NewDistLock()
	ml, ok := lock.(*mysqlAdvisoryLock)
	if !ok {
		t.Fatalf("expected *mysqlAdvisoryLock for mysql dialect, got %T", lock)
	}
	if got := ml.lockName(42); got != "varwof:core:42" {
		t.Fatalf("unexpected lock name: %s", got)
	}
	// GET_LOCK is session-scoped, so the advisory lock must never be shared
	// with a DB connection from the pool (which would release it prematurely).
	if ml.d == nil {
		t.Fatal("mysqlAdvisoryLock must reference the DB for Conn()")
	}
}

func TestPGAdvisoryLockStruct(t *testing.T) {
	d := newTestDB(t)
	l := newPGAdvisoryLock(d)
	// Directly manipulate held map to test reentrant logic
	l.held[7] = 2
	if err := l.Lock(t.Context(), 7); err != nil {
		t.Fatalf("reentrant lock: %v", err)
	}
	if ok, err := l.TryLock(t.Context(), 7); err != nil || !ok {
		t.Fatalf("reentrant trylock: %v %v", ok, err)
	}
	if err := l.Unlock(7); err != nil {
		t.Fatalf("unlock (n=3): %v", err)
	}
	if l.held[7] != 3 {
		t.Fatalf("refcount: %v", l.held)
	}
	// Unlock without holding lock → sqlite error (covers pg_advisory_unlock path)
	_ = l.Unlock(999)
}

// Prevent unused import
var _ = json.Marshal

func TestRevokeCertsBatchDB(t *testing.T) {
	d := newTestDB(t)
	for i := int64(1); i <= 4; i++ {
		rec := makeTestCert(t, 100+i, fmt.Sprintf("rb%d.example.com", i))
		if err := d.InsertCert(rec); err != nil {
			t.Fatal(err)
		}
	}

	entries := []RevokeBatchEntry{
		{CA: "issuing", Serial: "65", Reason: 5},       // 101 in hex = 0x65
		{CA: "issuing", Serial: "67", Reason: 5},       // 103
		{CA: "issuing", Serial: "DEADBEEF", Reason: 5}, // not issued
	}
	n, err := d.RevokeCertsBatch(entries)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 revoked, got %d", n)
	}
	for _, s := range []string{"65", "67"} {
		st, err := d.GetCertStatus("issuing", s)
		if err != nil || st.Status != "R" {
			t.Fatalf("serial %s status = %+v err=%v", s, st, err)
		}
	}
	// Non-target serial still valid.
	st, err := d.GetCertStatus("issuing", "66")
	if err != nil || st.Status != "V" {
		t.Fatalf("serial 66 should stay V: %+v err=%v", st, err)
	}

	// Empty batch.
	if n, err := d.RevokeCertsBatch(nil); err != nil || n != 0 {
		t.Fatalf("empty batch: n=%d err=%v", n, err)
	}
}
