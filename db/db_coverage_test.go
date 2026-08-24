// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"testing"
)

// ─── db.go pure helpers ──────────────────────────────────────────

func TestPubKeyInfoV12_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(nil, 2048)
	algo, size := pubKeyInfoV12(&key.PublicKey)
	if algo != "RSA" || size != 2048 {
		t.Fatalf("expected RSA/2048, got %s/%d", algo, size)
	}
}

func TestPubKeyInfoV12_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), nil)
	algo, size := pubKeyInfoV12(&key.PublicKey)
	if algo != "ECDSA" || size != 256 {
		t.Fatalf("expected ECDSA/256, got %s/%d", algo, size)
	}
}

func TestPubKeyInfoV12_Ed25519(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	algo, size := pubKeyInfoV12(pub)
	if algo != "Ed25519" || size != 256 {
		t.Fatalf("expected Ed25519/256, got %s/%d", algo, size)
	}
}

func TestPubKeyInfoV12_Unknown(t *testing.T) {
	algo, size := pubKeyInfoV12("not-a-key")
	if algo != "Unknown" || size != 0 {
		t.Fatalf("expected Unknown/0, got %s/%d", algo, size)
	}
}

func TestBytesHexV12(t *testing.T) {
	if got := bytesHexV12([]byte{0xde, 0xad}); got != "dead" {
		t.Fatalf("expected dead, got %s", got)
	}
	if got := bytesHexV12(nil); got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
	if got := bytesHexV12([]byte{}); got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
}

func TestSubjectFirstV12(t *testing.T) {
	if got := subjectFirstV12([]string{"first", "second"}); got != "first" {
		t.Fatalf("expected first, got %s", got)
	}
	if got := subjectFirstV12(nil); got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
	if got := subjectFirstV12([]string{}); got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
}

func TestFormatSANsV12(t *testing.T) {
	cert := &x509.Certificate{
		DNSNames:       []string{"example.com", "www.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("1.2.3.4")},
		EmailAddresses: []string{"admin@example.com"},
	}
	got := formatSANsV12(cert)
	if got == "" {
		t.Fatal("expected non-empty")
	}
	if !contains(got, "DNS:example.com") {
		t.Fatalf("expected DNS:example.com in %s", got)
	}
	if !contains(got, "IP:1.2.3.4") {
		t.Fatalf("expected IP:1.2.3.4 in %s", got)
	}
	if !contains(got, "email:admin@example.com") {
		t.Fatalf("expected email: in %s", got)
	}
}

func TestFormatSANsV12_Empty(t *testing.T) {
	cert := &x509.Certificate{}
	if got := formatSANsV12(cert); got != "" {
		t.Fatalf("expected empty, got %s", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─── adaptInsertSQL ──────────────────────────────────────────────

func TestAdaptInsertSQL_MysqlReplace(t *testing.T) {
	d := NewMySQLDialect("user:pass@tcp(localhost)/test")
	got := adaptInsertSQL("INSERT OR REPLACE INTO certs (id) VALUES (?)", d)
	if got != "REPLACE INTO certs (id) VALUES (?)" {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestAdaptInsertSQL_MysqlIgnore(t *testing.T) {
	d := NewMySQLDialect("user:pass@tcp(localhost)/test")
	got := adaptInsertSQL("INSERT OR IGNORE INTO certs (id) VALUES (?)", d)
	if got != "INSERT IGNORE INTO certs (id) VALUES (?)" {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestAdaptInsertSQL_PGReplace(t *testing.T) {
	d := NewPGDialect(PGConfig{DSN: "postgres://localhost/test"})
	got := adaptInsertSQL("INSERT OR REPLACE INTO certs (id) VALUES ($1)", d)
	if got != "INSERT INTO certs (id) VALUES ($1) ON CONFLICT DO NOTHING" {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestAdaptInsertSQL_PGIgnore(t *testing.T) {
	d := NewPGDialect(PGConfig{DSN: "postgres://localhost/test"})
	got := adaptInsertSQL("INSERT OR IGNORE INTO certs (id) VALUES ($1)", d)
	if got != "INSERT INTO certs (id) VALUES ($1) ON CONFLICT DO NOTHING" {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestAdaptInsertSQL_SQLite(t *testing.T) {
	d := SQLiteDialect{}
	got := adaptInsertSQL("INSERT OR REPLACE INTO certs (id) VALUES (?)", d)
	if got != "INSERT OR REPLACE INTO certs (id) VALUES (?)" {
		t.Fatalf("sqlite should not adapt, got: %s", got)
	}
}

func TestAdaptInsertSQL_WithInto(t *testing.T) {
	d := NewMySQLDialect("user:pass@tcp(localhost)/test")
	got := adaptInsertSQL("INSERT OR REPLACE INTO certs (id) VALUES (?)", d)
	if got != "REPLACE INTO certs (id) VALUES (?)" {
		t.Fatalf("unexpected: %s", got)
	}
}

// ─── MySQLURLToDSN ───────────────────────────────────────────────

func TestMySQLURLToDSN(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"mysql://user:pass@host:3306/db", "user:pass@tcp(host:3306)/db"},
		{"mariadb://user:pass@host:3306/db?parseTime=true", "user:pass@tcp(host:3306)/db?parseTime=true"},
		{"user:pass@tcp(host:3306)/db", "user:pass@tcp(host:3306)/db"}, // already raw
		{"host:3306/dbname", "tcp(host:3306)/dbname"},                  // no @
		{"hostonly", "tcp(hostonly)"},                                  // no / no @
		{"mysql://host:3306/db", "tcp(host:3306)/db"},                  // no userinfo
	}
	for _, tt := range tests {
		got := MySQLURLToDSN(tt.input)
		if got != tt.want {
			t.Errorf("MySQLURLToDSN(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ─── DialectForDSN ───────────────────────────────────────────────

func TestDialectForDSN(t *testing.T) {
	d1 := DialectForDSN("postgres://localhost/db")
	if d1.DriverName() != "pgx" {
		t.Fatalf("expected pgx, got %s", d1.DriverName())
	}
	d2 := DialectForDSN("mysql://localhost/db")
	if d2.DriverName() != "mysql" {
		t.Fatalf("expected mysql, got %s", d2.DriverName())
	}
	d3 := DialectForDSN("sqlite.db")
	if d3.DriverName() != "sqlite" {
		t.Fatalf("expected sqlite, got %s", d3.DriverName())
	}
}

// ─── DB.Dialect() accessor ──────────────────────────────────────

func TestDBDialect(t *testing.T) {
	d := &DB{dialect: SQLiteDialect{}}
	if d.Dialect().DriverName() != "sqlite" {
		t.Fatalf("expected sqlite")
	}
}

// ─── SQLiteDialect methods ──────────────────────────────────────

func TestSQLiteDialect_Methods(t *testing.T) {
	d := SQLiteDialect{}
	if d.DriverName() != "sqlite" {
		t.Fatal("expected sqlite")
	}
	if d.OpenSuffix() == "" {
		t.Fatal("expected non-empty suffix")
	}
	if d.AutoIncrement() == "" {
		t.Fatal("expected non-empty")
	}
	if d.BlobType() != "BLOB" {
		t.Fatalf("expected BLOB, got %s", d.BlobType())
	}
	if d.NowExpr() == "" {
		t.Fatal("expected non-empty")
	}
	if d.Placeholder(0) != "?" {
		t.Fatalf("expected ?, got %s", d.Placeholder(0))
	}
	if !d.SupportsColumnDrop() {
		t.Fatal("expected true")
	}
	if d.BoolInt(true) != 1 {
		t.Fatal("expected 1")
	}
	if d.BoolInt(false) != 0 {
		t.Fatal("expected 0")
	}
	if d.EnableFKs() == "" {
		t.Fatal("expected non-empty")
	}
	// InsertOrReplace
	s := d.InsertOrReplace("t", "a,b", "?,?")
	if !containsStr(s, "INSERT OR REPLACE") {
		t.Fatalf("expected INSERT OR REPLACE, got %s", s)
	}
	// InsertOrIgnore
	s = d.InsertOrIgnore("t", "a,b", "?,?")
	if !containsStr(s, "INSERT OR IGNORE") {
		t.Fatalf("expected INSERT OR IGNORE, got %s", s)
	}
	// VacuumInto
	v := d.VacuumInto("/tmp/backup.db")
	if !containsStr(v, "VACUUM INTO") {
		t.Fatalf("expected VACUUM INTO, got %s", v)
	}
}

// ─── pgDialect methods ──────────────────────────────────────────

func TestPGDialect_Methods(t *testing.T) {
	d := NewPGDialect(PGConfig{DSN: "postgres://localhost/test"})
	if d.DriverName() != "pgx" {
		t.Fatal("expected pgx")
	}
	if d.Placeholder(0) != "$1" {
		t.Fatalf("expected $1, got %s", d.Placeholder(0))
	}
	if d.Placeholder(4) != "$5" {
		t.Fatalf("expected $5, got %s", d.Placeholder(4))
	}
	if d.SupportsColumnDrop() {
		t.Fatal("expected false for PG")
	}
	if d.BoolInt(true) != 1 {
		t.Fatal("expected 1")
	}
	if d.EnableFKs() != "" {
		t.Fatal("expected empty for PG")
	}
	// InsertOrReplace
	s := d.InsertOrReplace("t", "a,b", "$1,$2")
	if !containsStr(s, "ON CONFLICT") {
		t.Fatalf("expected ON CONFLICT, got %s", s)
	}
	// InsertOrIgnore
	s = d.InsertOrIgnore("t", "a,b", "$1,$2")
	if !containsStr(s, "ON CONFLICT DO NOTHING") {
		t.Fatalf("expected ON CONFLICT DO NOTHING, got %s", s)
	}
	// VacuumInto returns empty
	if v := d.VacuumInto("/tmp"); v != "" {
		t.Fatalf("expected empty, got %s", v)
	}
}

// ─── MySQLDialect methods ──────────────────────────────────────

func TestMySQLDialect_Methods(t *testing.T) {
	d := NewMySQLDialect("user:pass@tcp(localhost)/test")
	if d.DriverName() != "mysql" {
		t.Fatal("expected mysql")
	}
	if d.Placeholder(0) != "?" {
		t.Fatalf("expected ?, got %s", d.Placeholder(0))
	}
	if !d.SupportsColumnDrop() {
		t.Fatal("expected true for MySQL")
	}
	if d.BoolInt(true) != 1 {
		t.Fatal("expected 1")
	}
	if d.EnableFKs() != "" {
		t.Fatal("expected empty for MySQL (FK always on)")
	}
	// InsertOrReplace
	s := d.InsertOrReplace("t", "a,b", "?,?")
	if !containsStr(s, "ON DUPLICATE KEY") {
		t.Fatalf("expected ON DUPLICATE KEY, got %s", s)
	}
	// InsertOrIgnore
	s = d.InsertOrIgnore("t", "a,b", "?,?")
	if !containsStr(s, "INSERT IGNORE") {
		t.Fatalf("expected INSERT IGNORE, got %s", s)
	}
	// VacuumInto — MySQL not supported
	if v := d.VacuumInto("/tmp/backup.db"); v != "" {
		t.Fatalf("expected empty for MySQL, got %s", v)
	}
}
