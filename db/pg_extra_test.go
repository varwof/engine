// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build postgres

package db

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func pgTestDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("PG_TEST_DSN"); dsn != "" {
		return dsn
	}
	t.Skip("PG_TEST_DSN not set, skipping PG integration test")
	return ""
}

func openPG(t *testing.T, dsn string) *DB {
	t.Helper()
	d, err := OpenWithDialect("", NewPGDialect(PGConfig{DSN: dsn}))
	if err != nil {
		t.Fatalf("open PG %s: %v", dsn, err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestPGAdvisoryLockReal exercises pgAdvisoryLock against a real PostgreSQL:
// the TryLock acquired=true branch, cross-session contention, and reentrancy.
func TestPGAdvisoryLockReal(t *testing.T) {
	dsn := pgTestDSN(t)
	d1 := openPG(t, dsn)
	d2 := openPG(t, dsn)

	pg := d1.NewDistLock()
	if _, ok := pg.(*pgAdvisoryLock); !ok {
		t.Fatalf("expected *pgAdvisoryLock, got %T", pg)
	}
	l := pg.(*pgAdvisoryLock)
	ctx := context.Background()
	key := int64(999000001)

	if ok, err := l.TryLock(ctx, key); err != nil || !ok {
		t.Fatalf("TryLock: ok=%v err=%v", ok, err)
	}
	// Reentrant TryLock bumps the refcount without a second DB call.
	if ok, err := l.TryLock(ctx, key); err != nil || !ok {
		t.Fatalf("reentrant TryLock: ok=%v err=%v", ok, err)
	}
	if l.held[key] != 2 {
		t.Fatalf("held[%d] = %d, want 2", key, l.held[key])
	}

	// A second instance (separate connection pool) must fail while we hold.
	l2 := d2.NewDistLock()
	if ok, err := l2.TryLock(ctx, key); err != nil || ok {
		t.Fatalf("l2 TryLock while held: ok=%v err=%v (want ok=false)", ok, err)
	}

	for i := 0; i < 2; i++ {
		if err := l.Unlock(key); err != nil {
			t.Fatalf("Unlock %d: %v", i, err)
		}
	}
	if _, ok := l.held[key]; ok {
		t.Fatal("held entry must be removed after final unlock")
	}

	// After release, the second instance can acquire.
	if ok, err := l2.TryLock(ctx, key); err != nil || !ok {
		t.Fatalf("l2 TryLock after release: ok=%v err=%v", ok, err)
	}
	if err := l2.Unlock(key); err != nil {
		t.Fatal(err)
	}

	// Blocking Lock + reentrancy through real PG.
	if err := l.Lock(ctx, key); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := l.Lock(ctx, key); err != nil {
		t.Fatalf("reentrant Lock: %v", err)
	}
	if l.held[key] != 2 {
		t.Fatalf("held[%d] = %d, want 2", key, l.held[key])
	}
	for i := 0; i < 2; i++ {
		if err := l.Unlock(key); err != nil {
			t.Fatalf("final Unlock %d: %v", i, err)
		}
	}
}

// TestPGTransferToReal transfers a SQLite source into a fresh PostgreSQL target,
// covering the pgx sequence-update branch of TransferTo.
func TestPGTransferToReal(t *testing.T) {
	base := pgTestDSN(t)
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	adminDSN := *u
	adminDSN.Path = "/postgres"
	targetDSN := *u
	targetDSN.Path = "/pki_transfer_test"

	admin := openPG(t, adminDSN.String())
	if _, err := admin.Exec("DROP DATABASE IF EXISTS pki_transfer_test"); err != nil {
		t.Fatalf("drop test db: %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE pki_transfer_test"); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	target := openPG(t, targetDSN.String())

	srcPath := filepath.Join(t.TempDir(), "src.db")
	src, err := Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	createdAt := time.Now().UTC().Format("2006-01-02 15:04:05")
	if _, err := src.Exec(
		"INSERT INTO acme_accounts (id, jwk_thumbprint, jwk_json, contact, status, created_at) VALUES (42, 'thumb-42', '{}', 'mailto:a@b.c', 'valid', ?)",
		createdAt,
	); err != nil {
		t.Fatalf("seed source: %v", err)
	}

	if err := TransferTo(target, srcPath); err != nil {
		t.Fatalf("TransferTo: %v", err)
	}

	var cnt int
	if err := target.QueryRow("SELECT COUNT(*) FROM acme_accounts").Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("acme_accounts count = %d, want 1", cnt)
	}
	// Explicit id=42 insert does not advance the sequence; the transfer's setval
	// must have moved it past 42.
	var next int64
	if err := target.QueryRow("SELECT nextval('acme_accounts_id_seq')").Scan(&next); err != nil {
		t.Fatal(err)
	}
	if next <= 42 {
		t.Fatalf("sequence not advanced by setval: nextval=%d", next)
	}
}

// TestPGBulkStoreDANonces verifies the R1 batch DA nonce sink dialect branch
// (INSERT ... ON CONFLICT DO NOTHING multi-row) on a real PostgreSQL: batch
// store, duplicate ignore, and 32-byte validation.
func TestPGBulkStoreDANonces(t *testing.T) {
	base := pgTestDSN(t)
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	adminDSN := *u
	adminDSN.Path = "/postgres"
	name := "pki_danonce_test"
	targetDSN := *u
	targetDSN.Path = "/" + name

	admin := openPG(t, adminDSN.String())
	if _, err := admin.Exec("DROP DATABASE IF EXISTS " + name); err != nil {
		t.Fatalf("drop test db: %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name)
	})
	d := openPG(t, targetDSN.String())

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

// TestPGBulkRevokeCertificates verifies the R3 single-statement bulk revoke
// dialect branch (CASE UPDATE with pgx $N placeholders) on a real PostgreSQL.
func TestPGBulkRevokeCertificates(t *testing.T) {
	base := pgTestDSN(t)
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	adminDSN := *u
	adminDSN.Path = "/postgres"
	name := "pki_bulkrev_test"
	targetDSN := *u
	targetDSN.Path = "/" + name

	admin := openPG(t, adminDSN.String())
	if _, err := admin.Exec("DROP DATABASE IF EXISTS " + name); err != nil {
		t.Fatalf("drop test db: %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatalf("create test db: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name)
	})
	d := openPG(t, targetDSN.String())

	const total = 250 // spans 2 chunks
	entries := make([]RevokeBatchEntry, total)
	for i := 0; i < total; i++ {
		serial := int64(0x3000 + i)
		rec := makeTestCert(t, serial, fmt.Sprintf("pgbulk%d.example.com", i))
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
	n2, err := d.BulkRevokeCertificates(entries)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("re-run revoked %d, want 0", n2)
	}
}
