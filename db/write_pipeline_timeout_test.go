// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEnsureMySQLTimeouts(t *testing.T) {
	tests := []struct {
		name string
		dsn  string
		want []string // substrings that must appear
		skip []string // substrings that must NOT appear
	}{
		{
			name: "url-derived dsn without timeouts",
			dsn:  "bench:bench@tcp(127.0.0.1:3306)/pki",
			want: []string{"?timeout=10s", "&readTimeout=30s", "&writeTimeout=30s"},
		},
		{
			name: "existing params preserved",
			dsn:  "user:pass@tcp(h:3306)/db?parseTime=true&readTimeout=1m",
			want: []string{"parseTime=true", "readTimeout=1m", "&writeTimeout=30s"},
			skip: []string{"readTimeout=30s"},
		},
		{
			name: "unix socket untouched",
			dsn:  "user:pass@unix(/run/mysqld/mysqld.sock)/db",
			want: []string{"@unix(/run/mysqld/mysqld.sock)/db"},
			skip: []string{"timeout="},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ensureMySQLTimeouts(tt.dsn)
			if got == tt.dsn && len(tt.skip) == 0 && len(tt.want) > 0 {
				t.Errorf("ensureMySQLTimeouts(%q) unchanged", tt.dsn)
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("ensureMySQLTimeouts(%q) = %q; missing %q", tt.dsn, got, w)
				}
			}
			for _, s := range tt.skip {
				if strings.Contains(got, s) {
					t.Errorf("ensureMySQLTimeouts(%q) = %q; should not contain %q", tt.dsn, got, s)
				}
			}
		})
	}
}

func TestBulkInsertCertRecordsCtxCancelled(t *testing.T) {
	d := newTestDB(t)
	recs := []*CertRecord{
		{
			SerialNumber: "AB01",
			CAName:       "timeout-ca",
			Status:       "V",
			Subject:      "CN=c1",
			CommonName:   "c1",
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			CertDER:      []byte("der"),
			Fingerprint:  "fp-ab",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	n, err := d.BulkInsertCertRecordsCtx(ctx, recs)
	if err == nil {
		t.Fatalf("expected context error, got n=%d err=nil", n)
	}
	if n != 0 {
		t.Fatalf("expected 0 inserted, got %d", n)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("cancelled ctx must return fast, took %v", time.Since(start))
	}

	// Nothing was inserted.
	var cnt int
	if err := d.QueryRow("SELECT COUNT(*) FROM certificates WHERE ca_name = ?", "timeout-ca").Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatalf("expected 0 rows, got %d", cnt)
	}
}

func TestBulkStoreDANoncesCtxCancelled(t *testing.T) {
	d := newTestDB(t)
	nonces := [][]byte{make32(), make32()}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err := d.BulkStoreDANoncesCtx(ctx, nonces)
	if err == nil {
		t.Fatalf("expected context error, got n=%d err=nil", n)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 stored, got %d", n)
	}
}

func make32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}
