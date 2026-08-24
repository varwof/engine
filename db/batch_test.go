// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBulkInsertSQLDialects(t *testing.T) {
	const rowColsTotal = 25
	rowTemplate := "(" + strings.Repeat("?,", rowColsTotal-1) + "?)"

	tests := []struct {
		name string
		dlg  Dialect
		want []string
		not  []string
	}{
		{
			name: "sqlite",
			dlg:  SQLiteDialect{},
			want: []string{
				"INSERT OR IGNORE INTO certificates (" + certColumns + ") VALUES ",
				rowTemplate + "," + rowTemplate,
			},
			not: []string{"ON CONFLICT", "INSERT IGNORE", "$1"},
		},
		{
			name: "pgx",
			dlg:  pgDialect{},
			want: []string{
				"INSERT INTO certificates (" + certColumns + ") VALUES ",
				"($1,", "$26,", " ON CONFLICT DO NOTHING",
			},
			not: []string{"INSERT OR IGNORE", "INSERT IGNORE"},
		},
		{
			name: "mysql",
			dlg:  mysqlDialect{},
			want: []string{
				"INSERT IGNORE INTO certificates (" + certColumns + ") VALUES ",
				rowTemplate + "," + rowTemplate,
			},
			not: []string{"INSERT OR IGNORE", "ON CONFLICT", "$1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bulkInsertSQL(tt.dlg, 2)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("bulkInsertSQL(%s, 2) = %q; missing %q", tt.name, got, w)
				}
			}
			for _, n := range tt.not {
				if strings.Contains(got, n) {
					t.Errorf("bulkInsertSQL(%s, 2) = %q; should not contain %q", tt.name, got, n)
				}
			}
			if tt.name != "pgx" {
				if n := strings.Count(got, "?"); n != 2*rowColsTotal {
					t.Errorf("placeholder count = %d, want %d", n, 2*rowColsTotal)
				}
			}
		})
	}

	// PG placeholders must be strictly 1-indexed and contiguous.
	pgSQL := bulkInsertSQL(pgDialect{}, 2)
	for i := 1; i <= 2*rowColsTotal; i++ {
		if !strings.Contains(pgSQL, "$"+itoa(i)) {
			t.Fatalf("pgx SQL missing placeholder $%d: %q", i, pgSQL)
		}
	}

	// Parameter count for a single sqlite row.
	one := bulkInsertSQL(SQLiteDialect{}, 1)
	if n := strings.Count(one, "?"); n != rowColsTotal {
		t.Errorf("single-row placeholder count = %d, want %d", n, rowColsTotal)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TestListAllCertsPage(t *testing.T) {
	d := newTestDB(t)
	var recs []*CertRecord
	for i := 0; i < 75; i++ {
		recs = append(recs, &CertRecord{
			SerialNumber: fmt.Sprintf("%03X", i),
			CAName:       "page-ca",
			Status:       "V",
			Subject:      fmt.Sprintf("CN=p%d", i),
			CommonName:   fmt.Sprintf("p%d", i),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			CertDER:      []byte("der-" + fmt.Sprint(i)),
			Fingerprint:  fmt.Sprintf("fp-%d", i),
		})
	}
	if n, err := d.BulkInsertCertRecords(recs); err != nil || n != 75 {
		t.Fatalf("bulk insert: n=%d err=%v", n, err)
	}

	all, err := d.ListAllCerts()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 75 {
		t.Fatalf("expected 75 all, got %d", len(all))
	}

	// Walk disjoint pages; each serial must appear exactly once.
	const page = 17
	var paged []*CertRecord
	for off := 0; ; off += page {
		p, err := d.ListAllCertsPage(page, off)
		if err != nil {
			t.Fatal(err)
		}
		paged = append(paged, p...)
		if len(p) < page {
			break
		}
	}
	if len(paged) != 75 {
		t.Fatalf("expected 75 paged, got %d", len(paged))
	}
	seen := map[string]bool{}
	for _, r := range paged {
		if seen[r.SerialNumber] {
			t.Fatalf("serial %s appears across two pages", r.SerialNumber)
		}
		seen[r.SerialNumber] = true
	}
	for _, r := range all {
		if !seen[r.SerialNumber] {
			t.Fatalf("serial %s missing from pages", r.SerialNumber)
		}
	}

	// limit <= 0 falls back to the unpaginated full scan.
	back, err := d.ListAllCertsPage(0, 0)
	if err != nil || len(back) != 75 {
		t.Fatalf("fallback: len=%d err=%v", len(back), err)
	}
}

// TestBulkInsertCertRecordsRoundTripRevoked pins the bulk-insert serialization
// of revoked_at / invalidity_date: a bulk-inserted revoked record must round
// trip with its revocation metadata intact.
func TestBulkInsertCertRecordsRoundTripRevoked(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	ra := now.Add(-time.Hour)
	reason := 4
	inv := now.Add(-30 * time.Minute)
	r := &CertRecord{
		SerialNumber: "B0001", CAName: "bulk-r", Status: "R",
		Subject: "CN=x", CommonName: "x",
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(48 * time.Hour),
		RevokedAt: &ra, RevokeReason: &reason, InvalidityDate: &inv,
		CertDER: []byte("der"), Fingerprint: "fp",
	}
	if n, err := d.BulkInsertCertRecords([]*CertRecord{r}); err != nil || n != 1 {
		t.Fatalf("bulk insert: n=%d err=%v", n, err)
	}
	all, err := d.ListAllCerts()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(all))
	}
	got := all[0]
	if got.Status != "R" || got.RevokedAt == nil || got.InvalidityDate == nil {
		t.Fatalf("revocation metadata lost in bulk round trip: %+v", got)
	}
	if got.RevokeReason == nil || *got.RevokeReason != 4 {
		t.Fatalf("revoke reason = %v, want 4", got.RevokeReason)
	}
}
