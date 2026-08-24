// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"strings"
	"testing"
)

// FuzzRebindAndAdapt ensures the dialect SQL transforms never panic on
// arbitrary query text and produce output with balanced placeholders.
func FuzzRebindAndAdapt(f *testing.F) {
	seeds := []string{
		"INSERT OR REPLACE INTO t (a, b) VALUES (?, ?)",
		"INSERT OR IGNORE INTO t (a) VALUES (?)",
		"SELECT * FROM t WHERE a = ? AND b = ?",
		"INSERT INTO t (a) VALUES (?), (?), (?)",
		"",
	}
	dialects := []Dialect{pgDialect{}, mysqlDialect{}, SQLiteDialect{}}
	f.Add(int32(0), "INSERT OR REPLACE INTO t (a, b) VALUES (?, ?)")
	f.Add(int32(1), "INSERT OR IGNORE INTO t (a) VALUES (?)")
	f.Add(int32(2), "SELECT * FROM t WHERE a = ? AND b = ?")
	for _, s := range seeds {
		for i := range dialects {
			f.Add(int32(i), s)
		}
	}
	f.Fuzz(func(t *testing.T, idx int32, q string) {
		d := dialects[int(uint32(idx)%uint32(len(dialects)))]
		drv := d.DriverName()
		rebound := RebindDialect(d, q)
		if drv == "pgx" {
			// Every '?' must have become a '$n' placeholder.
			if strings.Contains(rebound, "?") {
				t.Fatalf("pgx rebound SQL still contains '?': %q", rebound)
			}
		} else if rebound != q {
			t.Fatalf("%s rebound must be identity, got %q", drv, rebound)
		}
		_ = adaptInsertSQL(q, d)
	})
}

// TestAdaptInsertSQLBarePrefixes is a regression test for the slice-bounds
// panic the fuzzer found: adaptInsertSQL sliced past the end of the string
// when the input was exactly "INSERT OR IGNORE" / "INSERT OR REPLACE".
func TestAdaptInsertSQLBarePrefixes(t *testing.T) {
	for _, q := range []string{"INSERT OR IGNORE", "INSERT OR REPLACE"} {
		for _, d := range []Dialect{pgDialect{}, mysqlDialect{}, SQLiteDialect{}} {
			_ = adaptInsertSQL(q, d) // must not panic
		}
	}
	if got := adaptInsertSQL("INSERT OR IGNORE", mysqlDialect{}); got != "INSERT IGNORE INTO " {
		t.Fatalf("unexpected mysql result %q", got)
	}
	if got := adaptInsertSQL("INSERT OR IGNORE", pgDialect{}); got != "INSERT INTO  ON CONFLICT DO NOTHING" {
		t.Fatalf("unexpected pgx result %q", got)
	}
}

// FuzzBulkInsertSQL ensures the batch SQL builder never panics on arbitrary
// row counts.
func FuzzBulkInsertSQL(f *testing.F) {
	f.Add(0)
	f.Add(1)
	f.Add(50)
	f.Add(-3)
	f.Add(1000000)
	f.Fuzz(func(t *testing.T, n int) {
		dialects := []Dialect{SQLiteDialect{}, pgDialect{}, mysqlDialect{}}
		for _, d := range dialects {
			q := bulkInsertSQL(d, n)
			if n > 0 && !strings.Contains(q, "VALUES") {
				t.Fatalf("bulkInsertSQL(%d) missing VALUES: %q", n, q)
			}
		}
	})
}
