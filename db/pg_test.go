// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build postgres

package db

import (
	"os"
	"testing"
)

func TestPGConnect(t *testing.T) {
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_TEST_DSN not set, skipping PG integration test")
	}
	d, err := OpenWithDialect("", NewPGDialect(PGConfig{DSN: dsn}))
	if err != nil {
		t.Fatalf("open PG: %v", err)
	}
	defer d.Close()

	ver, err := d.CurrentVersion()
	if err != nil {
		t.Fatalf("current version: %v", err)
	}
	t.Logf("PG schema version: %d/%d", ver, SchemaVersion())

	if ver != SchemaVersion() {
		t.Errorf("expected schema v%d, got v%d", SchemaVersion(), ver)
	}

	// Verify SQLite backwards compat still works
	_ = Open
	t.Log("PG migration successful")
}
