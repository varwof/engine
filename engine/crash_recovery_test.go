// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// TestEngineCrashRecoveryE2E verifies the kill -9 path end-to-end: records
// issued into the WAL-backed pipeline before a hard crash (no Stop/FlushAll,
// no deferred cleanup) must be recovered on restart — WAL replay persists them
// to the DB, then load() rebuilds the in-memory index so reads see them.
//
// The crash is simulated faithfully with a subprocess helper that os.Exit(0)s
// mid-flight, exactly like a SIGKILL: deferred cleanup never runs, the record
// buffer's WAL file is left untruncated, and the DB stays empty because the
// batch pipeline never drains.
func TestEngineCrashRecoveryE2E(t *testing.T) {
	if os.Getenv("GO_WANT_CRASH_HELPER") == "1" {
		crashAndExit(t)
		return
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "crash.db")
	walPath := filepath.Join(dir, "records.wal")

	cmd := exec.Command(os.Args[0], "-test.run=^TestEngineCrashRecoveryE2E$")
	cmd.Env = append(os.Environ(),
		"GO_WANT_CRASH_HELPER=1",
		"PKI_CRASH_DB="+dbPath,
		"PKI_CRASH_WAL="+walPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("crash helper failed: %v\n%s", err, out)
	}

	// Reopen the same database. The crash left the DB empty (the pipeline never
	// drained); recovery must come entirely from WAL replay.
	d, err := openDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	n0, err := d.CountCertsByCA("issuing", "")
	if err != nil {
		t.Fatal(err)
	}
	if n0 != 0 {
		t.Fatalf("expected DB empty before replay (crash never drained the pipeline), got %d", n0)
	}

	e, err := NewEngine(d, EngineOptions{Logger: discardLogger(), WalPath: walPath})
	if err != nil {
		t.Fatalf("restart NewEngine: %v", err)
	}
	defer e.Stop()

	// The fsync boundary is 100 records; the helper issued 210, so exactly the
	// first 200 records are durable (records 201-210 sit in the WAL bufio buffer
	// and are lost with the process). Verify all 200 survive and rebuild.
	n, err := d.CountCertsByCA("issuing", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 200 {
		t.Fatalf("expected exactly 200 records replayed from WAL, got %d", n)
	}
	if got := e.Metrics().CertIndexSize; got != 200 {
		t.Fatalf("expected rebuilt index of 200 certs, got %d", got)
	}
	for i := 1; i <= 200; i++ {
		got, err := e.GetCert("issuing", fmt.Sprintf("%X", i))
		if err != nil {
			t.Fatalf("cert %d missing after restart: %v", i, err)
		}
		if want := fmt.Sprintf("host%d.example.com", i); got.CommonName != want {
			t.Fatalf("cert %d: got CN %q, want %q", i, got.CommonName, want)
		}
	}
}

// crashAndExit is the subprocess helper. It issues records into the WAL-backed
// pipeline and then hard-exits, skipping all cleanup to emulate kill -9.
func crashAndExit(t *testing.T) {
	dbPath := os.Getenv("PKI_CRASH_DB")
	walPath := os.Getenv("PKI_CRASH_WAL")

	d, err := openDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// Huge threshold + long latency: the run loop never drains, so the crash
	// leaves the DB empty and only the WAL carries the records.
	e, err := NewEngine(d, EngineOptions{
		Logger:          discardLogger(),
		WalPath:         walPath,
		WriteThreshold:  1 << 30,
		WriteMaxLatency: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = e // never stopped: the hard exit below is the crash

	for i := 1; i <= 210; i++ {
		rec := makeCert(int64(i), fmt.Sprintf("host%d.example.com", i), time.Now().Add(365*24*time.Hour))
		if err := e.IssueCert(rec); err != nil {
			t.Fatal(err)
		}
	}
	os.Exit(0)
}

func openDB(path string) (*db.DB, error) {
	return db.Open(path)
}
