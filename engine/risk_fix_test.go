// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// TestStoreDANonceBatchConvergence verifies the R1 fix: DA nonces route through
// the batched write pipeline (WAL), so after a flush all nonces are present in
// the backend da_nonces table in bulk rather than one INSERT each.
func TestStoreDANonceBatchConvergence(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	e, err := NewEngine(d, EngineOptions{
		Logger:          discardLogger(),
		WalPath:         filepath.Join(dir, "records.wal"),
		WriteThreshold:  1 << 30,
		WriteMaxLatency: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	const n = 200
	nonces := make([][]byte, n)
	for i := range nonces {
		nonces[i] = make([]byte, 32)
		nonces[i][0] = byte(i)
		if err := e.StoreDANonce(nonces[i]); err != nil {
			t.Fatalf("StoreDANonce %d: %v", i, err)
		}
	}

	// AddDANonceSync signals the drain loop, so the batch converges to the DB
	// promptly through the batched sink (BulkStoreDANonces). Poll for convergence.
	deadline := time.Now().Add(3 * time.Second)
	for {
		all := true
		for i := range nonces {
			if used, _ := d.IsDANonceUsed(nonces[i]); !used {
				all = false
				break
			}
		}
		if all {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DA nonces did not converge to DB within 3s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	e.FlushAll()

	// All nonces landed via the batched sink.
	for i := range nonces {
		used, err := d.IsDANonceUsed(nonces[i])
		if err != nil {
			t.Fatal(err)
		}
		if !used {
			t.Fatalf("nonce %d missing from DB after FlushAll", i)
		}
	}
}

// TestStoreDANonceNoWALFallbackSync verifies the crash-safety fallback: without
// a WAL, StoreDANonce persists synchronously to the DB before returning, so a
// crash right after acknowledgment cannot lose the nonce.
func TestStoreDANonceNoWALFallbackSync(t *testing.T) {
	e := newTestEngine(t) // newTestEngine opens with no WalPath

	if e.rb.WALEnabled() {
		t.Fatal("newTestEngine should have WAL disabled")
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	if err := e.StoreDANonce(nonce); err != nil {
		t.Fatal(err)
	}

	// Synchronous: the DB must already have the nonce, no flush required.
	used, err := e.DB().IsDANonceUsed(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Fatal("DA nonce not synchronously persisted without WAL")
	}
}

// TestStoreDANonceWALCrashRecovery verifies the R2 fix end-to-end: a DA nonce
// WAL-fsynced before acknowledgment survives a hard crash (kill -9) and blocks
// replay on restart. Uses a subprocess helper that stores the nonce and exits
// without any cleanup, so recovery must come entirely from WAL replay.
func TestStoreDANonceWALCrashRecovery(t *testing.T) {
	if os.Getenv("GO_WANT_DA_NONCE_CRASH_HELPER") == "1" {
		daNonceCrashAndExit(t)
		return
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "crash.db")
	walPath := filepath.Join(dir, "records.wal")

	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreDANonceWALCrashRecovery$")
	cmd.Env = append(os.Environ(),
		"GO_WANT_DA_NONCE_CRASH_HELPER=1",
		"PKI_CRASH_DB="+dbPath,
		"PKI_CRASH_WAL="+walPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("crash helper failed: %v\n%s", err, out)
	}

	// The DB is empty (the pipeline never drained); recovery must come from
	// WAL replay into the DB, then load() rebuilds the memory nonce set.
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	if used, _ := d.IsDANonceUsed(make([]byte, 32)); used {
		t.Fatal("expected DB empty of nonces before replay (crash never drained)")
	}

	e, err := NewEngine(d, EngineOptions{Logger: discardLogger(), WalPath: walPath})
	if err != nil {
		t.Fatalf("restart NewEngine: %v", err)
	}
	t.Cleanup(e.Stop)

	used, err := e.IsDANonceUsed(make([]byte, 32)) // the helper stored all-zero nonce
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Fatal("DA nonce lost across crash (replay protection broken)")
	}
	if err := e.StoreDANonce(make([]byte, 32)); !errors.Is(err, db.ErrDuplicateNonce) {
		t.Fatalf("replay after crash: want ErrDuplicateNonce, got %v", err)
	}
}

// daNonceCrashAndExit is the subprocess helper. It stores a DA nonce through
// the WAL path (synchronous fsync, no DB convergence because the pipeline never
// drains) and then hard-exits, skipping all cleanup to emulate kill -9.
func daNonceCrashAndExit(t *testing.T) {
	dbPath := os.Getenv("PKI_CRASH_DB")
	walPath := os.Getenv("PKI_CRASH_WAL")

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(d, EngineOptions{
		Logger:          discardLogger(),
		WalPath:         walPath,
		WriteThreshold:  1 << 30, // never drains via threshold: DB stays empty, WAL carries the nonce
		WriteMaxLatency: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Close the crash DB handle after the startup load() so the drain
	// goroutine's flush (triggered by the AddDANonceSync flushCh signal) fails
	// and flushLocked returns early — never persisting the nonce to the crash
	// DB and never truncating the WAL. This keeps the "DB empty before replay"
	// assertion deterministic under -race, where the drain goroutine may
	// otherwise win the race against os.Exit(0).
	d.Close()
	_ = e // never stopped: the hard exit below is the crash

	if err := e.StoreDANonce(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

// TestRevokeCertsBatchBulkConvergence verifies the R3 fix: a bulk revocation
// spanning multiple chunk boundaries (250 entries > 199/chunk) converges to
// the DB via single-statement batch UPDATEs with per-row reasons intact.
func TestRevokeCertsBatchBulkConvergence(t *testing.T) {
	e := newTestEngine(t)

	const total = 250
	entries := make([]RevokeBatchEntry, total)
	for i := 0; i < total; i++ {
		serial := int64(0x2000 + i)
		rec := makeCert(serial, fmt.Sprintf("bulkrev%d.example.com", i), time.Time{})
		if err := e.IssueCert(rec); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		entries[i] = RevokeBatchEntry{CA: "issuing", Serial: fmt.Sprintf("%X", serial), Reason: i % 3}
	}
	e.FlushAll()

	n, miss, err := e.RevokeCertsBatch(entries)
	if err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Fatalf("revoked %d, want %d", n, total)
	}
	if len(miss) != 0 {
		t.Fatalf("unexpected misses: %v", miss)
	}

	e.FlushAll()

	// DB status converged via the batch UPDATE.
	for i, en := range entries {
		rec, err := e.DB().GetCert(en.CA, en.Serial)
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

	// Memory agrees.
	if got := e.Metrics().RevokedSetSize; got != total {
		t.Fatalf("RevokedSetSize = %d, want %d", got, total)
	}
}
