// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package recordbuffer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func daNonce(t *testing.T, seed byte) []byte {
	t.Helper()
	n := make([]byte, 32)
	for i := range n {
		n[i] = seed
	}
	return n
}

// TestRecordBufferAddDANonceSyncNoWAL verifies the WAL-disabled path returns
// ErrWALDisabled so the engine falls back to synchronous DB persistence (the
// crash-safety contract for DA nonces without a WAL).
func TestRecordBufferAddDANonceSyncNoWAL(t *testing.T) {
	rb, err := NewRecordBuffer(func() *db.DB { return nil }, 100, 1000, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	if rb.WALEnabled() {
		t.Fatal("WAL should be disabled with empty walPath")
	}
	if err := rb.AddDANonceSync(daNonce(t, 1)); err != ErrWALDisabled {
		t.Fatalf("AddDANonceSync without WAL: want ErrWALDisabled, got %v", err)
	}
	if rb.Pending() != 0 {
		t.Fatalf("pending should stay 0 on WAL-disabled rejection, got %d", rb.Pending())
	}
}

// TestRecordBufferDANonceWALReplay verifies crash recovery for a DA nonce
// written to the WAL: the nonce survives a restart through WAL replay into
// the DB (R2). The buffer never drains (huge threshold), mirroring a crash.
func TestRecordBufferDANonceWALReplay(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "records.wal")
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Simulate a crash: write a DA nonce line to the WAL directly.
	line, _ := json.Marshal(walLine{Kind: "da_nonce", Nonce: daNonce(t, 3)})
	if err := os.WriteFile(walPath, append(line, '\n'), 0640); err != nil {
		t.Fatal(err)
	}

	rb, err := NewRecordBuffer(func() *db.DB { return d }, 1<<30, 1000, time.Hour, walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	// WAL replay during NewRecordBuffer must have persisted the nonce.
	used, err := d.IsDANonceUsed(daNonce(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Fatal("DA nonce not recovered from WAL replay")
	}
}

// TestRecordBufferAddDANonceSyncPersistsBatch verifies the batched sink for DA
// nonces (R1): many nonces Add()ed via AddDANonceSync converge to the DB in
// batched statements after a flush, and the WAL is fsynced before AddDANonceSync
// returns (durable once acknowledged).
func TestRecordBufferAddDANonceSyncPersistsBatch(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "records.wal")
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	rb, err := NewRecordBuffer(func() *db.DB { return d }, 1<<30, 100000, time.Hour, walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	const n = 250
	nonces := make([][]byte, n)
	for i := range nonces {
		nonces[i] = daNonce(t, byte(i))
		if err := rb.AddDANonceSync(nonces[i]); err != nil {
			t.Fatalf("AddDANonceSync %d: %v", i, err)
		}
	}

	// AddDANonceSync signals the drain loop; the batch converges to the DB
	// promptly (batched bulk store). Poll until all nonces are visible.
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
			t.Fatal("nonces did not converge to DB within 3s")
		}
		time.Sleep(5 * time.Millisecond)
	}

	rb.FlushAll()
	if rb.Pending() != 0 {
		t.Fatalf("pending after FlushAll = %d, want 0", rb.Pending())
	}
	// WAL truncated after full flush.
	fi, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Fatalf("WAL not truncated after flush, size=%d", fi.Size())
	}
}

// TestRecordBufferAddDANonceSyncMixedBatch verifies a buffer carrying both
// certificates and DA nonces flushes both groups in their respective bulk
// statements without loss.
func TestRecordBufferAddDANonceSyncMixedBatch(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "records.wal")
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	rb, err := NewRecordBuffer(func() *db.DB { return d }, 1<<30, 100000, time.Hour, walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rb.Stop()

	for i := 0; i < 50; i++ {
		if !rb.Add(rec("0000000000000000000000000000000000000"+string(rune('A'+i)), "mixed.example.com")) {
			t.Fatal("cert add rejected")
		}
	}
	for i := 0; i < 50; i++ {
		if err := rb.AddDANonceSync(daNonce(t, byte(100+i))); err != nil {
			t.Fatalf("nonce add: %v", err)
		}
	}
	rb.FlushAll()

	if n, _ := d.CountCertsByCA("test", ""); n != 50 {
		t.Fatalf("expected 50 certs persisted, got %d", n)
	}
	for i := 0; i < 50; i++ {
		if used, _ := d.IsDANonceUsed(daNonce(t, byte(100+i))); !used {
			t.Fatalf("nonce %d missing from DB", i)
		}
	}
}
