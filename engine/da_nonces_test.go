// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

// futureExp is the standard non-expired retention deadline for DA-nonce tests.
func futureExp() time.Time { return time.Now().Add(time.Hour) }

func TestDANonceStoreAndReplay(t *testing.T) {
	e := newTestEngine(t)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	if err := e.StoreDANonce(nonce, futureExp()); err != nil {
		t.Fatalf("store: %v", err)
	}

	used, err := e.IsDANonceUsed(nonce)
	if err != nil {
		t.Fatalf("is_used: %v", err)
	}
	if !used {
		t.Fatal("stored DA nonce should be reported used")
	}

	// Replay: same nonce must be rejected.
	if err := e.StoreDANonce(nonce, futureExp()); !errors.Is(err, db.ErrDuplicateNonce) {
		t.Fatalf("replay: want db.ErrDuplicateNonce, got %v", err)
	}
}

func TestDANonceInvalidLen(t *testing.T) {
	e := newTestEngine(t)
	if err := e.StoreDANonce(make([]byte, 16), futureExp()); err == nil {
		t.Error("expected error for 16-byte DA nonce")
	}
	if _, err := e.IsDANonceUsed(make([]byte, 31)); err == nil {
		t.Error("expected error for 31-byte DA nonce")
	}
}

func TestDANonceMetrics(t *testing.T) {
	e := newTestEngine(t)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	if err := e.StoreDANonce(nonce, futureExp()); err != nil {
		t.Fatal(err)
	}

	m := e.Metrics()
	if m.DANonceSetSize != 1 {
		t.Fatalf("DANonceSetSize = %d, want 1", m.DANonceSetSize)
	}
	if !containsMetric(e.PrometheusMetrics(), "varwof_engine_danonceset_size") {
		t.Fatal("prometheus output missing varwof_engine_danonceset_size")
	}
}

// TestDANonceNoWALBatchConvergence verifies the WAL-less (non-file backend)
// StoreDANonce path: the nonce is visible to replay checks immediately
// (memory is authoritative) and converges to the backend da_nonces table
// through the batch write pipeline instead of a synchronous single-row INSERT.
func TestDANonceNoWALBatchConvergence(t *testing.T) {
	path := t.TempDir() + "/test.db"
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	e, err := NewEngine(d, EngineOptions{Logger: discardLogger(), WalPath: ""})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	if err := e.StoreDANonce(nonce, futureExp()); err != nil {
		t.Fatal(err)
	}

	used, err := e.IsDANonceUsed(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Fatal("stored DA nonce should be reported used from memory immediately")
	}
	if err := e.StoreDANonce(nonce, futureExp()); !errors.Is(err, db.ErrDuplicateNonce) {
		t.Fatalf("replay without flush: want db.ErrDuplicateNonce, got %v", err)
	}

	// Converge the pipeline and verify the backend row exists.
	if err := e.FlushAll(); err != nil {
		t.Fatalf("FlushAll: %v", err)
	}
	usedDB, err := d.IsDANonceUsed(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !usedDB {
		t.Fatal("DA nonce not persisted to backend after batch flush")
	}
	if err := e.StoreDANonce(nonce, futureExp()); !errors.Is(err, db.ErrDuplicateNonce) {
		t.Fatalf("replay after flush: want db.ErrDuplicateNonce, got %v", err)
	}
}

func TestDANonceRestartRebuild(t *testing.T) {
	path := t.TempDir() + "/test.db"
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	// Engine #1 stores a DA nonce (async persisted to backend).
	e, err := NewEngine(d, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	if err := e.StoreDANonce(nonce, futureExp()); err != nil {
		t.Fatal(err)
	}
	e.Stop()
	d.Close()

	// Engine #2 rebuilds from the backend: the nonce must be present, so a
	// replay attempt is rejected after restart (crash-recovery guarantee).
	d2, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d2.Close() })
	e2, err := NewEngine(d2, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e2.Stop)

	used, err := e2.IsDANonceUsed(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Fatal("DA nonce lost across engine restart (replay protection broken)")
	}
	if err := e2.StoreDANonce(nonce, futureExp()); !errors.Is(err, db.ErrDuplicateNonce) {
		t.Fatalf("replay after restart: want ErrDuplicateNonce, got %v", err)
	}
}

func containsMetric(render, name string) bool {
	for i := 0; i+len(name) <= len(render); i++ {
		if render[i:i+len(name)] == name {
			return true
		}
	}
	return false
}
