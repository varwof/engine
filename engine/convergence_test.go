// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// TestConvergenceMemoryAuthoritative runs a seeded random sequence of
// issue/revoke/nonce operations while concurrent readers hammer the in-memory
// indexes, then flushes and asserts the backend exactly matches memory. This is
// the core invariant: memory is authoritative and the DB converges in order.
// It is designed to be run under -race in CI.
func TestConvergenceMemoryAuthoritative(t *testing.T) {
	for _, seed := range []int64{1, 2, 3} {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			e := newTestEngine(t)
			rng := rand.New(rand.NewSource(seed))

			const ops = 1500
			const serials = 60

			// Concurrent readers exercise the RWMutex read paths while writers
			// mutate the indexes and the backend converges.
			stop := make(chan struct{})
			var wg sync.WaitGroup
			for r := 0; r < 4; r++ {
				wg.Add(1)
				go func(rs int64) {
					defer wg.Done()
					rr := rand.New(rand.NewSource(rs))
					counter := 0
					for {
						select {
						case <-stop:
							return
						default:
						}
						s := rr.Intn(serials)
						e.GetCertStatus("issuing", fmt.Sprintf("%X", s))
						_, _ = e.GetRevokedCertEntries("issuing")
						nonce := make([]byte, 16)
						rr.Read(nonce)
						e.IsNonceUsed(nonce)
						counter++
					}
				}(1000 + int64(r))
			}

			for i := 0; i < ops; i++ {
				serial := int64(rng.Intn(serials))
				cn := fmt.Sprintf("conv%d.example.com", serial)
				switch rng.Intn(4) {
				case 0: // issue (idempotent retries included)
					_ = e.IssueCert(makeCert(serial, cn, time.Now().Add(365*24*time.Hour)))
				case 1: // revoke
					_ = e.RevokeCert("issuing", fmt.Sprintf("%X", serial), rng.Intn(6))
				case 2: // store nonce (collisions surface as errors)
					b := make([]byte, 16)
					rng.Read(b)
					_ = e.StoreNonce(b)
				case 3: // consume nonce
					b := make([]byte, 16)
					rng.Read(b)
					_ = e.ConsumeNonce(b)
				}
			}
			close(stop)
			wg.Wait()

			if err := e.FlushAll(); err != nil {
				t.Fatal(err)
			}
			verifyConvergence(t, e)
		})
	}
}

func verifyConvergence(t *testing.T, e *Engine) {
	t.Helper()
	d := e.DB()

	// Certificates: memory == backend, status for status.
	memCerts := map[string]string{}
	e.certIdx.mu.RLock()
	for k, r := range e.certIdx.byKey {
		memCerts[k.ca+"/"+k.serial] = r.Status
	}
	e.certIdx.mu.RUnlock()

	backend, err := d.ListAllCerts()
	if err != nil {
		t.Fatal(err)
	}
	beCerts := map[string]string{}
	for _, r := range backend {
		beCerts[r.CAName+"/"+r.SerialNumber] = r.Status
	}
	if len(memCerts) != len(beCerts) {
		t.Fatalf("cert count mismatch: memory=%d backend=%d", len(memCerts), len(beCerts))
	}
	for k, st := range memCerts {
		if beCerts[k] != st {
			t.Fatalf("cert %s: memory=%q backend=%q", k, st, beCerts[k])
		}
	}

	// The CRL revoked set must equal the R certs in the index (all NotAfter are
	// in the future here, so none are pruned).
	rev := e.revoked.Len()
	rCount := 0
	e.certIdx.mu.RLock()
	for _, r := range e.certIdx.byKey {
		if r.Status == "R" {
			rCount++
		}
	}
	e.certIdx.mu.RUnlock()
	if rev != rCount {
		t.Fatalf("revoked set (%d) != R certs in index (%d)", rev, rCount)
	}

	// Nonces: memory == backend, used flag for used flag.
	memNonces := map[string]bool{}
	e.nonces.mu.RLock()
	for k, v := range e.nonces.entry {
		memNonces[k] = v.used
	}
	e.nonces.mu.RUnlock()

	beNonces, err := d.ListNonces()
	if err != nil {
		t.Fatal(err)
	}
	beN := map[string]bool{}
	for _, r := range beNonces {
		beN[hex.EncodeToString(r.Nonce)] = r.Used
	}
	if len(memNonces) != len(beN) {
		t.Fatalf("nonce count mismatch: memory=%d backend=%d", len(memNonces), len(beN))
	}
	for k, u := range memNonces {
		if beN[k] != u {
			t.Fatalf("nonce %s: memory.used=%v backend.used=%v", k, u, beN[k])
		}
	}
}
