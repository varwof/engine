// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"context"
	"time"

	"github.com/varwof/engine/db"
)

// janitorLoop runs expiry pruning on the configured interval until ctx ends.
func (e *Engine) janitorLoop(ctx context.Context) {
	defer e.wg.Done()
	ticker := time.NewTicker(e.opts.JanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.janitor()
		case <-ctx.Done():
			return
		}
	}
}

// janitor prunes expired certificates, expired revoked entries, expired
// nonces, and AIC extensions whose certificates left the hot window, so memory
// and the backend tables stay bounded.
func (e *Engine) janitor() {
	now := time.Now()
	cutoff := now.Add(-e.opts.Grace)

	if keys := e.certIdx.evictExpired(cutoff); len(keys) > 0 {
		e.evictions.Add(uint64(len(keys)))
		e.opts.Logger.Info("engine: janitor evicted expired certs", "count", len(keys))
		e.pruneAICForEvicted(keys)
	}
	if n := e.revoked.pruneExpired(now); n > 0 {
		e.opts.Logger.Info("engine: janitor pruned expired revoked entries", "count", n)
	}
	if n := e.nonces.pruneExpired(now); n > 0 {
		e.opts.Logger.Info("engine: janitor pruned expired nonces", "count", n)
	}
	if n := e.daNonces.pruneExpired(now); n > 0 {
		e.opts.Logger.Info("engine: janitor pruned expired da nonces", "count", n)
	}
	// Prune the backend renewal_tokens table so it does not grow without
	// bound while only hot (unexpired) nonces stay in memory.
	if n, err := e.DB().CleanupExpiredNonces(e.opts.NonceTTL); err != nil {
		e.opts.Logger.Warn("engine: janitor backend nonce cleanup failed", "error", err)
	} else if n > 0 {
		e.opts.Logger.Info("engine: janitor pruned expired backend nonces", "count", n)
	}
	// Prune the backend da_nonces table (DA nonce replay-protection window).
	if n, err := e.DB().CleanupExpiredDANonces(e.opts.NonceTTL); err != nil {
		e.opts.Logger.Warn("engine: janitor backend da nonce cleanup failed", "error", err)
	} else if n > 0 {
		e.opts.Logger.Info("engine: janitor pruned expired backend da nonces", "count", n)
	}

	// Reconcile out-of-band revocations: a certificate revoked directly in the
	// backend (CLI-via-SQL, cross-tool backfill, another node) must become
	// revoked in memory so mTLS/OCSP/CRL stop authorizing it without waiting
	// for a full restart (finding 7).
	e.reconcileRevocations()
}

// reconcileRevocations picks up revocations made directly in the backend since
// the last pass and flips the corresponding resident certificates to revoked,
// using the backend-recorded timestamp/reason. Runs only from the janitor
// goroutine, so the reconcileSince watermark needs no lock.
func (e *Engine) reconcileRevocations() {
	since := e.reconcileSince.Add(-5 * time.Minute) // overlap guard for clock skew
	refs, err := e.DB().ListRevokedCertRefsSince(since.UTC().Format(time.RFC3339))
	if err != nil {
		e.opts.Logger.Warn("engine: revoke reconcile failed", "error", err)
		return
	}
	var flipped []*db.CertRecord
	for _, ref := range refs {
		if rec := e.certIdx.reconcileRevoked(ref.CAName, ref.SerialNumber, ref.RevokedAt, ref.RevokeReason); rec != nil {
			flipped = append(flipped, rec)
		}
		if !ref.RevokedAt.IsZero() && ref.RevokedAt.After(e.reconcileSince) {
			e.reconcileSince = ref.RevokedAt
		}
	}
	if len(flipped) == 0 {
		return
	}
	e.revoked.putAll(flipped)
	e.revokedCount.Add(uint64(len(flipped)))
	if e.opts.OnCertRevoked != nil {
		e.opts.OnCertRevoked("") // bulk
	}
	e.opts.Logger.Info("engine: reconciled out-of-band revocations", "count", len(flipped))
}

// pruneAICForEvicted drops AIC extensions whose certificates have left the hot
// window: from the in-memory AIC index immediately and from the backend
// aic_extensions table via the write pipeline. The key must match
// UpsertAICExtension's key (ca/serial) so both land on the same shard and the
// delete orders after the insert, and after any re-issue of the same serial.
func (e *Engine) pruneAICForEvicted(keys []certKey) {
	pruned := uint64(0)
	for _, k := range keys {
		if !e.aic.removeByCert(k.ca, k.serial) {
			continue
		}
		pruned++
		ca, serial := k.ca, k.serial
		e.enqueue(ca+"/"+serial, func() error {
			return e.DB().DeleteAICExtension(ca, serial)
		})
	}
	if pruned > 0 {
		e.aicPruned.Add(pruned)
		e.opts.Logger.Info("engine: janitor pruned AIC extensions for evicted certs", "count", pruned)
	}
}
