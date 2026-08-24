// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/varwof/engine/db"
)

// IssueCert writes a certificate to memory first (immediately visible to all
// reads) and enqueues it for batched, WAL-protected persistence. Issuing the
// same (ca, serial) again is idempotent when the fingerprint matches;
// otherwise db.ErrDuplicateSerial is returned.
func (e *Engine) IssueCert(rec *db.CertRecord) error {
	if rec == nil {
		return fmt.Errorf("issue: nil record")
	}
	existing, inserted, evicted, err := e.certIdx.insertIfAbsent(
		rec, e.opts.MaxCerts, e.opts.MaxResidentBytes, time.Now().Add(-e.opts.Grace))
	if evicted > 0 {
		e.evictions.Add(uint64(evicted))
	}
	if err != nil {
		e.opts.Logger.Warn("engine: issue rejected by backpressure", "reason", "cert_index_at_capacity", "ca", rec.CAName, "serial", rec.SerialNumber)
		return err // ErrBackpressure when at capacity with nothing to evict
	}
	if !inserted {
		if existing.Fingerprint == rec.Fingerprint {
			return nil // idempotent retry after crash/WAL replay
		}
		return fmt.Errorf("cert %s/%s: %w", rec.CAName, rec.SerialNumber, db.ErrDuplicateSerial)
	}
	if e.rb.IsFull() {
		e.opts.Logger.Warn("engine: issue rejected by backpressure", "reason", "write_pipeline_full", "ca", rec.CAName, "serial", rec.SerialNumber)
		return ErrBackpressure
	}
	if !e.rb.Add(rec) {
		// Extremely unlikely after the IsFull check; keep memory authoritative
		// but signal backpressure so the caller can return 503.
		e.opts.Logger.Warn("engine: issue rejected by backpressure", "reason", "write_pipeline_add_failed", "ca", rec.CAName, "serial", rec.SerialNumber)
		return ErrBackpressure
	}
	e.issued.Add(1)
	return nil
}

// RevokeCert marks a certificate revoked in memory immediately, notifies the
// OnCertRevoked callback, flushes buffered certs to the backend so the UPDATE
// matches, and queues the persistence op.
//
// It returns ErrNotFound when the certificate is not resident in memory
// (e.g. an out-of-band write such as the CLI issued it while the engine was
// stopped) so callers can fall back to the DB; a certificate that is already
// revoked reports an "already revoked" error.
func (e *Engine) RevokeCert(caName, serial string, reason int) error {
	now := time.Now().UTC()
	r, ok := e.certIdx.setRevoked(caName, serial, now, reason)
	if !ok {
		// Distinguish a memory-miss (fall back to DB) from already-revoked.
		if _, exists := e.certIdx.get(caName, serial); !exists {
			return fmt.Errorf("%w: certificate %s/%s not in memory", ErrNotFound, caName, serial)
		}
		return fmt.Errorf("certificate %s/%s already revoked", caName, serial)
	}
	e.revoked.put(r)
	e.revokedCount.Add(1)
	if e.opts.OnCertRevoked != nil {
		e.opts.OnCertRevoked(serial)
	}
	// Ensure the cert row exists before the UPDATE is persisted (ordering
	// guarantee: memory is authoritative, DB converges in order).
	e.rb.FlushAll()
	e.enqueue(caName+"/"+serial, func() error {
		_, err := e.DB().Exec(`
			UPDATE certificates
			SET status = 'R', revoked_at = ?, revoke_reason = ?, invalidity_date = ?
			WHERE ca_name = ? AND serial_number = ? AND status = 'V'`,
			now.Format(time.RFC3339), reason, now.Format(time.RFC3339), caName, serial)
		return err
	})
	return nil
}

// RevokeBatchEntry identifies a single certificate to revoke in a bulk
// operation (aliased from the db package so both layers share one type).
type RevokeBatchEntry = db.RevokeBatchEntry

// RevokeCertsBatch revokes a large set of certificates with memory-first
// semantics: every resident certificate is flipped to revoked under a single
// index-lock acquisition (immediately visible to all reads — "memory is
// truth"), then a single backend op persists the batch. Non-resident
// (out-of-band) entries are reported in the returned slice so callers can
// retry them against the DB.
//
// This is the hot path for revocation storms (e.g. mass revocation of a
// compromised batch): one lock acquisition, one enqueue, N UPDATEs serialized
// by the writer — as opposed to N RevokeCert calls (N locks + N enqueues).
func (e *Engine) RevokeCertsBatch(entries []RevokeBatchEntry) (int, []RevokeBatchEntry, error) {
	if len(entries) == 0 {
		return 0, nil, nil
	}
	now := time.Now().UTC()

	// Pass 1: mutate memory under one lock. Each entry's reason is written into
	// its clone before publication, so the published records carry per-entry
	// reasons with no post-hoc mutation.
	pairs := make([]revokePair, len(entries))
	for i, en := range entries {
		pairs[i] = revokePair{CA: en.CA, Serial: en.Serial, Reason: en.Reason}
	}
	revoked, missing := e.certIdx.bulkSetRevoked(pairs, now)
	e.revoked.putAll(revoked)
	if len(revoked) > 0 {
		e.revokedCount.Add(uint64(len(revoked)))
	}
	if len(revoked) > 0 && e.opts.OnCertRevoked != nil {
		e.opts.OnCertRevoked("") // bulk
	}

	miss := make([]RevokeBatchEntry, 0, len(missing))
	missSet := make(map[certKey]struct{}, len(missing))
	for _, m := range missing {
		missSet[m] = struct{}{}
	}
	for _, en := range entries {
		if _, isMiss := missSet[certKey{ca: en.CA, serial: en.Serial}]; isMiss {
			miss = append(miss, en)
		}
	}

	// Pass 2: single backend op persisting the whole batch. Writer is
	// serialized, so ordering relative to pending INSERTs is preserved.
	// BulkRevokeCertificates issues one UPDATE per ~200-entry chunk (a CASE
	// expression carries per-row reasons) instead of one UPDATE per entry.
	if len(revoked) > 0 {
		e.rb.FlushAll()
		entries := make([]db.RevokeBatchEntry, len(revoked))
		for i, r := range revoked {
			entries[i] = db.RevokeBatchEntry{
				CA:     r.CAName,
				Serial: r.SerialNumber,
				Reason: derefInt(r.RevokeReason),
			}
		}
		// Single bulk op, key-free: the FlushAll above guarantees every cert
		// INSERT has landed before this batch UPDATE runs, and the batch is
		// idempotent, so shard placement does not affect correctness.
		e.enqueue("", func() error {
			if _, err := e.DB().BulkRevokeCertificates(entries); err != nil {
				return fmt.Errorf("batch revoke: %w", err)
			}
			return nil
		})
	}
	return len(revoked), miss, nil
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// RevokeCertsByPrincipalUid revokes every active certificate of a principal.
// Returns the number revoked. The in-memory status mutation happens under the
// certificate index lock, so it is race-free against concurrent reads. The DB
// update is always enqueued so out-of-band (non-resident) certificates of the
// principal are revoked too.
func (e *Engine) RevokeCertsByPrincipalUid(uid string, reason int) (int, error) {
	now := time.Now().UTC()
	revoked := e.certIdx.bulkSetRevokedByUid(uid, now, reason)
	e.revoked.putAll(revoked)
	e.revokedCount.Add(uint64(len(revoked)))
	if e.opts.OnCertRevoked != nil {
		e.opts.OnCertRevoked("") // bulk
	}
	e.rb.FlushAll()
	e.enqueue("uid:"+uid, func() error {
		_, err := e.DB().Exec(`
			UPDATE certificates SET status = 'R', revoked_at = ?, revoke_reason = ?, invalidity_date = ?
			WHERE principal_uid = ? AND status = 'V'`,
			now.Format(time.RFC3339), reason, now.Format(time.RFC3339), uid)
		return err
	})
	return len(revoked), nil
}

// RevokeCertsBySubCA revokes every active certificate issued by a sub-CA.
// Returns the number revoked. The DB update is always enqueued so out-of-band
// (non-resident) certificates under the CA are revoked too.
func (e *Engine) RevokeCertsBySubCA(caName string, reason int) (int, error) {
	now := time.Now().UTC()
	revoked := e.certIdx.bulkSetRevokedByCA(caName, now, reason)
	e.revoked.putAll(revoked)
	e.revokedCount.Add(uint64(len(revoked)))
	if e.opts.OnCertRevoked != nil {
		e.opts.OnCertRevoked("") // bulk
	}
	e.rb.FlushAll()
	e.enqueue("ca:"+caName, func() error {
		_, err := e.DB().Exec(`
			UPDATE certificates SET status = 'R', revoked_at = ?, revoke_reason = ?, invalidity_date = ?
			WHERE ca_name = ? AND status = 'V'`,
			now.Format(time.RFC3339), reason, now.Format(time.RFC3339), caName)
		return err
	})
	return len(revoked), nil
}

// StoreNonce records a one-time nonce in memory and queues persistence. Keyed
// by the nonce so a later ConsumeNonce for the same nonce lands on the same
// writer shard, preserving Store→Consume ordering in the backend.
func (e *Engine) StoreNonce(nonce []byte) error {
	if len(nonce) != 16 {
		return fmt.Errorf("store_nonce: nonce must be 16 bytes, got %d", len(nonce))
	}
	if err := e.nonces.store(nonce, time.Now().Add(e.opts.NonceTTL)); err != nil {
		if errors.Is(err, ErrBackpressure) {
			e.opts.Logger.Warn("engine: nonce store rejected by backpressure", "nonce", hex.EncodeToString(nonce))
		}
		return err
	}
	e.enqueue("nonce:"+hex.EncodeToString(nonce), func() error { return e.DB().StoreNonce(nonce) })
	return nil
}

// ConsumeNonce atomically consumes a one-time nonce (CAS semantics). It
// returns db.ErrNonceNotFound or db.ErrNonceAlreadyUsed on failure. Same-key
// routing as StoreNonce keeps Store→Consume ordering on one writer shard.
func (e *Engine) ConsumeNonce(nonce []byte) error {
	if len(nonce) != 16 {
		return fmt.Errorf("consume_nonce: nonce must be 16 bytes, got %d", len(nonce))
	}
	if err := e.nonces.consume(nonce); err != nil {
		return err
	}
	e.enqueue("nonce:"+hex.EncodeToString(nonce), func() error { return e.DB().ConsumeNonce(nonce) })
	return nil
}

// StoreDANonce records a DelegationAuthorization nonce (SIZE(32)) for replay
// protection. Memory is authoritative; the backend da_nonces table converges
// through the batch write pipeline. Returns db.ErrDuplicateNonce if the nonce
// was already used to mint an AIC (replay attempt).
//
// Crash safety: with WAL enabled, the nonce is WAL-fsynced before this returns,
// so once the caller's AIC issuance is acknowledged the nonce survives a crash
// and a replayed DA signature is rejected. Without WAL (non-file backend) the
// nonce is persisted synchronously to the DB instead.
func (e *Engine) StoreDANonce(nonce []byte) error {
	if len(nonce) != 32 {
		return fmt.Errorf("store_da_nonce: nonce must be 32 bytes, got %d", len(nonce))
	}
	// Reserve in memory first (atomic; concurrent duplicate claims lose).
	if err := e.daNonces.store(nonce, time.Now().Add(e.opts.NonceTTL)); err != nil {
		if errors.Is(err, ErrBackpressure) {
			e.opts.Logger.Warn("engine: da nonce store rejected by backpressure", "nonce", hex.EncodeToString(nonce))
		}
		return err
	}
	if e.rb.WALEnabled() {
		if err := e.rb.AddDANonceSync(nonce); err != nil {
			e.daNonces.remove(nonce)
			return fmt.Errorf("store_da_nonce: %w", err)
		}
		return nil
	}
	// No WAL: persist synchronously so the nonce is durable before the
	// issuance is acknowledged.
	if err := e.DB().StoreDANonce(nonce); err != nil {
		e.daNonces.remove(nonce)
		return err
	}
	return nil
}

// IsDANonceUsed reports whether a DelegationAuthorization nonce has already
// been stored (replay protection pre-check).
func (e *Engine) IsDANonceUsed(nonce []byte) (bool, error) {
	if len(nonce) != 32 {
		return false, fmt.Errorf("is_da_nonce_used: nonce must be 32 bytes, got %d", len(nonce))
	}
	used := e.daNonces.has(nonce)
	e.tickRead(used)
	return used, nil
}

// UpsertSubCA stores a sub-CA in memory and queues backend persistence.
// Keyed by name so a re-insert of the same sub-CA stays ordered on one shard.
func (e *Engine) UpsertSubCA(rec *db.SubCAMeta) error {
	e.subCas.put(rec)
	e.enqueue("subca:"+rec.Name, func() error { return e.DB().InsertSubCA(rec) })
	return nil
}

// UpsertTrustAnchor stores a trust anchor in memory and queues persistence.
func (e *Engine) UpsertTrustAnchor(rec *db.TrustAnchor) error {
	e.trust.put(rec)
	e.enqueue("ta:"+strconv.Itoa(rec.ID), func() error { return e.DB().InsertTrustAnchor(rec) })
	return nil
}

// UpsertAICExtension stores an AIC extension in memory and queues persistence.
// Keyed by (ca, serial) so an AIC row stays ordered relative to its cert.
func (e *Engine) UpsertAICExtension(a *db.AICExtension) error {
	e.aic.put(a)
	e.enqueue(a.CAName+"/"+a.SerialNumber, func() error { return e.DB().InsertAICExtension(a) })
	return nil
}
