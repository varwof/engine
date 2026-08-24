// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// Package engine implements the memory-centric data subsystem for varwof-core.
//
// It keeps the hot-path datasets (certificates, revocation set, one-time
// nonces, sub-CAs, trust anchors, AIC extensions) resident in memory and
// treats memory as the source of truth: reads hit in-memory indexes with zero
// SQL, writes land in memory first (immediately visible) and are persisted
// asynchronously to the backend database (SQLite / PostgreSQL / MySQL) through
// a batch write pipeline.
//
// See docs/REQUIREMENTS.md and docs/IMPLEMENTATION_PLAN.md for the full
// specification this package implements.
package engine

import (
	"log/slog"
	"time"
)

// EngineOptions configures the memory engine. Zero values select defaults.
type EngineOptions struct {
	// MaxCerts bounds the number of certificates kept in memory. When the
	// limit is reached, expired certificates are evicted first; if none can
	// be evicted, new issues are rejected (ErrBackpressure). 0 = default.
	MaxCerts int

	// MaxResidentBytes bounds the estimated resident memory of the hot
	// indexes (certificate records across all secondary maps plus AIC
	// extensions). It is an estimate, not an exact heap measurement: each
	// certificate contributes a fixed base overhead plus the length of its
	// string fields and cert_der; AIC extensions contribute their JSON
	// payloads. Enforced the same way as MaxCerts — expired entries are
	// evicted first, otherwise IssueCert returns ErrBackpressure. 0 =
	// default (2 GiB).
	MaxResidentBytes int64

	// MaxNonces bounds the in-memory nonce set. 0 = default.
	MaxNonces int

	// MaxDANonces bounds the in-memory DelegationAuthorization nonce set
	// (replay protection for DA signatures). 0 = default.
	MaxDANonces int

	// MaxRevoked bounds the per-CA revoked set. 0 = default.
	MaxRevoked int

	// Grace is the window kept beyond a certificate's NotAfter before the
	// janitor evicts it from the hot memory indexes. 0 = default (24h).
	Grace time.Duration

	// JanitorInterval is how often the background janitor runs expiry
	// pruning. 0 = default (60s).
	JanitorInterval time.Duration

	// NonceTTL is how long an unused nonce stays live. 0 = default (24h).
	NonceTTL time.Duration

	// WriteThreshold is the number of buffered certificate records that
	// triggers a batch flush. 0 = default (100).
	WriteThreshold int

	// WriteMaxPending is the hard backpressure ceiling for buffered
	// certificate writes. Add returns false past this point. 0 = default.
	WriteMaxPending int32

	// WriteMaxLatency is the maximum time a buffered certificate write can
	// wait before a forced flush. 0 = default (500ms).
	WriteMaxLatency time.Duration

	// WriteWorkers is the number of backend writer goroutines. Backend ops
	// (revoke/nonce/meta) are partitioned by key so same-key operations keep
	// their ordering (e.g. nonce Store → Consume); different keys run in
	// parallel. 0 = default (4).
	WriteWorkers int

	// WalPath is the WAL pre-write log for certificate batches. Empty
	// disables WAL (not crash-safe for unflushed batches). Only meaningful
	// for the file-backed SQLite backend.
	WalPath string

	// OnCertRevoked, if set, is invoked after a certificate is marked
	// revoked in memory. serial is the revoked certificate's serial number,
	// empty for bulk revocations. varwof-core wires this to invalidate the
	// mTLS handshake revocation cache and the OCSP response LRU.
	OnCertRevoked func(serial string)

	// Logger receives structured engine events. Defaults to slog.Default().
	Logger *slog.Logger
}

// defaults returns an options copy with zero values filled in.
func (o EngineOptions) defaults() EngineOptions {
	if o.MaxCerts <= 0 {
		o.MaxCerts = 200000
	}
	if o.MaxResidentBytes <= 0 {
		o.MaxResidentBytes = 2 << 30 // 2 GiB
	}
	if o.MaxNonces <= 0 {
		o.MaxNonces = 100000
	}
	if o.MaxDANonces <= 0 {
		o.MaxDANonces = 100000
	}
	if o.MaxRevoked <= 0 {
		o.MaxRevoked = 50000
	}
	if o.Grace <= 0 {
		o.Grace = 24 * time.Hour
	}
	if o.JanitorInterval <= 0 {
		o.JanitorInterval = 60 * time.Second
	}
	if o.NonceTTL <= 0 {
		o.NonceTTL = 24 * time.Hour
	}
	if o.WriteThreshold <= 0 {
		o.WriteThreshold = 100
	}
	if o.WriteMaxPending <= 0 {
		o.WriteMaxPending = 5000
	}
	if o.WriteMaxLatency <= 0 {
		o.WriteMaxLatency = 500 * time.Millisecond
	}
	if o.WriteWorkers <= 0 {
		o.WriteWorkers = 4
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}
