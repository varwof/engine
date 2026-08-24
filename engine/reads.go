// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"fmt"
	"time"

	"github.com/varwof/engine/db"
)

// GetCert returns the full certificate record from the in-memory index.
func (e *Engine) GetCert(caName, serial string) (*db.CertRecord, error) {
	r, ok := e.certIdx.get(caName, serial)
	if !ok {
		e.tickRead(false)
		return nil, ErrNotFound
	}
	e.tickRead(true)
	return r, nil
}

// GetCertStatus returns the lightweight status of a certificate for OCSP /
// handshake revocation checks. Callers must apply OCSP expiry semantics
// (a valid certificate whose NotAfter has passed is "unknown"); the engine
// keeps expired certs in memory only within the configured grace window.
func (e *Engine) GetCertStatus(caName, serial string) (*db.CertStatus, error) {
	r, ok := e.certIdx.get(caName, serial)
	if !ok {
		e.tickRead(false)
		return nil, ErrNotFound
	}
	e.tickRead(true)
	return recordStatus(r), nil
}

// GetCertStatusByIssuer looks up certificate status by issuer DN + serial,
// used by mTLS handshake revocation checks where only the issuer DN is known.
func (e *Engine) GetCertStatusByIssuer(issuerDN, serial string) (*db.CertStatus, error) {
	r, ok := e.certIdx.getByIssuer(issuerDN, serial)
	if !ok {
		e.tickRead(false)
		return nil, ErrNotFound
	}
	e.tickRead(true)
	return recordStatus(r), nil
}

func recordStatus(r *db.CertRecord) *db.CertStatus {
	s := &db.CertStatus{
		Status:       r.Status,
		NotAfter:     r.NotAfter,
		RevokedAt:    r.RevokedAt,
		RevokeReason: r.RevokeReason,
	}
	return s
}

// GetCertBySPKIHash returns certificates matching a SPKI hash, optionally
// filtered by CA name and status, ordered by NotBefore descending. limit > 0
// pages the result: the returned cursor resumes from the last record and
// hasMore reports whether another page exists (pass limit=0 for the full set).
func (e *Engine) GetCertBySPKIHash(spkiHash, caName, status string, limit int, after *CertCursor) (recs []*db.CertRecord, next *CertCursor, hasMore bool, err error) {
	recs, next, hasMore = e.certIdx.getBySPKI(spkiHash, caName, status, limit, after)
	e.tickRead(len(recs) > 0)
	return recs, next, hasMore, nil
}

// ListCertsByPrincipalUid returns certificates for a principal UID, optionally
// filtered by status, ordered by NotBefore descending. Pagination as in
// GetCertBySPKIHash.
func (e *Engine) ListCertsByPrincipalUid(uid, status string, limit int, after *CertCursor) (recs []*db.CertRecord, next *CertCursor, hasMore bool, err error) {
	recs, next, hasMore = e.certIdx.getByUid(uid, status, limit, after)
	e.tickRead(len(recs) > 0)
	return recs, next, hasMore, nil
}

// ListCertsByAgentID returns certificates for an agent ID, optionally filtered
// by status, ordered by NotBefore descending. Pagination as in
// GetCertBySPKIHash.
func (e *Engine) ListCertsByAgentID(agent, status string, limit int, after *CertCursor) (recs []*db.CertRecord, next *CertCursor, hasMore bool, err error) {
	recs, next, hasMore = e.certIdx.getByAgent(agent, status, limit, after)
	e.tickRead(len(recs) > 0)
	return recs, next, hasMore, nil
}

// CheckDuplicateCN returns an error if an active certificate under the same CA
// and common_name has an overlapping validity window with [notBefore, notAfter].
func (e *Engine) CheckDuplicateCN(caName, cn string, notBefore, notAfter time.Time) error {
	for _, r := range e.certIdx.getActiveByCN(caName, cn) {
		if notBefore.Before(r.NotAfter) && notAfter.After(r.NotBefore) {
			return fmt.Errorf("duplicate CN %q: active cert %s already exists (valid %s – %s)",
				cn, r.SerialNumber, r.NotBefore.Format("2006-01-02"), r.NotAfter.Format("2006-01-02"))
		}
	}
	return nil
}

// GetRevokedCertEntries returns the revoked certificates of a CA that are
// still within their validity window, ordered by revoked_at descending, for
// CRL generation. Pure in-memory traversal, zero SQL.
func (e *Engine) GetRevokedCertEntries(caName string) ([]*db.RevokedCertEntry, error) {
	return e.GetRevokedCertEntriesSince(caName, time.Time{})
}

// GetRevokedCertEntriesSince returns revoked (non-expired) entries revoked at
// or after `since`, for Delta CRL generation. A zero `since` returns all
// entries (full CRL). Pure in-memory traversal, zero SQL.
func (e *Engine) GetRevokedCertEntriesSince(caName string, since time.Time) ([]*db.RevokedCertEntry, error) {
	recs := e.revoked.entries(caName)
	entries := make([]*db.RevokedCertEntry, 0, len(recs))
	for _, r := range recs {
		if !since.IsZero() {
			if r.RevokedAt == nil || r.RevokedAt.Before(since) {
				continue
			}
		}
		entries = append(entries, &db.RevokedCertEntry{
			SerialNumber:   r.SerialNumber,
			RevokedAt:      r.RevokedAt,
			RevokeReason:   r.RevokeReason,
			InvalidityDate: r.InvalidityDate,
		})
	}
	return entries, nil
}

// GetRevokedCerts returns the full revoked certificate records of a CA.
func (e *Engine) GetRevokedCerts(caName string) ([]*db.CertRecord, error) {
	return e.revoked.entries(caName), nil
}

// GetSubCA returns a sub-CA by name.
func (e *Engine) GetSubCA(name string) (*db.SubCAMeta, error) {
	r, ok := e.subCas.get(name)
	if !ok {
		e.tickRead(false)
		return nil, ErrNotFound
	}
	e.tickRead(true)
	return r, nil
}

// GetTrustAnchor returns a trust anchor by numeric id.
func (e *Engine) GetTrustAnchor(id int) (*db.TrustAnchor, error) {
	r, ok := e.trust.get(id)
	if !ok {
		e.tickRead(false)
		return nil, ErrNotFound
	}
	e.tickRead(true)
	return r, nil
}

// GetAICExtensionByCert returns the AIC extension for a certificate.
func (e *Engine) GetAICExtensionByCert(caName, serial string) (*db.AICExtension, error) {
	a, ok := e.aic.getByCert(caName, serial)
	if !ok {
		e.tickRead(false)
		return nil, ErrNotFound
	}
	e.tickRead(true)
	return a, nil
}

// ListAICExtensionsByAgentID returns the AIC extensions bound to an agent.
func (e *Engine) ListAICExtensionsByAgentID(agentID string) ([]*db.AICExtension, error) {
	recs := e.aic.getByAgent(agentID)
	e.tickRead(len(recs) > 0)
	return recs, nil
}

// ListAICExtensionsByPrincipalUid returns the AIC extensions bound to a
// principal UID.
func (e *Engine) ListAICExtensionsByPrincipalUid(uid string) ([]*db.AICExtension, error) {
	recs := e.aic.getByUid(uid)
	e.tickRead(len(recs) > 0)
	return recs, nil
}

// IsNonceUsed reports whether a nonce has been consumed.
func (e *Engine) IsNonceUsed(nonce []byte) (bool, error) {
	if len(nonce) != 16 {
		return false, fmt.Errorf("nonce must be 16 bytes, got %d", len(nonce))
	}
	used := e.nonces.isUsed(nonce)
	e.tickRead(used)
	return used, nil
}
