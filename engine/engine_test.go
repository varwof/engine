// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func newTestEngine(tb testing.TB, mutate ...func(*db.DB)) *Engine {
	tb.Helper()
	d, err := db.Open(tb.TempDir() + "/test.db")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { d.Close() })
	for _, m := range mutate {
		m(d)
	}
	e, err := NewEngine(d, EngineOptions{Logger: discardLogger()})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(e.Stop)
	return e
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestSetDBRepointsWritePath verifies that SetDB atomically swaps the backend
// handle so writes after the swap land in the new DB while reads stay on the
// resident in-memory index (E04 reload-keep-engine semantics).
func TestSetDBRepointsWritePath(t *testing.T) {
	path := t.TempDir() + "/swap.db"

	oldDB, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { oldDB.Close() })

	e, err := NewEngine(oldDB, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)

	rec := makeCert(1, "swap.example.com", time.Time{})
	if err := e.IssueCert(rec); err != nil {
		t.Fatal(err)
	}
	e.FlushAll()
	if _, err := oldDB.GetCert("issuing", "1"); err != nil {
		t.Fatalf("old DB should have the record: %v", err)
	}

	// A brand-new handle over the same store acts as the "reload" DB.
	newDB, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { newDB.Close() })

	e.SetDB(newDB)
	if e.DB() != newDB {
		t.Fatalf("DB() should return the swapped handle")
	}

	// Issue another record after the swap; it must land in newDB.
	rec2 := makeCert(2, "swap2.example.com", time.Time{})
	if err := e.IssueCert(rec2); err != nil {
		t.Fatal(err)
	}
	e.FlushAll()
	if _, err := newDB.GetCert("issuing", "2"); err != nil {
		t.Fatalf("new DB should have the post-swap record: %v", err)
	}

	// Reads stay memory-authoritative regardless of the swapped handle.
	if _, err := e.GetCert("issuing", "1"); err != nil {
		t.Fatalf("read should be served from memory after swap: %v", err)
	}

	// Revocation after the swap updates the DB through the new handle.
	if err := e.RevokeCert("issuing", "1", 1); err != nil {
		t.Fatal(err)
	}
	e.FlushAll()
	status, err := newDB.GetCertStatus("issuing", "1")
	if err != nil {
		t.Fatalf("read status from new DB: %v", err)
	}
	if status.Status != "R" {
		t.Fatalf("expected R after revoke via new handle, got %s", status.Status)
	}
}

// TestSetDBNilIgnored verifies SetDB(nil) is a safe no-op.
func TestSetDBNilIgnored(t *testing.T) {
	e := newTestEngine(t)
	before := e.DB()
	e.SetDB(nil)
	if e.DB() != before {
		t.Fatalf("SetDB(nil) must not change the handle")
	}
}

func makeCert(serial int64, cn string, notAfter time.Time) *db.CertRecord {
	now := time.Now()
	if notAfter.IsZero() {
		notAfter = now.Add(365 * 24 * time.Hour)
	}
	rec := &db.CertRecord{
		SerialNumber: fmt.Sprintf("%X", serial),
		CAName:       "issuing",
		Status:       "V",
		Subject:      "CN=" + cn + ",O=test",
		CommonName:   cn,
		NotBefore:    now,
		NotAfter:     notAfter,
		CertDER:      []byte("fake-der-cert-" + cn),
		IssuerDN:     "CN=Varwof Issuing CA,O=Varwof",
		SPKIHash:     "spki-" + cn,
		PrincipalUid: "uid-" + cn,
		AgentId:      "agent-" + cn,
	}
	rec.Fingerprint = db.Fingerprint(rec.CertDER)
	return rec
}

func TestGetCertAndStatus(t *testing.T) {
	e := newTestEngine(t)
	rec := makeCert(1, "a.example.com", time.Time{})
	if err := e.IssueCert(rec); err != nil {
		t.Fatal(err)
	}

	got, err := e.GetCert("issuing", "1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CommonName != "a.example.com" || got.Status != "V" {
		t.Fatalf("unexpected record: %+v", got)
	}

	st, err := e.GetCertStatus("issuing", "1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "V" || !st.NotAfter.Equal(rec.NotAfter) {
		t.Fatalf("unexpected status: %+v", st)
	}

	if _, err := e.GetCert("issuing", "999"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := e.GetCertStatus("issuing", "999"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetCertStatusByIssuerAndRevoke(t *testing.T) {
	e := newTestEngine(t)
	rec := makeCert(7, "b.example.com", time.Time{})
	rec.IssuerDN = "CN=Some CA,O=X"
	if err := e.IssueCert(rec); err != nil {
		t.Fatal(err)
	}

	st, err := e.GetCertStatusByIssuer("CN=Some CA,O=X", "7")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "V" {
		t.Fatalf("expected V, got %q", st.Status)
	}

	if err := e.RevokeCert("issuing", "7", 1); err != nil {
		t.Fatal(err)
	}
	// Memory is authoritative: revocation is visible immediately.
	st, err = e.GetCertStatus("issuing", "7")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "R" || st.RevokedAt == nil || st.RevokeReason == nil || *st.RevokeReason != 1 {
		t.Fatalf("expected revoked, got %+v", st)
	}
	st, err = e.GetCertStatusByIssuer("CN=Some CA,O=X", "7")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "R" {
		t.Fatalf("expected revoked via issuer, got %q", st.Status)
	}

	// Double revoke fails.
	if err := e.RevokeCert("issuing", "7", 2); err == nil {
		t.Fatal("expected error on double revoke")
	}
}

func TestSecondaryIndexes(t *testing.T) {
	e := newTestEngine(t)
	for i := int64(1); i <= 3; i++ {
		cn := fmt.Sprintf("c%d.example.com", i)
		if err := e.IssueCert(makeCert(i, cn, time.Time{})); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.RevokeCert("issuing", "2", 5); err != nil {
		t.Fatal(err)
	}

	// SPKI (with status filter).
	recs, _, _, err := e.GetCertBySPKIHash("spki-c1.example.com", "", "", 0, nil)
	if err != nil || len(recs) != 1 {
		t.Fatalf("spki: %v, %d", err, len(recs))
	}
	recs, _, _, err = e.GetCertBySPKIHash("spki-c2.example.com", "", "V", 0, nil)
	if err != nil || len(recs) != 0 {
		t.Fatalf("spki status filter: %v, %d", err, len(recs))
	}

	// Principal.
	recs, _, _, err = e.ListCertsByPrincipalUid("uid-c1.example.com", "", 0, nil)
	if err != nil || len(recs) != 1 {
		t.Fatalf("principal: %v, %d", err, len(recs))
	}

	// Agent.
	recs, _, _, err = e.ListCertsByAgentID("agent-c3.example.com", "", 0, nil)
	if err != nil || len(recs) != 1 {
		t.Fatalf("agent: %v, %d", err, len(recs))
	}
}

func TestCheckDuplicateCN(t *testing.T) {
	e := newTestEngine(t)
	rec := makeCert(1, "dup.example.com", time.Now().Add(30*24*time.Hour))
	if err := e.IssueCert(rec); err != nil {
		t.Fatal(err)
	}

	// Overlapping window → error.
	if err := e.CheckDuplicateCN("issuing", "dup.example.com",
		time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour)); err == nil {
		t.Fatal("expected duplicate CN error")
	}
	// Non-overlapping window → ok.
	if err := e.CheckDuplicateCN("issuing", "dup.example.com",
		time.Now().Add(90*24*time.Hour), time.Now().Add(120*24*time.Hour)); err != nil {
		t.Fatalf("unexpected duplicate CN error: %v", err)
	}
	// Revoked certs no longer count as active.
	if err := e.RevokeCert("issuing", "1", 3); err != nil {
		t.Fatal(err)
	}
	if err := e.CheckDuplicateCN("issuing", "dup.example.com", time.Now(), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("revoked cert should not block CN: %v", err)
	}
}

func TestRevokedSetCRLOrder(t *testing.T) {
	e := newTestEngine(t)
	for i := int64(1); i <= 3; i++ {
		if err := e.IssueCert(makeCert(i, fmt.Sprintf("crl%d.example.com", i), time.Time{})); err != nil {
			t.Fatal(err)
		}
	}
	// Revoke 1, then 2 → order should be [2, 1] (revoked_at desc).
	if err := e.RevokeCert("issuing", "1", 1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := e.RevokeCert("issuing", "2", 1); err != nil {
		t.Fatal(err)
	}

	entries, err := e.GetRevokedCertEntries("issuing")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].SerialNumber != "2" || entries[1].SerialNumber != "1" {
		t.Fatalf("unexpected CRL order: %+v", entries)
	}

	// Expired certs must not appear: revoke a soon-expiring cert.
	expired := makeCert(9, "soon-expiring.example.com", time.Now().Add(time.Hour))
	if err := e.IssueCert(expired); err != nil {
		t.Fatal(err)
	}
	if err := e.RevokeCert("issuing", "9", 1); err != nil {
		t.Fatal(err)
	}
	e.janitor() // prune now: cert not_after in 1h is still >= now → stays
	if entries, _ := e.GetRevokedCertEntries("issuing"); len(entries) != 3 {
		t.Fatalf("expected 3 revoked entries, got %d", len(entries))
	}
}

func TestNonceCAS(t *testing.T) {
	e := newTestEngine(t)
	nonce := []byte("0123456789abcdef")
	if err := e.StoreNonce(nonce); err != nil {
		t.Fatal(err)
	}
	if used, _ := e.IsNonceUsed(nonce); used {
		t.Fatal("fresh nonce should be unused")
	}

	var wg sync.WaitGroup
	successes := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			successes <- e.ConsumeNonce(nonce)
		}()
	}
	wg.Wait()
	close(successes)
	winners, alreadyUsed := 0, 0
	for err := range successes {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, db.ErrNonceAlreadyUsed):
			alreadyUsed++
		default:
			t.Fatalf("unexpected consume error: %v", err)
		}
	}
	if winners != 1 || alreadyUsed != 19 {
		t.Fatalf("expected 1 winner and 19 already-used, got %d/%d", winners, alreadyUsed)
	}
	if used, _ := e.IsNonceUsed(nonce); !used {
		t.Fatal("nonce should be used")
	}
}

func TestIssueCertIdempotentAndBackpressure(t *testing.T) {
	e := newTestEngine(t)
	rec := makeCert(1, "idem.example.com", time.Time{})
	if err := e.IssueCert(rec); err != nil {
		t.Fatal(err)
	}
	// Same fingerprint → idempotent.
	if err := e.IssueCert(rec); err != nil {
		t.Fatalf("idempotent re-issue failed: %v", err)
	}
	// Different fingerprint → duplicate.
	dup := *rec
	dup.CertDER = []byte("different-der")
	dup.Fingerprint = db.Fingerprint(dup.CertDER)
	if err := e.IssueCert(&dup); !errors.Is(err, db.ErrDuplicateSerial) {
		t.Fatalf("expected ErrDuplicateSerial, got %v", err)
	}

	// Backpressure when over the max.
	eng, err := NewEngine(e.DB(), EngineOptions{
		MaxCerts:        5,
		WriteMaxPending: 1,
		Logger:          discardLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()
	for i := int64(100); i < 110; i++ {
		r := makeCert(i, fmt.Sprintf("bp%d.example.com", i), time.Time{})
		if err := eng.IssueCert(r); err != nil && errors.Is(err, ErrBackpressure) {
			return // reached capacity, as expected
		}
	}
	t.Fatal("expected backpressure before reaching 10 certs with max 5")
}

func TestEngineRebuild(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Seed the backend directly.
	if err := d.InsertCert(makeCert(1, "seed.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	nonce := []byte("deadbeefdeadbeef")
	if err := d.StoreNonce(nonce); err != nil {
		t.Fatal(err)
	}

	e, err := NewEngine(d, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	st, err := e.GetCertStatus("issuing", "1")
	if err != nil {
		t.Fatalf("rebuild failed to load cert: %v", err)
	}
	if st.Status != "V" {
		t.Fatalf("expected V, got %q", st.Status)
	}
	if used, _ := e.IsNonceUsed(nonce); used {
		t.Fatal("loaded nonce should be unused")
	}
	if e.Loading() {
		t.Fatal("engine should be loaded")
	}
}

func TestEngineRebuildFullState(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	now := time.Now()

	// Valid cert.
	valid := makeCert(1, "valid.example.com", now.Add(365*24*time.Hour))
	if err := d.InsertCert(valid); err != nil {
		t.Fatal(err)
	}

	// Revoked cert (directly seeded backend, as a crashed restart would see).
	rev := makeCert(2, "revoked.example.com", now.Add(365*24*time.Hour))
	rev.Status = "R"
	ra := now.Add(-2 * time.Hour)
	reason := 4
	inv := now.Add(-time.Hour)
	rev.RevokedAt = &ra
	rev.RevokeReason = &reason
	rev.InvalidityDate = &inv
	if err := d.InsertCert(rev); err != nil {
		t.Fatal(err)
	}

	// Consumed nonce.
	nonce := []byte("deadbeefdeadbeef")
	if err := d.StoreNonce(nonce); err != nil {
		t.Fatal(err)
	}
	if err := d.ConsumeNonce(nonce); err != nil {
		t.Fatal(err)
	}

	// Sub-CA.
	if err := d.InsertSubCA(&db.SubCAMeta{
		Name: "sub-a", ParentCA: "issuing", Status: "active",
		CertDER: []byte("sub-der"), Subject: "CN=Sub A", KeyAlgorithm: "RSA",
	}); err != nil {
		t.Fatal(err)
	}

	// Trust anchor.
	if err := d.InsertTrustAnchor(&db.TrustAnchor{
		Name: "root-ta", HashID: "hash-root", CertDER: []byte("ta-der"),
		Subject: "CN=Root", NotBefore: now, NotAfter: now.Add(365 * 24 * time.Hour),
		Trusted: true, Source: "import",
	}); err != nil {
		t.Fatal(err)
	}
	seeded, err := d.ListTrustAnchors(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(seeded) != 1 {
		t.Fatalf("expected 1 seeded trust anchor, got %d", len(seeded))
	}
	taID := seeded[0].ID

	// AIC extension for the revoked cert's serial.
	if err := d.InsertAICExtension(&db.AICExtension{
		CAName: "issuing", SerialNumber: "2", AgentID: "agent-x",
		PrincipalUID: "uid-x", CapabilitiesJSON: `["admin"]`, AICJSON: `{"v":1}`,
	}); err != nil {
		t.Fatal(err)
	}

	e, err := NewEngine(d, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	if e.Loading() {
		t.Fatal("engine should be loaded after full rebuild")
	}

	// Valid cert loaded as V.
	st, err := e.GetCertStatus("issuing", "1")
	if err != nil {
		t.Fatalf("rebuild failed to load valid cert: %v", err)
	}
	if st.Status != "V" {
		t.Fatalf("expected V, got %q", st.Status)
	}

	// Revoked cert loaded as R and present in the CRL revoked set.
	st, err = e.GetCertStatus("issuing", "2")
	if err != nil {
		t.Fatalf("rebuild failed to load revoked cert: %v", err)
	}
	if st.Status != "R" {
		t.Fatalf("expected R, got %q", st.Status)
	}
	if e.revoked.Len() != 1 {
		t.Fatalf("expected 1 revoked entry, got %d", e.revoked.Len())
	}
	entries, err := e.GetRevokedCertEntries("issuing")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].SerialNumber != "2" {
		t.Fatalf("unexpected revoked entries: %+v", entries)
	}
	if entries[0].RevokeReason == nil || *entries[0].RevokeReason != 4 {
		t.Fatalf("revoke reason not loaded: %+v", entries[0].RevokeReason)
	}
	if entries[0].InvalidityDate == nil {
		t.Fatal("invalidity date not loaded")
	}

	// Consumed nonce loads as used.
	if used, _ := e.IsNonceUsed(nonce); !used {
		t.Fatal("consumed nonce should load as used")
	}

	// Sub-CA / trust anchor / AIC extension loaded.
	if sub, err := e.GetSubCA("sub-a"); err != nil || sub.ParentCA != "issuing" {
		t.Fatalf("sub-CA not loaded: %+v err=%v", sub, err)
	}
	if ta, err := e.GetTrustAnchor(taID); err != nil || !ta.Trusted {
		t.Fatalf("trust anchor not loaded: %+v err=%v", ta, err)
	}
	aic, err := e.GetAICExtensionByCert("issuing", "2")
	if err != nil || aic.AgentID != "agent-x" {
		t.Fatalf("AIC extension not loaded: %+v err=%v", aic, err)
	}
	if list, _ := e.ListAICExtensionsByAgentID("agent-x"); len(list) != 1 {
		t.Fatalf("AIC agent lookup returned %d, want 1", len(list))
	}
}

// TestEngineRebuildPaginated seeds more certificates than loadPageSize and
// verifies the paginated rebuild assembles the complete in-memory state,
// including the revoked set with revocation metadata.
func TestEngineRebuildPaginated(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	const total = 1100 // > loadPageSize, forces a second page
	now := time.Now()
	recs := make([]*db.CertRecord, 0, total)
	for i := 0; i < total; i++ {
		r := makeCert(int64(i), fmt.Sprintf("page%d.example.com", i), now.Add(365*24*time.Hour))
		if i%10 == 0 {
			r.Status = "R"
			ra := now.Add(-time.Duration(i) * time.Hour)
			r.RevokedAt = &ra
		}
		recs = append(recs, r)
	}
	if n, err := d.BulkInsertCertRecords(recs); err != nil || n != total {
		t.Fatalf("seed: n=%d err=%v", n, err)
	}

	e, err := NewEngine(d, EngineOptions{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	if e.Loading() {
		t.Fatal("engine should be loaded after paginated rebuild")
	}
	if e.certIdx.Len() != total {
		t.Fatalf("expected %d certs in index, got %d", total, e.certIdx.Len())
	}
	if e.revoked.Len() != total/10 {
		t.Fatalf("expected %d revoked entries, got %d", total/10, e.revoked.Len())
	}
	// Spot-check a revoked cert's metadata survived the bulk-insert round trip.
	st, err := e.GetCertStatus("issuing", fmt.Sprintf("%X", 90))
	if err != nil || st.Status != "R" {
		t.Fatalf("cert 90: status=%q err=%v", st.Status, err)
	}
	if st.RevokedAt == nil {
		t.Fatal("revoked_at lost in bulk-insert round trip")
	}
}

func TestJanitorPrunesExpired(t *testing.T) {
	e := newTestEngine(t)
	now := time.Now()
	// One expired (beyond grace) and one live cert.
	expired := makeCert(1, "expired.example.com", now.Add(-2*24*time.Hour))
	live := makeCert(2, "live.example.com", now.Add(30*24*time.Hour))
	if err := e.IssueCert(expired); err != nil {
		t.Fatal(err)
	}
	if err := e.IssueCert(live); err != nil {
		t.Fatal(err)
	}
	// Backend seed for a fresh-engine janitor check (janitor runs on existing engine).
	if _, err := e.GetCert("issuing", "1"); err != nil {
		t.Fatal(err)
	}

	e.janitor()

	if _, err := e.GetCert("issuing", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired cert should be evicted, got %v", err)
	}
	if _, err := e.GetCert("issuing", "2"); err != nil {
		t.Fatalf("live cert should remain: %v", err)
	}
	if m := e.Metrics(); m.WindowEvictions < 1 {
		t.Fatalf("expected eviction counter, got %d", m.WindowEvictions)
	}
}

func TestFlushAllConvergesBackend(t *testing.T) {
	e := newTestEngine(t)
	rec := makeCert(5, "flush.example.com", time.Time{})
	if err := e.IssueCert(rec); err != nil {
		t.Fatal(err)
	}
	nonce := []byte("0123456789abcdef")
	if err := e.StoreNonce(nonce); err != nil {
		t.Fatal(err)
	}
	if err := e.FlushAll(); err != nil {
		t.Fatal(err)
	}

	// Backend now has the cert and the nonce.
	if _, err := e.DB().GetCert("issuing", "5"); err != nil {
		t.Fatalf("cert not persisted: %v", err)
	}
	if used, err := e.DB().IsNonceUsed(nonce); err != nil || used {
		t.Fatalf("nonce not persisted cleanly: used=%v err=%v", used, err)
	}

	// Consume + flush → backend sees used.
	if err := e.ConsumeNonce(nonce); err != nil {
		t.Fatal(err)
	}
	if err := e.FlushAll(); err != nil {
		t.Fatal(err)
	}
	if used, err := e.DB().IsNonceUsed(nonce); err != nil || !used {
		t.Fatalf("nonce consume not persisted: used=%v err=%v", used, err)
	}
}

func TestSubCATrustAIC(t *testing.T) {
	e := newTestEngine(t)
	e.UpsertSubCA(&db.SubCAMeta{Name: "sub", ParentCA: "root", Status: "active"})
	e.UpsertTrustAnchor(&db.TrustAnchor{ID: 1, Name: "ta", Trusted: true})
	e.UpsertAICExtension(&db.AICExtension{
		CAName: "issuing", SerialNumber: "1", AgentID: "agent-1",
		PrincipalUID: "uid-1", CapabilitiesJSON: "[]", AICJSON: "{}",
	})

	if r, err := e.GetSubCA("sub"); err != nil || r.ParentCA != "root" {
		t.Fatalf("sub-ca: %v %v", r, err)
	}
	if r, err := e.GetTrustAnchor(1); err != nil || !r.Trusted {
		t.Fatalf("trust: %v %v", r, err)
	}
	if a, err := e.GetAICExtensionByCert("issuing", "1"); err != nil || a.AgentID != "agent-1" {
		t.Fatalf("aic: %v %v", a, err)
	}
}

func TestPrometheusMetrics(t *testing.T) {
	e := newTestEngine(t)
	if err := e.IssueCert(makeCert(1, "m.example.com", time.Time{})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.GetCertStatus("issuing", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.GetCertStatus("issuing", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	out := e.PrometheusMetrics()
	for _, want := range []string{"varwof_engine_certindex_size 1", "varwof_engine_read_hit_total 1", "varwof_engine_read_miss_total 1", "varwof_engine_cert_issued_total 1", "varwof_engine_wal_bytes 0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, out)
		}
	}
}

// TestIssueCertConcurrentSameKey verifies the get-or-put is atomic: when many
// goroutines race to issue the same (ca, serial) with different fingerprints,
// exactly one wins and the rest observe ErrDuplicateSerial.
func TestIssueCertConcurrentSameKey(t *testing.T) {
	e := newTestEngine(t)
	const n = 32
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := makeCert(1, fmt.Sprintf("race%d.example.com", i), time.Time{})
			rec.CertDER = []byte(fmt.Sprintf("der-%d", i))
			rec.Fingerprint = db.Fingerprint(rec.CertDER)
			results <- e.IssueCert(rec)
		}(i)
	}
	wg.Wait()
	close(results)
	winners, dupes := 0, 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, db.ErrDuplicateSerial):
			dupes++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if winners != 1 || dupes != n-1 {
		t.Fatalf("expected 1 winner and %d dupes, got %d/%d", n-1, winners, dupes)
	}
}

// TestBulkRevoke verifies RevokeCertsByPrincipalUid and RevokeCertsBySubCA
// mark the right certificates revoked in memory and populate the CRL set.
func TestBulkRevoke(t *testing.T) {
	e := newTestEngine(t)
	now := time.Now()
	for i := int64(1); i <= 4; i++ {
		rec := makeCert(i, fmt.Sprintf("bulk%d.example.com", i), now.Add(365*24*time.Hour))
		rec.PrincipalUid = "uid-bulk"
		if err := e.IssueCert(rec); err != nil {
			t.Fatal(err)
		}
	}
	// A second CA under a different principal, to isolate sub-CA revocation.
	other := makeCert(5, "bulk-other.example.com", now.Add(365*24*time.Hour))
	other.CAName = "other-ca"
	other.PrincipalUid = "uid-other-ca"
	if err := e.IssueCert(other); err != nil {
		t.Fatal(err)
	}

	n, err := e.RevokeCertsByPrincipalUid("uid-bulk", 4)
	if err != nil || n != 4 {
		t.Fatalf("principal bulk revoke: n=%d err=%v", n, err)
	}
	for i := int64(1); i <= 4; i++ {
		st, err := e.GetCertStatus("issuing", fmt.Sprintf("%X", i))
		if err != nil || st.Status != "R" {
			t.Fatalf("cert %X status after bulk revoke: %+v err=%v", i, st, err)
		}
	}
	entries, err := e.GetRevokedCertEntries("issuing")
	if err != nil || len(entries) != 4 {
		t.Fatalf("CRL entries after principal revoke: %d err=%v", len(entries), err)
	}

	// Sub-CA revoke now has nothing left for "issuing" but the "other-ca" cert.
	n, err = e.RevokeCertsBySubCA("other-ca", 1)
	if err != nil || n != 1 {
		t.Fatalf("sub-ca bulk revoke: n=%d err=%v", n, err)
	}
	st, err := e.GetCertStatus("other-ca", "5")
	if err != nil || st.Status != "R" {
		t.Fatalf("other-ca cert status: %+v err=%v", st, err)
	}
}

// TestConcurrentReadsDuringBulkRevoke stresses the revocation path against
// concurrent point reads. Correctness is asserted on statuses and counts; run
// with -race to detect unsynchronized field mutation (see bulkSetRevoked*).
func TestConcurrentReadsDuringBulkRevoke(t *testing.T) {
	e := newTestEngine(t)
	now := time.Now()
	const perCA = 200
	for ca := 0; ca < 2; ca++ {
		caName := fmt.Sprintf("ca-%d", ca)
		for i := 0; i < perCA; i++ {
			rec := makeCert(int64(ca*perCA+i+1), fmt.Sprintf("stress%d.example.com", i), now.Add(365*24*time.Hour))
			rec.CAName = caName
			rec.PrincipalUid = "uid-stress"
			if err := e.IssueCert(rec); err != nil {
				t.Fatal(err)
			}
		}
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					e.GetCertStatus(fmt.Sprintf("ca-%d", w%2),
						fmt.Sprintf("%X", w%2*perCA+1))
				}
			}
		}(w)
	}

	n, err := e.RevokeCertsByPrincipalUid("uid-stress", 1)
	if err != nil || n != perCA*2 {
		t.Fatalf("bulk revoke during reads: n=%d err=%v", n, err)
	}
	close(stop)
	wg.Wait()

	if entries, _ := e.GetRevokedCertEntries("ca-0"); len(entries) != perCA {
		t.Fatalf("ca-0 revoked entries: %d", len(entries))
	}
}

func TestListAICExtensionsByAgentAndUid(t *testing.T) {
	e := newTestEngine(t)
	e.UpsertAICExtension(&db.AICExtension{
		CAName: "issuing", SerialNumber: "1", AgentID: "agent-9",
		PrincipalUID: "uid-9", CapabilitiesJSON: "[]", AICJSON: "{}",
	})
	e.UpsertAICExtension(&db.AICExtension{
		CAName: "issuing", SerialNumber: "2", AgentID: "agent-9",
		PrincipalUID: "uid-other", CapabilitiesJSON: "[]", AICJSON: "{}",
	})

	byAgent, err := e.ListAICExtensionsByAgentID("agent-9")
	if err != nil || len(byAgent) != 2 {
		t.Fatalf("aic by agent: %d err=%v", len(byAgent), err)
	}
	byUid, err := e.ListAICExtensionsByPrincipalUid("uid-9")
	if err != nil || len(byUid) != 1 || byUid[0].SerialNumber != "1" {
		t.Fatalf("aic by uid: %d err=%v", len(byUid), err)
	}
}

func TestGetRevokedCertEntriesSince(t *testing.T) {
	e := newTestEngine(t)
	for _, s := range []int64{1, 2, 3} {
		if err := e.IssueCert(makeCert(s, fmt.Sprintf("d%d.example.com", s), time.Now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.RevokeCert("issuing", "1", 0); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(-time.Hour)
	after := time.Now().UTC().Add(time.Hour)

	// since=after → empty (revocation happened in the past)
	if entries, err := e.GetRevokedCertEntriesSince("issuing", after); err != nil || len(entries) != 0 {
		t.Fatalf("future since: %d err=%v", len(entries), err)
	}
	// since=before → includes serial 1
	entries, err := e.GetRevokedCertEntriesSince("issuing", before)
	if err != nil || len(entries) != 1 || entries[0].SerialNumber != "1" {
		t.Fatalf("past since: %+v err=%v", entries, err)
	}
	// zero value → full set (same as GetRevokedCertEntries)
	all, err := e.GetRevokedCertEntriesSince("issuing", time.Time{})
	if err != nil || len(all) != 1 {
		t.Fatalf("zero since: %d err=%v", len(all), err)
	}
}

func TestRevokeCertsBatch(t *testing.T) {
	e := newTestEngine(t)
	for i := int64(1); i <= 5; i++ {
		if err := e.IssueCert(makeCert(i, fmt.Sprintf("b%d.example.com", i), time.Now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	e.FlushAll()

	// Revoke serials 1,3,5 via batch. Serial 99 is not resident → reported miss.
	entries := []RevokeBatchEntry{
		{CA: "issuing", Serial: "1", Reason: 4},
		{CA: "issuing", Serial: "3", Reason: 4},
		{CA: "issuing", Serial: "5", Reason: 4},
		{CA: "issuing", Serial: "99", Reason: 4},
	}
	revoked, miss, err := e.RevokeCertsBatch(entries)
	if err != nil {
		t.Fatal(err)
	}
	if revoked != 3 {
		t.Fatalf("expected 3 revoked, got %d", revoked)
	}
	if len(miss) != 1 || miss[0].Serial != "99" {
		t.Fatalf("expected 1 miss (serial 99), got %+v", miss)
	}

	// Memory is truth immediately: statuses flipped.
	for _, s := range []string{"1", "3", "5"} {
		st, err := e.GetCertStatus("issuing", s)
		if err != nil || st.Status != "R" {
			t.Fatalf("serial %s status after batch = %+v err=%v", s, st, err)
		}
	}
	// Non-revoked serials untouched.
	for _, s := range []string{"2", "4"} {
		st, err := e.GetCertStatus("issuing", s)
		if err != nil || st.Status != "V" {
			t.Fatalf("serial %s should stay V, got %+v err=%v", s, st, err)
		}
	}

	// Revoked set reflects the batch.
	entries2, err := e.GetRevokedCertEntries("issuing")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries2) != 3 {
		t.Fatalf("revoked set size = %d, want 3", len(entries2))
	}

	// Re-batching an already-revoked cert is a no-op (no double count).
	revoked2, miss2, err := e.RevokeCertsBatch([]RevokeBatchEntry{{CA: "issuing", Serial: "1", Reason: 4}})
	if err != nil {
		t.Fatal(err)
	}
	if revoked2 != 0 || len(miss2) != 0 {
		t.Fatalf("re-revoke: revoked=%d miss=%v, want 0/0", revoked2, miss2)
	}

	// Empty batch.
	if n, m, err := e.RevokeCertsBatch(nil); err != nil || n != 0 || len(m) != 0 {
		t.Fatalf("empty batch: n=%d m=%v err=%v", n, m, err)
	}
}

func TestRevokeCertsBatchConcurrent(t *testing.T) {
	e := newTestEngine(t)
	const n = 200
	for i := int64(1); i <= n; i++ {
		if err := e.IssueCert(makeCert(i, fmt.Sprintf("cc%d.example.com", i), time.Now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	e.FlushAll()

	// Concurrent batch revokes across disjoint serial ranges.
	var wg sync.WaitGroup
	results := make([]int, 4)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			var entries []RevokeBatchEntry
			for i := 1 + g*n/4; i <= (g+1)*n/4; i++ {
				entries = append(entries, RevokeBatchEntry{CA: "issuing", Serial: fmt.Sprintf("%X", i), Reason: 1})
			}
			revoked, _, err := e.RevokeCertsBatch(entries)
			if err != nil {
				t.Errorf("batch %d: %v", g, err)
			}
			results[g] = revoked
		}(g)
	}
	wg.Wait()

	total := 0
	for _, r := range results {
		total += r
	}
	if total != n {
		t.Fatalf("concurrent batch revoked %d, want %d", total, n)
	}
}
