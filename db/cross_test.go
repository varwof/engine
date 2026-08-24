// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"os"
	"testing"
	"time"
)

func openTestDB(t *testing.T) (*DB, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "cross-db-test")
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(tmpDir + "/test.db")
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("open db: %v", err)
	}
	return d, func() {
		d.Close()
		os.RemoveAll(tmpDir)
	}
}

func TestInsertAndGetCrossCert(t *testing.T) {
	d, cleanup := openTestDB(t)
	defer cleanup()

	record := &CrossCertRecord{
		IssuerCA:     "issuer",
		SubjectCA:    "target",
		CertDER:      []byte("fake-der"),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SerialNumber: "0000000000000000000000000000000000000001",
		Fingerprint:  "abc123",
		Status:       "V",
	}

	if err := d.InsertCrossCert(record); err != nil {
		t.Fatalf("InsertCrossCert: %v", err)
	}

	got, err := d.GetCrossCert("issuer", "0000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("GetCrossCert: %v", err)
	}
	if got.IssuerCA != "issuer" {
		t.Fatalf("expected issuer=issuer, got %s", got.IssuerCA)
	}
	if got.SubjectCA != "target" {
		t.Fatalf("expected subjectCA=target, got %s", got.SubjectCA)
	}
	if got.Status != "V" {
		t.Fatalf("expected status=V, got %s", got.Status)
	}
}

func TestGetCrossCertNotFound(t *testing.T) {
	d, cleanup := openTestDB(t)
	defer cleanup()

	_, err := d.GetCrossCert("nonexistent", "0000000000000000000000000000000000000001")
	if err == nil {
		t.Fatal("expected error for nonexistent cross cert")
	}
}

func TestListCrossCerts(t *testing.T) {
	d, cleanup := openTestDB(t)
	defer cleanup()

	recs := []*CrossCertRecord{
		{IssuerCA: "issuer", SubjectCA: "target1", CertDER: []byte("der1"), NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour), SerialNumber: "0000000000000000000000000000000000000001", Fingerprint: "fp1", Status: "V"},
		{IssuerCA: "issuer", SubjectCA: "target2", CertDER: []byte("der2"), NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour), SerialNumber: "0000000000000000000000000000000000000002", Fingerprint: "fp2", Status: "V"},
		{IssuerCA: "other", SubjectCA: "target3", CertDER: []byte("der3"), NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour), SerialNumber: "0000000000000000000000000000000000000003", Fingerprint: "fp3", Status: "V"},
	}
	for _, r := range recs {
		if err := d.InsertCrossCert(r); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	got, err := d.ListCrossCerts("issuer")
	if err != nil {
		t.Fatalf("ListCrossCerts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}

	all, err := d.ListCrossCertsAll()
	if err != nil {
		t.Fatalf("ListCrossCertsAll: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3, got %d", len(all))
	}
}

func TestRevokeCrossCert(t *testing.T) {
	d, cleanup := openTestDB(t)
	defer cleanup()

	record := &CrossCertRecord{
		IssuerCA:     "issuer",
		SubjectCA:    "target",
		CertDER:      []byte("der"),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SerialNumber: "0000000000000000000000000000000000000001",
		Fingerprint:  "fp",
		Status:       "V",
	}
	if err := d.InsertCrossCert(record); err != nil {
		t.Fatal(err)
	}

	if err := d.RevokeCrossCert("issuer", "0000000000000000000000000000000000000001", 1); err != nil {
		t.Fatalf("RevokeCrossCert: %v", err)
	}

	got, err := d.GetCrossCert("issuer", "0000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "R" {
		t.Fatalf("expected status=R, got %s", got.Status)
	}
	if got.RevokedAt == nil {
		t.Fatal("expected RevokedAt to be set")
	}
	if *got.RevokeReason != 1 {
		t.Fatalf("expected reason=1, got %d", *got.RevokeReason)
	}
}

func TestRevokeCrossCertNotFound(t *testing.T) {
	d, cleanup := openTestDB(t)
	defer cleanup()

	err := d.RevokeCrossCert("issuer", "nonexistent", 0)
	if err == nil {
		t.Fatal("expected error for nonexistent cross cert")
	}
}

func TestGetRevokedCrossCerts(t *testing.T) {
	d, cleanup := openTestDB(t)
	defer cleanup()

	record := &CrossCertRecord{
		IssuerCA:     "issuer",
		SubjectCA:    "target",
		CertDER:      []byte("der"),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SerialNumber: "0000000000000000000000000000000000000001",
		Fingerprint:  "fp",
		Status:       "V",
	}
	if err := d.InsertCrossCert(record); err != nil {
		t.Fatal(err)
	}
	d.RevokeCrossCert("issuer", "0000000000000000000000000000000000000001", 1)

	revoked, err := d.GetRevokedCrossCerts("issuer")
	if err != nil {
		t.Fatalf("GetRevokedCrossCerts: %v", err)
	}
	if len(revoked) != 1 {
		t.Fatalf("expected 1 revoked, got %d", len(revoked))
	}
	if revoked[0].SerialNumber != "0000000000000000000000000000000000000001" {
		t.Fatalf("unexpected serial: %s", revoked[0].SerialNumber)
	}
}

func TestCrossCertSchemaVersion(t *testing.T) {
	// cross_certs is part of the base schema (v1). Verify it exists.
	d, cleanup := openTestDB(t)
	defer cleanup()
	var name string
	err := d.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='cross_certs'").Scan(&name)
	if err != nil || name != "cross_certs" {
		t.Fatalf("cross_certs table missing: %v", err)
	}
}

func TestCrossCertCRLIntegration(t *testing.T) {
	d, cleanup := openTestDB(t)
	defer cleanup()

	record := &CrossCertRecord{
		IssuerCA:     "crl-issuer",
		SubjectCA:    "crl-target",
		CertDER:      []byte("crl-der"),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SerialNumber: "00000000000000000000000000000000000000FF",
		Fingerprint:  "crl-fp",
		Status:       "V",
	}
	if err := d.InsertCrossCert(record); err != nil {
		t.Fatal(err)
	}

	reason := 2
	d.RevokeCrossCert("crl-issuer", "00000000000000000000000000000000000000FF", reason)

	revoked, err := d.GetRevokedCrossCerts("crl-issuer")
	if err != nil {
		t.Fatalf("GetRevokedCrossCerts: %v", err)
	}
	if len(revoked) != 1 {
		t.Fatalf("expected 1, got %d", len(revoked))
	}
	cr := revoked[0]
	if cr.CAName != "crl-issuer" {
		t.Fatalf("expected CAName=crl-issuer, got %s", cr.CAName)
	}
	if cr.RevokeReason == nil || *cr.RevokeReason != reason {
		t.Fatalf("expected reason %d, got %v", reason, cr.RevokeReason)
	}
}
