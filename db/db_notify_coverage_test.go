// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
	"time"
)

func TestNotifyCertRevokedCallback(t *testing.T) {
	d := newTestDB(t)

	var called []string
	prev := OnCertRevoked
	OnCertRevoked = func(serial string) {
		called = append(called, serial)
	}
	defer func() { OnCertRevoked = prev }()

	if err := d.InsertCert(&CertRecord{
		SerialNumber: "00000000000000000000000000000000000000A1",
		CAName:       "test-ca", Status: "V",
		CommonName: "alice", NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), CertDER: []byte("der"),
		PrincipalUid: "varwof:alice@varwof.com:abc",
	}); err != nil {
		t.Fatal(err)
	}

	// bulk revoke by principal uid triggers notifyCertRevoked("")
	n, err := d.RevokeCertsByPrincipalUid("varwof:alice@varwof.com:abc", 1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 revoked, got %d", n)
	}
	if len(called) != 1 || called[0] != "" {
		t.Fatalf("expected single bulk callback, got %v", called)
	}

	// no matching rows → no callback
	d.RevokeCertsBySubCA("test-ca", 1)
	if len(called) != 1 {
		t.Fatalf("expected no additional callback, got %v", called)
	}
}
