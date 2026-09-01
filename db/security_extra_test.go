// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"strings"
	"testing"
	"time"
)

// TestListRevokedCertRefsSince verifies the out-of-band revocation sync query:
// revoked rows are returned with reason/timestamp, non-revoked rows are not,
// and the `since` filter is honored (finding 7 backend half).
func TestListRevokedCertRefsSince(t *testing.T) {
	d := newTestDB(t)

	rec := makeTestCert(t, 1, "oob.example.com")
	if err := d.InsertCert(rec); err != nil {
		t.Fatal(err)
	}
	rec2 := makeTestCert(t, 2, "still-valid.example.com")
	if err := d.InsertCert(rec2); err != nil {
		t.Fatal(err)
	}

	// Revoke only the first certificate (reason 2 = keyCompromise).
	if err := d.RevokeCert("issuing", "1", 2); err != nil {
		t.Fatal(err)
	}

	before := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	refs, err := d.ListRevokedCertRefsSince(before)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 {
		t.Fatalf("want exactly 1 revoked ref, got %d", len(refs))
	}
	ref := refs[0]
	if ref.CAName != "issuing" || ref.SerialNumber != "1" {
		t.Fatalf("unexpected ref %+v", ref)
	}
	if ref.RevokeReason == nil || *ref.RevokeReason != 2 {
		t.Fatalf("want reason 2, got %+v", ref.RevokeReason)
	}
	if ref.RevokedAt.IsZero() {
		t.Fatal("expected revoked_at to be parsed")
	}

	// Future `since` must return nothing.
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if refs, err = d.ListRevokedCertRefsSince(future); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("future since: want 0 refs, got %d", len(refs))
	}
}

// TestAcmeTokenEncryptedAtRest verifies ACME challenge tokens are encrypted at
// rest (finding 11): the stored column must not contain the plaintext token,
// and reads must return the decrypted value.
func TestAcmeTokenEncryptedAtRest(t *testing.T) {
	d := newTestDB(t)
	if err := d.SetAtRestKey(strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	acctID, err := d.InsertAcmeAccount("thumb-e1", `{"kty":"EC"}`, "a@b.com", "valid")
	if err != nil {
		t.Fatal(err)
	}
	orderID, err := d.InsertAcmeOrder(acctID, `[]`, "20991231T000000Z")
	if err != nil {
		t.Fatal(err)
	}
	authzID, err := d.InsertAcmeAuthorization(orderID, "dns", "example.com", "tok-authz", "20991231T000000Z")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "super-secret-challenge-token"
	challID, err := d.InsertAcmeChallenge(authzID, "http-01", secret)
	if err != nil {
		t.Fatal(err)
	}

	// Raw row: stored value must not be the plaintext.
	var stored string
	if err := d.QueryRow("SELECT token FROM acme_challenges WHERE id = ?", challID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == secret {
		t.Fatal("ACME token stored in plaintext at rest")
	}
	if stored == "" {
		t.Fatal("stored token unexpectedly empty")
	}

	// Read path returns the decrypted token.
	ch, err := d.GetAcmeChallenge(challID)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Token != secret {
		t.Fatalf("GetAcmeChallenge token = %q, want %q", ch.Token, secret)
	}
}

// TestAcmeTokenWrongKeyFails verifies that reading a challenge with the wrong
// at-rest key fails closed instead of returning garbage or plaintext.
func TestAcmeTokenWrongKeyFails(t *testing.T) {
	d := newTestDB(t)
	if err := d.SetAtRestKey(strings.Repeat("cd", 32)); err != nil {
		t.Fatal(err)
	}
	acctID, _ := d.InsertAcmeAccount("thumb-e2", `{}`, "c@d.com", "valid")
	orderID, _ := d.InsertAcmeOrder(acctID, `[]`, "20991231T000000Z")
	authzID, _ := d.InsertAcmeAuthorization(orderID, "dns", "example.com", "tok", "20991231T000000Z")
	challID, err := d.InsertAcmeChallenge(authzID, "http-01", "secret-token")
	if err != nil {
		t.Fatal(err)
	}

	// Rotate the key in memory (simulating a config change with a different key).
	if err := d.SetAtRestKey(strings.Repeat("ef", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetAcmeChallenge(challID); err == nil {
		t.Fatal("expected decrypt error with wrong at-rest key")
	}
}
