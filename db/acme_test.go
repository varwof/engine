// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

func TestUpdateAcmeOrderFinalize(t *testing.T) {
	d := newTestDB(t)
	acctID, err := d.InsertAcmeAccount("thumb1", `{"kty":"EC"}`, "admin@example.com", "valid")
	if err != nil {
		t.Fatal(err)
	}

	orderID, err := d.InsertAcmeOrder(acctID, `[{"type":"dns","value":"example.com"}]`, "20991231T000000Z")
	if err != nil {
		t.Fatal(err)
	}

	if err := d.UpdateAcmeOrderFinalize(orderID, "processing"); err != nil {
		t.Fatalf("UpdateAcmeOrderFinalize: %v", err)
	}

	order, err := d.GetAcmeOrder(orderID)
	if err != nil {
		t.Fatal(err)
	}
	if order.Status != "processing" {
		t.Fatalf("expected status processing, got %q", order.Status)
	}
}

func TestUpdateAcmeOrderFinalizeTwice(t *testing.T) {
	d := newTestDB(t)
	acctID, _ := d.InsertAcmeAccount("thumb2", `{}`, "a@b.com", "valid")
	orderID, _ := d.InsertAcmeOrder(acctID, `[]`, "20991231T000000Z")

	if err := d.UpdateAcmeOrderFinalize(orderID, "processing"); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateAcmeOrderFinalize(orderID, "valid"); err != nil {
		t.Fatalf("UpdateAcmeOrderFinalize twice: %v", err)
	}
}

func TestUpdateAcmeChallenge(t *testing.T) {
	d := newTestDB(t)
	acctID, _ := d.InsertAcmeAccount("thumb3", `{}`, "x@y.com", "valid")
	orderID, _ := d.InsertAcmeOrder(acctID, `[]`, "20991231T000000Z")
	authzID, err := d.InsertAcmeAuthorization(orderID, "dns", "example.com", "tok1", "20991231T000000Z")
	if err != nil {
		t.Fatal(err)
	}

	challID, err := d.InsertAcmeChallenge(authzID, "http-01", "tok1")
	if err != nil {
		t.Fatal(err)
	}

	now := "2026-06-19T00:00:00Z"
	if err := d.UpdateAcmeChallenge(challID, "valid", &now); err != nil {
		t.Fatalf("UpdateAcmeChallenge: %v", err)
	}

	chall, err := d.GetAcmeChallenge(challID)
	if err != nil {
		t.Fatal(err)
	}
	if chall.Status != "valid" {
		t.Fatalf("expected status valid, got %q", chall.Status)
	}
	if chall.ValidatedAt == nil || *chall.ValidatedAt != now {
		t.Fatalf("expected validated_at %q, got %v", now, chall.ValidatedAt)
	}
}

func TestUpdateAcmeChallengeNilValidatedAt(t *testing.T) {
	d := newTestDB(t)
	acctID, _ := d.InsertAcmeAccount("thumb4", `{}`, "a@b.com", "valid")
	orderID, _ := d.InsertAcmeOrder(acctID, `[]`, "20991231T000000Z")
	authzID, _ := d.InsertAcmeAuthorization(orderID, "dns", "x.com", "tok2", "20991231T000000Z")
	challID, _ := d.InsertAcmeChallenge(authzID, "http-01", "tok2")

	if err := d.UpdateAcmeChallenge(challID, "invalid", nil); err != nil {
		t.Fatalf("UpdateAcmeChallenge nil validated_at: %v", err)
	}
}

func TestGetAcmeAccountByThumbprint(t *testing.T) {
	d := newTestDB(t)
	id, err := d.InsertAcmeAccount("thumb1", `{"kty":"EC"}`, "admin@example.com", "valid")
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}

	acct, err := d.GetAcmeAccountByThumbprint("thumb1")
	if err != nil {
		t.Fatal(err)
	}
	if acct == nil {
		t.Fatal("expected non-nil account")
	}
	if acct.JWKThumbprint != "thumb1" {
		t.Fatalf("expected thumb1, got %q", acct.JWKThumbprint)
	}
	if acct.Contact != "admin@example.com" {
		t.Fatalf("expected admin@example.com, got %q", acct.Contact)
	}

	// Non-existent thumbprint → nil, nil
	acct, err = d.GetAcmeAccountByThumbprint("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if acct != nil {
		t.Fatal("expected nil account for nonexistent thumbprint")
	}
}

func TestGetAcmeAccountByID(t *testing.T) {
	d := newTestDB(t)
	id, err := d.InsertAcmeAccount("thumb2", `{}`, "user@example.com", "valid")
	if err != nil {
		t.Fatal(err)
	}

	acct, err := d.GetAcmeAccountByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if acct == nil {
		t.Fatal("expected non-nil account")
	}
	if acct.Contact != "user@example.com" {
		t.Fatalf("expected user@example.com, got %q", acct.Contact)
	}
	if acct.JWKThumbprint != "thumb2" {
		t.Fatalf("expected thumb2, got %q", acct.JWKThumbprint)
	}

	// Non-existent ID → nil, nil
	acct, err = d.GetAcmeAccountByID(99999)
	if err != nil {
		t.Fatal(err)
	}
	if acct != nil {
		t.Fatal("expected nil account for nonexistent ID")
	}
}

func TestUpdateAcmeAccount(t *testing.T) {
	d := newTestDB(t)
	id, err := d.InsertAcmeAccount("thumb3", `{}`, "old@contact.com", "valid")
	if err != nil {
		t.Fatal(err)
	}

	if err := d.UpdateAcmeAccount(id, "new@contact.com", "deactivated"); err != nil {
		t.Fatalf("UpdateAcmeAccount: %v", err)
	}

	acct, err := d.GetAcmeAccountByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if acct == nil {
		t.Fatal("expected non-nil account")
	}
	if acct.Status != "deactivated" {
		t.Fatalf("expected deactivated, got %q", acct.Status)
	}
	if acct.Contact != "new@contact.com" {
		t.Fatalf("expected new@contact.com, got %q", acct.Contact)
	}
}

func TestUpdateAcmeAccountKey(t *testing.T) {
	d := newTestDB(t)
	id, err := d.InsertAcmeAccount("old-thumb", `{"kty":"EC"}`, "test@test.com", "valid")
	if err != nil {
		t.Fatal(err)
	}

	if err := d.UpdateAcmeAccountKey(id, "new-thumb", `{"kty":"RSA"}`); err != nil {
		t.Fatalf("UpdateAcmeAccountKey: %v", err)
	}

	acct, err := d.GetAcmeAccountByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if acct == nil {
		t.Fatal("expected non-nil account")
	}
	if acct.JWKThumbprint != "new-thumb" {
		t.Fatalf("expected new-thumb, got %q", acct.JWKThumbprint)
	}
	if acct.JWKJSON != `{"kty":"RSA"}` {
		t.Fatalf("expected {\"kty\":\"RSA\"}, got %q", acct.JWKJSON)
	}
}

func TestAcmeAuthorizationCRUD(t *testing.T) {
	d := newTestDB(t)

	// 1. Insert account
	acctID, err := d.InsertAcmeAccount("thumb-crud", `{}`, "crud@test.com", "valid")
	if err != nil {
		t.Fatal(err)
	}

	// 2. Insert order
	orderID, err := d.InsertAcmeOrder(acctID, `[{"type":"dns","value":"example.com"}]`, "20991231T000000Z")
	if err != nil {
		t.Fatal(err)
	}

	// 3. Insert 2 authorizations
	authz1ID, err := d.InsertAcmeAuthorization(orderID, "dns", "example.com", "tok-authz1", "20991231T000000Z")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.InsertAcmeAuthorization(orderID, "dns", "other.com", "tok-authz2", "20991231T000000Z")
	if err != nil {
		t.Fatal(err)
	}

	// 4. GetAcmeAuthorizationsByOrder → 2 results
	authzs, err := d.GetAcmeAuthorizationsByOrder(orderID)
	if err != nil {
		t.Fatal(err)
	}
	if len(authzs) != 2 {
		t.Fatalf("expected 2 authorizations, got %d", len(authzs))
	}

	// 5. GetAcmeAuthorization(first) → matches
	a1, err := d.GetAcmeAuthorization(authz1ID)
	if err != nil {
		t.Fatal(err)
	}
	if a1 == nil {
		t.Fatal("expected non-nil authz")
	}
	if a1.IdentifierValue != "example.com" {
		t.Fatalf("expected example.com, got %q", a1.IdentifierValue)
	}

	// 6. GetAcmeAuthorization(99999) → nil, nil
	aMissing, err := d.GetAcmeAuthorization(99999)
	if err != nil {
		t.Fatal(err)
	}
	if aMissing != nil {
		t.Fatal("expected nil for nonexistent authz")
	}

	// 7. UpdateAcmeAuthzStatus(first, "valid") → success
	if err := d.UpdateAcmeAuthzStatus(authz1ID, "valid"); err != nil {
		t.Fatalf("UpdateAcmeAuthzStatus: %v", err)
	}

	// 8. Verify status changed
	a1Updated, err := d.GetAcmeAuthorization(authz1ID)
	if err != nil {
		t.Fatal(err)
	}
	if a1Updated.Status != "valid" {
		t.Fatalf("expected valid, got %q", a1Updated.Status)
	}

	// 9. Insert challenge for authz
	challID, err := d.InsertAcmeChallenge(authz1ID, "http-01", "chall-token")
	if err != nil {
		t.Fatal(err)
	}
	if challID == 0 {
		t.Fatal("expected non-zero challenge id")
	}

	// 10. GetAcmeChallengesByAuthz(authzID) → 1 challenge
	challs, err := d.GetAcmeChallengesByAuthz(authz1ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(challs) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(challs))
	}
	if challs[0].Token != "chall-token" {
		t.Fatalf("expected chall-token, got %q", challs[0].Token)
	}

	// 11. InsertAcmeCertOrder(orderID, certDER, serial, caName)
	certOrderID, err := d.InsertAcmeCertOrder(orderID, []byte("DER"), "01", "test-ca")
	if err != nil {
		t.Fatalf("InsertAcmeCertOrder: %v", err)
	}
	if certOrderID == 0 {
		t.Fatal("expected non-zero cert_order id")
	}

	// 12. GetAcmeCertOrder(orderID) → matches serial and ca_name
	co, err := d.GetAcmeCertOrder(orderID)
	if err != nil {
		t.Fatal(err)
	}
	if co == nil {
		t.Fatal("expected non-nil cert order")
	}
	if co.SerialNumber != "01" {
		t.Fatalf("expected serial 01, got %q", co.SerialNumber)
	}
	if co.CAName != "test-ca" {
		t.Fatalf("expected ca test-ca, got %q", co.CAName)
	}

	// 13. GetAcmeCertOrder(99999) → nil, nil
	coMissing, err := d.GetAcmeCertOrder(99999)
	if err != nil {
		t.Fatal(err)
	}
	if coMissing != nil {
		t.Fatal("expected nil for nonexistent cert order")
	}
}

func TestAcmeCertOrderByHash(t *testing.T) {
	d := newTestDB(t)
	accID, err := d.InsertAcmeAccount("tp", "{}", "mailto:x@y.z", "valid")
	if err != nil {
		t.Fatal(err)
	}
	orderID, err := d.InsertAcmeOrder(accID, "dns:example.com", time.Now().Add(time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}

	der := []byte("some-certificate-der-bytes")
	expectedHash := fmt.Sprintf("%x", sha256.Sum256(der))
	if _, err := d.InsertAcmeCertOrder(orderID, der, "ABCDEF", "test-ca"); err != nil {
		t.Fatalf("InsertAcmeCertOrder: %v", err)
	}

	co, err := d.GetAcmeCertOrderByCertHash(expectedHash)
	if err != nil {
		t.Fatal(err)
	}
	if co == nil {
		t.Fatal("expected cert order for known hash")
	}
	if co.CertSHA256 != expectedHash {
		t.Fatalf("expected stored hash %q, got %q", expectedHash, co.CertSHA256)
	}
	if string(co.CertDER) != string(der) {
		t.Fatal("cert DER mismatch")
	}

	miss, err := d.GetAcmeCertOrderByCertHash("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if miss != nil {
		t.Fatal("expected nil for unknown hash")
	}
}

func TestSchemaMigrationV18AddsCertHashColumn(t *testing.T) {
	d := newTestDB(t)
	// The cert_sha256 column must exist and accept inserts with a hash.
	accID, err := d.InsertAcmeAccount("tp-mig", "{}", "mailto:mig@y.z", "valid")
	if err != nil {
		t.Fatal(err)
	}
	orderID, err := d.InsertAcmeOrder(accID, "dns:mig.example.com", time.Now().Add(time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.InsertAcmeCertOrder(orderID, []byte("der"), "S", "ca"); err != nil {
		t.Fatalf("insert after migration: %v", err)
	}
}
