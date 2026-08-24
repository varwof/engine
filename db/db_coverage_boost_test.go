// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"fmt"
	"testing"
	"time"
)

// ---------- trust_anchor.go ----------

func TestInsertTrustAnchor(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	rec := &TrustAnchor{
		Name:            "Test Root",
		HashID:          "hash123",
		CertDER:         []byte{0x30, 0x82, 0x01, 0x22},
		Subject:         "CN=Test Root",
		NotBefore:       now,
		NotAfter:        now.Add(10 * 365 * 24 * time.Hour),
		Issuer:          "CN=Test Root",
		Trusted:         true,
		Source:          "import",
		SubjectO:        "TestOrg",
		SubjectC:        "CN",
		KeyAlgo:         "ECDSA",
		KeySize:         256,
		SHA1Fingerprint: "aa:bb:cc",
		PathLen:         0,
	}
	if err := d.InsertTrustAnchor(rec); err != nil {
		t.Fatalf("InsertTrustAnchor: %v", err)
	}
}

func TestInsertAndDeleteTrustAnchor(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	rec := &TrustAnchor{
		Name:      "Delete Me",
		HashID:    "del-hash",
		CertDER:   []byte{0x30},
		Subject:   "CN=Delete Me",
		NotBefore: now, NotAfter: now.Add(time.Hour),
		Issuer: "CN=Delete Me", Source: "test",
	}
	if err := d.InsertTrustAnchor(rec); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteTrustAnchor("del-hash"); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetTrustAnchor("del-hash")
	if err == nil && got != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestDeleteTrustAnchorsBySource(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	for i := 0; i < 3; i++ {
		d.InsertTrustAnchor(&TrustAnchor{
			Name: fmt.Sprintf("ta%d", i), HashID: fmt.Sprintf("src-%d", i),
			CertDER: []byte{0x30}, Subject: fmt.Sprintf("CN=ta%d", i),
			NotBefore: now, NotAfter: now.Add(time.Hour),
			Issuer: "CN=root", Source: "bulk-import",
		})
	}
	if err := d.DeleteTrustAnchorsBySource("bulk-import"); err != nil {
		t.Fatal(err)
	}
	tas, _ := d.ListTrustAnchors(nil)
	if len(tas) != 0 {
		t.Fatalf("expected 0 after delete by source, got %d", len(tas))
	}
}

func TestListTrustAnchors_All(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	for i := 0; i < 5; i++ {
		d.InsertTrustAnchor(&TrustAnchor{
			Name: fmt.Sprintf("Anchor%d", i), HashID: fmt.Sprintf("hash-%d", i),
			CertDER: []byte{0x30}, Subject: fmt.Sprintf("CN=Anchor%d", i),
			NotBefore: now, NotAfter: now.Add(time.Hour),
			Issuer: "CN=root", Source: "test",
			Trusted: i%2 == 0, SubjectO: "OrgA", SubjectC: "US", KeyAlgo: "RSA",
		})
	}
	tas, err := d.ListTrustAnchors(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tas) != 5 {
		t.Fatalf("expected 5, got %d", len(tas))
	}
}

func TestListTrustAnchors_FilterTrusted(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	trusted := true
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "Trusted", HashID: "t1", CertDER: []byte{0x30},
		Subject: "CN=Trusted", NotBefore: now, NotAfter: now.Add(time.Hour),
		Issuer: "CN=root", Trusted: true, Source: "test",
	})
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "Untrusted", HashID: "u1", CertDER: []byte{0x30},
		Subject: "CN=Untrusted", NotBefore: now, NotAfter: now.Add(time.Hour),
		Issuer: "CN=root", Trusted: false, Source: "test",
	})
	tas, err := d.ListTrustAnchors(&TrustAnchorFilter{Trusted: &trusted})
	if err != nil {
		t.Fatal(err)
	}
	if len(tas) != 1 {
		t.Fatalf("expected 1 trusted, got %d", len(tas))
	}
	if tas[0].HashID != "t1" {
		t.Fatalf("expected t1, got %s", tas[0].HashID)
	}
}

func TestListTrustAnchors_FilterSource(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "A", HashID: "a1", CertDER: []byte{0x30}, Subject: "CN=A",
		NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "srcA",
	})
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "B", HashID: "b1", CertDER: []byte{0x30}, Subject: "CN=B",
		NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "srcB",
	})
	tas, _ := d.ListTrustAnchors(&TrustAnchorFilter{Source: "srcA"})
	if len(tas) != 1 || tas[0].HashID != "a1" {
		t.Fatalf("expected 1 result a1, got %d", len(tas))
	}
}

func TestListTrustAnchors_FilterHashID(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "X", HashID: "x1", CertDER: []byte{0x30}, Subject: "CN=X",
		NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test",
	})
	tas, _ := d.ListTrustAnchors(&TrustAnchorFilter{HashID: "x1"})
	if len(tas) != 1 || tas[0].Name != "X" {
		t.Fatalf("expected X, got %+v", tas)
	}
}

func TestListTrustAnchors_FilterSubjectO(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "O1", HashID: "o1", CertDER: []byte{0x30}, Subject: "CN=O1",
		NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test",
		SubjectO: "Acme Corp",
	})
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "O2", HashID: "o2", CertDER: []byte{0x30}, Subject: "CN=O2",
		NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test",
		SubjectO: "Other Inc",
	})
	tas, _ := d.ListTrustAnchors(&TrustAnchorFilter{SubjectO: "Acme"})
	if len(tas) != 1 {
		t.Fatalf("expected 1, got %d", len(tas))
	}
}

func TestListTrustAnchors_FilterSubjectC(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "C1", HashID: "c1", CertDER: []byte{0x30}, Subject: "CN=C1",
		NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test",
		SubjectC: "US",
	})
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "C2", HashID: "c2", CertDER: []byte{0x30}, Subject: "CN=C2",
		NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test",
		SubjectC: "CN",
	})
	tas, _ := d.ListTrustAnchors(&TrustAnchorFilter{SubjectC: "US"})
	if len(tas) != 1 {
		t.Fatalf("expected 1, got %d", len(tas))
	}
}

func TestListTrustAnchors_FilterKeyAlgo(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "K1", HashID: "k1", CertDER: []byte{0x30}, Subject: "CN=K1",
		NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test",
		KeyAlgo: "RSA",
	})
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "K2", HashID: "k2", CertDER: []byte{0x30}, Subject: "CN=K2",
		NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test",
		KeyAlgo: "ECDSA",
	})
	tas, _ := d.ListTrustAnchors(&TrustAnchorFilter{KeyAlgo: "ECDSA"})
	if len(tas) != 1 {
		t.Fatalf("expected 1, got %d", len(tas))
	}
}

func TestListTrustAnchors_Pagination(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	for i := 0; i < 10; i++ {
		d.InsertTrustAnchor(&TrustAnchor{
			Name: fmt.Sprintf("P%d", i), HashID: fmt.Sprintf("pg-%d", i),
			CertDER: []byte{0x30}, Subject: fmt.Sprintf("CN=P%d", i),
			NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test",
		})
	}
	tas, _ := d.ListTrustAnchors(&TrustAnchorFilter{Page: 2, Size: 3})
	if len(tas) != 3 {
		t.Fatalf("expected 3 on page 2, got %d", len(tas))
	}
	tas1, _ := d.ListTrustAnchors(&TrustAnchorFilter{Page: 1, Size: 3})
	if len(tas1) != 3 {
		t.Fatalf("expected 3 on page 1, got %d", len(tas1))
	}
}

func TestGetTrustAnchor(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "GetMe", HashID: "get-me", CertDER: []byte{0x30, 0x01},
		Subject: "CN=GetMe", NotBefore: now, NotAfter: now.Add(time.Hour),
		Issuer: "CN=root", Trusted: true, Source: "test",
		SubjectO: "Org", SubjectC: "US", KeyAlgo: "RSA", KeySize: 2048,
		SHA1Fingerprint: "ff:00", PathLen: 1,
	})
	ta, err := d.GetTrustAnchor("get-me")
	if err != nil {
		t.Fatal(err)
	}
	if ta.Name != "GetMe" {
		t.Fatalf("expected GetMe, got %s", ta.Name)
	}
	if !ta.Trusted {
		t.Fatal("expected trusted=true")
	}
	if ta.SubjectO != "Org" {
		t.Fatalf("expected Org, got %s", ta.SubjectO)
	}
	if ta.KeySize != 2048 {
		t.Fatalf("expected key size 2048, got %d", ta.KeySize)
	}
}

func TestGetTrustAnchor_NotFound(t *testing.T) {
	d := newTestDB(t)
	ta, err := d.GetTrustAnchor("nonexistent")
	if err == nil && ta != nil {
		t.Fatal("expected nil")
	}
}

func TestUpdateTrustAnchorTrusted(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	d.InsertTrustAnchor(&TrustAnchor{
		Name: "Flip", HashID: "flip1", CertDER: []byte{0x30},
		Subject: "CN=Flip", NotBefore: now, NotAfter: now.Add(time.Hour),
		Issuer: "CN=root", Trusted: false, Source: "test",
	})
	d.UpdateTrustAnchorTrusted("flip1", true)
	ta, _ := d.GetTrustAnchor("flip1")
	if !ta.Trusted {
		t.Fatal("expected trusted=true after update")
	}
	d.UpdateTrustAnchorTrusted("flip1", false)
	ta, _ = d.GetTrustAnchor("flip1")
	if ta.Trusted {
		t.Fatal("expected trusted=false after flip back")
	}
}

func TestTrustAnchorHashIDs(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	d.InsertTrustAnchor(&TrustAnchor{Name: "H1", HashID: "h1", CertDER: []byte{0x30}, Subject: "CN=H1", NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test"})
	d.InsertTrustAnchor(&TrustAnchor{Name: "H2", HashID: "h2", CertDER: []byte{0x30}, Subject: "CN=H2", NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Source: "test"})
	ids, err := d.TrustAnchorHashIDs()
	if err != nil {
		t.Fatal(err)
	}
	if !ids["h1"] || !ids["h2"] {
		t.Fatalf("expected h1 and h2, got %v", ids)
	}
}

func TestTrustAnchorStats(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	d.InsertTrustAnchor(&TrustAnchor{Name: "T1", HashID: "t1", CertDER: []byte{0x30}, Subject: "CN=T1", NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Trusted: true, Source: "test"})
	d.InsertTrustAnchor(&TrustAnchor{Name: "T2", HashID: "t2", CertDER: []byte{0x30}, Subject: "CN=T2", NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Trusted: true, Source: "test"})
	d.InsertTrustAnchor(&TrustAnchor{Name: "U1", HashID: "u1", CertDER: []byte{0x30}, Subject: "CN=U1", NotBefore: now, NotAfter: now.Add(time.Hour), Issuer: "CN=root", Trusted: false, Source: "test"})
	total, trusted, untrusted, err := d.TrustAnchorStats()
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || trusted != 2 || untrusted != 1 {
		t.Fatalf("expected 3/2/1, got %d/%d/%d", total, trusted, untrusted)
	}
}

func TestTrustAnchorStats_Empty(t *testing.T) {
	d := newTestDB(t)
	total, trusted, untrusted, err := d.TrustAnchorStats()
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || trusted != 0 || untrusted != 0 {
		t.Fatalf("expected 0/0/0, got %d/%d/%d", total, trusted, untrusted)
	}
}

// ---------- scep.go ----------

func TestInsertAndGetSCEPRequest(t *testing.T) {
	d := newTestDB(t)
	rec := &SCEPRequestRecord{
		TransactionID: "txn-001",
		CAName:        "test-ca",
		SerialNumber:  "00AA",
		CertDER:       []byte{0x30, 0x01},
		IssuerDER:     []byte{0x30, 0x02},
		CreatedAt:     time.Now(),
	}
	if err := d.InsertSCEPRequest(rec); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetSCEPRequestByTransactionID("txn-001")
	if err != nil {
		t.Fatal(err)
	}
	if got.CAName != "test-ca" || got.SerialNumber != "00AA" {
		t.Fatalf("expected test-ca/00AA, got %s/%s", got.CAName, got.SerialNumber)
	}
}

func TestGetSCEPRequestBySerial(t *testing.T) {
	d := newTestDB(t)
	d.InsertSCEPRequest(&SCEPRequestRecord{
		TransactionID: "txn-002",
		CAName:        "ca-b",
		SerialNumber:  "00BB",
		CertDER:       []byte{0x30},
		IssuerDER:     []byte{0x30},
		CreatedAt:     time.Now(),
	})
	got, err := d.GetSCEPRequestBySerial("ca-b", "00BB")
	if err != nil {
		t.Fatal(err)
	}
	if got.TransactionID != "txn-002" {
		t.Fatalf("expected txn-002, got %s", got.TransactionID)
	}
}

func TestDeleteSCEPRequest(t *testing.T) {
	d := newTestDB(t)
	d.InsertSCEPRequest(&SCEPRequestRecord{
		TransactionID: "txn-del",
		CAName:        "ca", SerialNumber: "01",
		CertDER: []byte{0x30}, IssuerDER: []byte{0x30}, CreatedAt: time.Now(),
	})
	if err := d.DeleteSCEPRequest("txn-del"); err != nil {
		t.Fatal(err)
	}
	_, err := d.GetSCEPRequestByTransactionID("txn-del")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestGetSCEPRequest_NotFound(t *testing.T) {
	d := newTestDB(t)
	_, err := d.GetSCEPRequestByTransactionID("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent")
	}
}
