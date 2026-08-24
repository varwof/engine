// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
	"time"
)

func TestInsertAndGetCAMeta(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	rec := &CAMeta{
		Name:         "test-ca",
		CertDER:      []byte("fake-der"),
		Subject:      "CN=test-ca,O=test",
		NotBefore:    now,
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "abcdef1234567890",
	}
	if err := d.InsertCAMeta(rec); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetCAMeta("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "test-ca" {
		t.Fatalf("expected test-ca, got %q", got.Name)
	}
	if got.KeyAlgorithm != "ecdsa-p256" {
		t.Fatalf("expected ecdsa-p256, got %q", got.KeyAlgorithm)
	}
}

func TestInsertCAMetaReplace(t *testing.T) {
	d := newTestDB(t)
	rec := &CAMeta{
		Name:         "replace-ca",
		CertDER:      []byte("v1"),
		Subject:      "CN=v1",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "fp-v1",
	}
	if err := d.InsertCAMeta(rec); err != nil {
		t.Fatal(err)
	}
	rec2 := &CAMeta{
		Name:         "replace-ca",
		CertDER:      []byte("v2"),
		Subject:      "CN=v2",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyAlgorithm: "ecdsa-p384",
		Fingerprint:  "fp-v2",
	}
	if err := d.InsertCAMeta(rec2); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetCAMeta("replace-ca")
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != "fp-v2" {
		t.Fatalf("expected fp-v2, got %q", got.Fingerprint)
	}
}

func TestListCAMetas(t *testing.T) {
	d := newTestDB(t)
	now := time.Now()
	for _, name := range []string{"ca-a", "ca-b", "ca-c"} {
		d.InsertCAMeta(&CAMeta{
			Name:         name,
			CertDER:      []byte("der-" + name),
			Subject:      "CN=" + name,
			NotBefore:    now,
			NotAfter:     now.Add(365 * 24 * time.Hour),
			KeyAlgorithm: "ecdsa-p256",
			Fingerprint:  "fp-" + name,
		})
	}
	list, err := d.ListCAMetas()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3, got %d", len(list))
	}
	names := make(map[string]bool)
	for _, m := range list {
		names[m.Name] = true
	}
	for _, n := range []string{"ca-a", "ca-b", "ca-c"} {
		if !names[n] {
			t.Fatalf("missing %q", n)
		}
	}
}

func TestDeleteCAMeta(t *testing.T) {
	d := newTestDB(t)
	rec := &CAMeta{
		Name:         "delete-me",
		CertDER:      []byte("der"),
		Subject:      "CN=delete-me",
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "fp",
	}
	d.InsertCAMeta(rec)
	if err := d.DeleteCAMeta("delete-me"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetCAMeta("delete-me"); err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestGetCAMetaNotFound(t *testing.T) {
	d := newTestDB(t)
	_, err := d.GetCAMeta("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent CA")
	}
}

func TestListCAMetasEmpty(t *testing.T) {
	d := newTestDB(t)
	list, err := d.ListCAMetas()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty list, got %d", len(list))
	}
}
