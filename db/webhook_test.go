// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
)

func TestCreateAndGetWebhookSub(t *testing.T) {
	d := newTestDB(t)

	s, err := CreateWebhookSub(d, "https://hooks.example.com/notify", "issue,revoke")
	if err != nil {
		t.Fatalf("CreateWebhookSub: %v", err)
	}
	if s.ID == 0 {
		t.Fatal("expected non-zero id")
	}
	if s.URL != "https://hooks.example.com/notify" {
		t.Fatalf("expected https://hooks.example.com/notify, got %q", s.URL)
	}
	if s.Events != "issue,revoke" {
		t.Fatalf("expected issue,revoke, got %q", s.Events)
	}
	if !s.Enabled {
		t.Fatal("expected enabled to be true")
	}

	got, err := GetWebhookSub(d, s.ID)
	if err != nil {
		t.Fatalf("GetWebhookSub: %v", err)
	}
	if got.URL != s.URL {
		t.Fatalf("expected %q, got %q", s.URL, got.URL)
	}
}

func TestCreateWebhookSubDefaultEvents(t *testing.T) {
	d := newTestDB(t)

	s, err := CreateWebhookSub(d, "https://hooks.example.com/default", "")
	if err != nil {
		t.Fatal(err)
	}
	if s.Events != "issue,revoke,expiry" {
		t.Fatalf("expected default events, got %q", s.Events)
	}
}

func TestListWebhookSubs(t *testing.T) {
	d := newTestDB(t)

	CreateWebhookSub(d, "https://hook1.example.com", "issue")
	CreateWebhookSub(d, "https://hook2.example.com", "revoke")

	subs, err := ListWebhookSubs(d)
	if err != nil {
		t.Fatalf("ListWebhookSubs: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("expected 2 subs, got %d", len(subs))
	}
}

func TestDeleteWebhookSub(t *testing.T) {
	d := newTestDB(t)

	s, _ := CreateWebhookSub(d, "https://hooks.example.com/delete-me", "issue")

	if err := DeleteWebhookSub(d, s.ID); err != nil {
		t.Fatalf("DeleteWebhookSub: %v", err)
	}

	_, err := GetWebhookSub(d, s.ID)
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestDeleteWebhookSubNotFound(t *testing.T) {
	d := newTestDB(t)

	err := DeleteWebhookSub(d, 999)
	if err == nil {
		t.Fatal("expected error for nonexistent webhook sub")
	}
}
