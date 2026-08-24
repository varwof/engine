// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
	"time"
)

func TestRegisterGateway_Success(t *testing.T) {
	d := newRenewalTestDB(t)
	if err := d.RegisterGateway("192.168.1.1:8443", ""); err != nil {
		t.Fatalf("RegisterGateway: %v", err)
	}
	gw, err := d.GetGateway("192.168.1.1:8443")
	if err != nil {
		t.Fatalf("GetGateway: %v", err)
	}
	if gw.Address != "192.168.1.1:8443" {
		t.Fatalf("expected address 192.168.1.1:8443, got %s", gw.Address)
	}
	if gw.Status != "active" {
		t.Fatalf("expected status active, got %s", gw.Status)
	}
}

func TestRegisterGateway_EmptyAddress(t *testing.T) {
	d := newRenewalTestDB(t)
	if err := d.RegisterGateway("", ""); err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestRegisterGateway_Update(t *testing.T) {
	d := newRenewalTestDB(t)
	if err := d.RegisterGateway("gw1:8443", "ca-a"); err != nil {
		t.Fatalf("first register: %v", err)
	}
	orig, _ := d.GetGateway("gw1:8443")
	if err := d.RegisterGateway("gw1:8443", "ca-b"); err != nil {
		t.Fatalf("second register: %v", err)
	}
	updated, _ := d.GetGateway("gw1:8443")
	if updated.CaName != "ca-b" {
		t.Fatalf("expected ca_name ca-b, got %s", updated.CaName)
	}
	if updated.LastSeen.Before(orig.LastSeen) {
		t.Fatal("expected last_seen not before original")
	}
}

func TestHeartbeatGateway_Success(t *testing.T) {
	d := newRenewalTestDB(t)
	d.RegisterGateway("gw1:8443", "")
	time.Sleep(10 * time.Millisecond)
	if err := d.HeartbeatGateway("gw1:8443"); err != nil {
		t.Fatalf("HeartbeatGateway: %v", err)
	}
	gw, _ := d.GetGateway("gw1:8443")
	if gw.Status != "active" {
		t.Fatalf("expected active, got %s", gw.Status)
	}
}

func TestHeartbeatGateway_NotFound(t *testing.T) {
	d := newRenewalTestDB(t)
	if err := d.HeartbeatGateway("nonexistent:8443"); err != ErrGatewayNotFound {
		t.Fatalf("expected ErrGatewayNotFound, got %v", err)
	}
}

func TestListActiveGateways(t *testing.T) {
	d := newRenewalTestDB(t)
	d.RegisterGateway("gw1:8443", "")
	d.RegisterGateway("gw2:8443", "")
	d.MarkGatewayInactive("gw2:8443")

	active, err := d.ListActiveGateways()
	if err != nil {
		t.Fatalf("ListActiveGateways: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
	if active[0].Address != "gw1:8443" {
		t.Fatalf("expected gw1:8443, got %s", active[0].Address)
	}
}

func TestListAllGateways(t *testing.T) {
	d := newRenewalTestDB(t)
	d.RegisterGateway("gw1:8443", "")
	d.RegisterGateway("gw2:8443", "")

	all, err := d.ListAllGateways()
	if err != nil {
		t.Fatalf("ListAllGateways: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 total, got %d", len(all))
	}
}

func TestMarkGatewayInactive(t *testing.T) {
	d := newRenewalTestDB(t)
	d.RegisterGateway("gw1:8443", "")
	if err := d.MarkGatewayInactive("gw1:8443"); err != nil {
		t.Fatalf("MarkGatewayInactive: %v", err)
	}
	gw, _ := d.GetGateway("gw1:8443")
	if gw == nil {
		t.Fatal("expected gateway record")
	}
	if gw.Status != "inactive" {
		t.Fatalf("expected inactive, got %s", gw.Status)
	}
}

func TestCleanupStaleGateways(t *testing.T) {
	d := newRenewalTestDB(t)
	d.RegisterGateway("gw1:8443", "")
	d.RegisterGateway("gw2:8443", "")

	// Backdate gw1's last_seen
	_, err := d.Exec(`UPDATE gateway_registry SET last_seen = datetime('now', '-2 hours') WHERE address = ?`,
		"gw1:8443")
	if err != nil {
		t.Fatalf("backdate: %v", err)
	}

	n, err := d.CleanupStaleGateways(1 * time.Hour)
	if err != nil {
		t.Fatalf("CleanupStaleGateways: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 cleaned, got %d", n)
	}

	gw1, _ := d.GetGateway("gw1:8443")
	gw2, _ := d.GetGateway("gw2:8443")
	if gw1 == nil || gw1.Status != "inactive" {
		t.Fatal("gw1 should be inactive")
	}
	if gw2 == nil || gw2.Status != "active" {
		t.Fatal("gw2 should remain active")
	}
}

func TestRemoveGateway(t *testing.T) {
	d := newRenewalTestDB(t)
	d.RegisterGateway("gw1:8443", "")
	if err := d.RemoveGateway("gw1:8443"); err != nil {
		t.Fatalf("RemoveGateway: %v", err)
	}
	if _, err := d.GetGateway("gw1:8443"); err != ErrGatewayNotFound {
		t.Fatalf("expected ErrGatewayNotFound, got %v", err)
	}
}

func TestGetGateway_NotFound(t *testing.T) {
	d := newRenewalTestDB(t)
	if _, err := d.GetGateway("nonexistent:8443"); err != ErrGatewayNotFound {
		t.Fatalf("expected ErrGatewayNotFound, got %v", err)
	}
}
