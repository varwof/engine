// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
)

func TestCreateAndGetRARequest(t *testing.T) {
	d := newTestDB(t)

	id, err := d.CreateRARequest([]byte("csr-der"), "test.example.com",
		"san1,san2", "tls-server", "issuing-ca", "requester1", 2)
	if err != nil {
		t.Fatalf("CreateRARequest: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}

	req, err := d.GetRARequest(id)
	if err != nil {
		t.Fatalf("GetRARequest: %v", err)
	}

	if req.CommonName != "test.example.com" {
		t.Fatalf("expected test.example.com, got %q", req.CommonName)
	}
	if req.Status != "pending" {
		t.Fatalf("expected pending, got %q", req.Status)
	}
	if req.Requester != "requester1" {
		t.Fatalf("expected requester1, got %q", req.Requester)
	}
	if req.RequiredApprovals != 2 {
		t.Fatalf("expected 2, got %d", req.RequiredApprovals)
	}
	if req.ApprovalCount != 0 {
		t.Fatalf("expected 0 approvals, got %d", req.ApprovalCount)
	}
}

func TestGetRARequestNotFound(t *testing.T) {
	d := newTestDB(t)
	_, err := d.GetRARequest(999)
	if err == nil {
		t.Fatal("expected error for nonexistent RA request")
	}
}

func TestListRARequests(t *testing.T) {
	d := newTestDB(t)

	for i := 0; i < 3; i++ {
		cn := "test" + string(rune('A'+i)) + ".example.com"
		d.CreateRARequest([]byte("csr-"+cn), cn, "", "tls-server", "ca1", "user", 1)
	}

	all, err := d.ListRARequests("", 10, 0)
	if err != nil {
		t.Fatalf("ListRARequests: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(all))
	}

	pending, err := d.ListRARequests("pending", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 3 {
		t.Fatalf("expected 3 pending, got %d", len(pending))
	}
}

func TestListRARequestsLimitOffset(t *testing.T) {
	d := newTestDB(t)

	for i := 0; i < 5; i++ {
		d.CreateRARequest([]byte("csr"), "cn", "", "tls-server", "ca1", "user", 1)
	}

	first, _ := d.ListRARequests("", 2, 0)
	if len(first) != 2 {
		t.Fatalf("expected 2, got %d", len(first))
	}

	second, _ := d.ListRARequests("", 2, 2)
	if len(second) != 2 {
		t.Fatalf("expected 2, got %d", len(second))
	}
}

func TestAddRAApproval(t *testing.T) {
	d := newTestDB(t)

	id, _ := d.CreateRARequest([]byte("csr"), "app.example.com", "", "tls-server", "ca1", "user", 2)

	count, total, err := d.AddRAApproval(id, "approver1", "approved", "looks good")
	if err != nil {
		t.Fatalf("AddRAApproval: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 approval, got %d", count)
	}
	if total != 2 {
		t.Fatalf("expected 2 required, got %d", total)
	}

	count, total, err = d.AddRAApproval(id, "approver2", "approved", "")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected 2 approvals, got %d", count)
	}
}

func TestAddApprovalDuplicate(t *testing.T) {
	d := newTestDB(t)

	id, _ := d.CreateRARequest([]byte("csr"), "dup.example.com", "", "tls-server", "ca1", "user", 1)

	_, _, err := d.AddRAApproval(id, "approver1", "approved", "")
	if err != nil {
		t.Fatal(err)
	}

	// Same approver, same decision — duplicate should be ignored (INSERT OR IGNORE)
	_, _, err = d.AddRAApproval(id, "approver1", "approved", "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRARequestStatus(t *testing.T) {
	d := newTestDB(t)

	id, _ := d.CreateRARequest([]byte("csr"), "status.example.com", "", "tls-server", "ca1", "user", 1)

	if err := d.UpdateRARequestStatus(id, "issued", "SERIAL001", ""); err != nil {
		t.Fatalf("UpdateRARequestStatus issued: %v", err)
	}

	req, _ := d.GetRARequest(id)
	if req.Status != "issued" {
		t.Fatalf("expected issued, got %q", req.Status)
	}
	if req.IssuedSerial == nil || *req.IssuedSerial != "SERIAL001" {
		t.Fatalf("expected SERIAL001, got %v", req.IssuedSerial)
	}

	if err := d.UpdateRARequestStatus(id, "rejected", "", "bad csr"); err != nil {
		t.Fatalf("UpdateRARequestStatus rejected: %v", err)
	}

	req2, _ := d.GetRARequest(id)
	if req2.Status != "rejected" {
		t.Fatalf("expected rejected, got %q", req2.Status)
	}
	if req2.RejectReason == nil || *req2.RejectReason != "bad csr" {
		t.Fatalf("expected 'bad csr', got %v", req2.RejectReason)
	}
}

func TestCountRAPending(t *testing.T) {
	d := newTestDB(t)

	count, err := d.CountRAPending()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected 0 pending initially, got %d", count)
	}

	d.CreateRARequest([]byte("csr"), "a.example.com", "", "tls-server", "ca1", "user", 1)
	d.CreateRARequest([]byte("csr"), "b.example.com", "", "tls-server", "ca1", "user", 1)

	count, _ = d.CountRAPending()
	if count != 2 {
		t.Fatalf("expected 2 pending, got %d", count)
	}
}
