// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package db

import (
	"testing"
)

func TestCRLNumberStore(t *testing.T) {
	d := newTestDB(t)

	// Unknown CA returns 0 (no error).
	n, err := d.GetLastCRLNumber("nonexistent-ca")
	if err != nil {
		t.Fatalf("GetLastCRLNumber unknown CA: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 for unknown CA, got %d", n)
	}

	// Set then read back.
	if err := d.SetLastCRLNumber("root", 7); err != nil {
		t.Fatalf("SetLastCRLNumber: %v", err)
	}
	n, err = d.GetLastCRLNumber("root")
	if err != nil {
		t.Fatalf("GetLastCRLNumber: %v", err)
	}
	if n != 7 {
		t.Fatalf("expected 7, got %d", n)
	}

	// Monotonic guard: a lower number must NOT overwrite a higher persisted one.
	if err := d.SetLastCRLNumber("root", 3); err != nil {
		t.Fatalf("SetLastCRLNumber lower: %v", err)
	}
	n, _ = d.GetLastCRLNumber("root")
	if n != 7 {
		t.Fatalf("expected persisted 7 to survive lower write, got %d", n)
	}
	if err := d.SetLastCRLNumber("root", 100); err != nil {
		t.Fatalf("SetLastCRLNumber higher: %v", err)
	}
	n, _ = d.GetLastCRLNumber("root")
	if n != 100 {
		t.Fatalf("expected 100, got %d", n)
	}

	// Per-CA isolation.
	if err := d.SetLastCRLNumber("issuing", 42); err != nil {
		t.Fatalf("SetLastCRLNumber issuing: %v", err)
	}
	nums, err := d.ListCRLNumbers()
	if err != nil {
		t.Fatalf("ListCRLNumbers: %v", err)
	}
	if len(nums) != 2 {
		t.Fatalf("expected 2 CAs, got %d: %v", len(nums), nums)
	}
	if nums["root"] != 100 || nums["issuing"] != 42 {
		t.Fatalf("unexpected map: %v", nums)
	}
}
