// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package engine

import "testing"

// TestVersionExposed ensures the build-time version variables are set and
// readable (used by callers for logging/observability).
func TestVersionExposed(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
	if Commit == "" {
		t.Fatal("Commit must not be empty")
	}
}
