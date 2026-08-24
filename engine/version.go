// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// Package engine provides the core engine for the varwof project.
package engine

import (
	"runtime/debug"
	"strings"
)

// Version is the package version.
//
// When built from a tagged git checkout it resolves from module build info
// (e.g. v0.1.0); otherwise it falls back to the compile-time default below.
// It can be overridden via -ldflags -X github.com/varwof/engine/engine.Version=x.y.z.
var Version = "0.1.0"

// Commit is the short VCS revision the binary was built from.
// Populated automatically from module build info, or overridden via
// -ldflags -X github.com/varwof/engine/engine.Commit=<short-hash>.
var Commit = "unknown"

func init() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if bi.Main.Version != "" && bi.Main.Version != "(devel)" && Version == "0.1.0" {
		Version = strings.TrimPrefix(bi.Main.Version, "v")
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 && Commit == "unknown" {
			Commit = s.Value[:7]
			break
		}
	}
}
