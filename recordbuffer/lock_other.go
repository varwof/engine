// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build !unix

package recordbuffer

import "os"

// tryFlockWAL is a no-op on platforms without flock (e.g. Windows); the SQLite
// WAL file itself plus DB-level locking provide the cross-process guard there.
func tryFlockWAL(f *os.File) error { return nil }
