// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package recordbuffer

import "errors"

// ErrWALLocked is returned when another process holds the WAL write pipeline
// for the same DB file (multi-process engine/recordbuffer conflict). Callers
// should treat it as "engine cannot be enabled here", degrade to DB-only and
// log a warning.
var ErrWALLocked = errors.New("record buffer WAL locked by another process")

// ErrWALDisabled is returned when an operation that requires the write-ahead
// log (e.g. crash-safe DA nonce storage) is attempted on a buffer created
// without a WAL path. Callers fall back to synchronous DB persistence.
var ErrWALDisabled = errors.New("record buffer WAL disabled")
