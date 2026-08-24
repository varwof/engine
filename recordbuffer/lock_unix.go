// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build unix

package recordbuffer

import (
	"errors"
	"os"
	"syscall"
)

// tryFlockWAL acquires an exclusive, non-blocking advisory lock on the WAL
// file so a second process sharing the same DB directory cannot also own the
// write pipeline (two writers truncating/rewriting the same WAL corrupts it).
// The lock is released automatically when the file is closed on Stop.
//
// EWOULDBLOCK/EAGAIN means another process already holds the pipeline; any
// other error is a hard failure. Both abort engine/recordbuffer enabling.
func tryFlockWAL(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return ErrWALLocked
		}
		return err
	}
	return nil
}
