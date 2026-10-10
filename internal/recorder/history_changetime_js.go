// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package recorder

import (
	"fmt"
	"syscall"
)

// Access time is deliberately excluded: reading evidence can change it.
func historyChangeTime(stat *syscall.Stat_t) string {
	return fmt.Sprintf("%d:%d", stat.Ctime, stat.CtimeNsec)
}
