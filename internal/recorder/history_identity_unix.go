// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix || (js && wasm)

package recorder

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func historyFileIdentity(_ EvidenceLocation, _ string, info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("cannot identify evidence shard")
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}
