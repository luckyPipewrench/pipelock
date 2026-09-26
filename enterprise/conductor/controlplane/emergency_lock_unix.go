//go:build enterprise && !windows

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"os"
	"path/filepath"
	"syscall"
)

func lockEmergencyDirectory(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Clean(filepath.Join(dir, ".emergency-controls.lock")), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
