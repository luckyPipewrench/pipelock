// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const execModeEnv = "__PIPELOCK_GUARD_EXEC"

func IsExecMode() bool { return os.Getenv(execModeEnv) == "1" }

func ExecControlEnvironment(declaration config.Guard, profile, policyHash, workspace, tempDir, binary string, environmentFD int) ([]string, error) {
	encoded, err := json.Marshal(declaration)
	if err != nil {
		return nil, fmt.Errorf("encoding guard declaration: %w", err)
	}
	if len(encoded) > 64<<10 {
		return nil, errors.New("guard declaration exceeds the 64 KiB environment transport limit")
	}
	return []string{execModeEnv + "=1"}, nil
}

func RunExec() {
	_, _ = fmt.Fprintln(os.Stderr, "[guard] REFUSED: Guard execution requires Linux")
	os.Exit(1)
}
