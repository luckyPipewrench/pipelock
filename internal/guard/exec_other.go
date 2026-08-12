// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package guard

import (
	"fmt"
	"os"
)

const execModeEnv = "__PIPELOCK_GUARD_EXEC"

func IsExecMode() bool { return os.Getenv(execModeEnv) == "1" }

func ExecControlEnvironment(_ ExecControlOptions) ([]string, error) {
	return []string{execModeEnv + "=1"}, nil
}

func RunExec() {
	_, _ = fmt.Fprintln(os.Stderr, "[guard] REFUSED: Guard execution requires Linux")
	os.Exit(1)
}
