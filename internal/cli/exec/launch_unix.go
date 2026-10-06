// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package exec

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/processexec"
)

func launch(_ *cobra.Command, args, environment []string) error {
	binary, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("find command: %w", err)
	}
	if err := processexec.Replace(binary, args, environment); err != nil {
		return fmt.Errorf("exec command: %w", err)
	}
	return nil
}
