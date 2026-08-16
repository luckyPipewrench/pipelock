// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package mcp

import (
	"context"
	"os/exec"
)

// waitForCommandWithProcessGroup waits for the direct child where the platform
// cannot observe exit without reaping it. Do not signal a numeric process
// group after Wait: that identifier may already name unrelated work.
func waitForCommandWithProcessGroup(_ context.Context, cmd *exec.Cmd, _ int) error {
	return cmd.Wait()
}
