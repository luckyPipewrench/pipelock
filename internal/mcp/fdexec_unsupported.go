// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package mcp

import (
	"context"
	"errors"
	"os/exec"

	"github.com/luckyPipewrench/pipelock/internal/mcp/integrity"
)

var errDescriptorExecUnsupported = errors.New("descriptor-based executable launch is unsupported on this platform")

func descriptorCommand(_ context.Context, _ []string, _ *integrity.PreparedCommand) (*exec.Cmd, error) {
	return nil, errDescriptorExecUnsupported
}
