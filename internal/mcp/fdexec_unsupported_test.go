// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package mcp

import (
	"context"
	"errors"
	"testing"
)

func TestDescriptorCommandUnsupportedFailsClosed(t *testing.T) {
	_, err := descriptorCommand(context.Background(), []string{"server"}, nil)
	if !errors.Is(err, errDescriptorExecUnsupported) {
		t.Fatalf("descriptorCommand() error = %v, want %v", err, errDescriptorExecUnsupported)
	}
}
