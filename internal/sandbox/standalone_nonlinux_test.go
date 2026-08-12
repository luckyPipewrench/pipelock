// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestLaunchStandaloneRejectsGuardOnNonLinux(t *testing.T) {
	err := LaunchStandalone(StandaloneLaunchConfig{GuardDeclaration: &config.Guard{}})
	if err == nil || !strings.Contains(err.Error(), "Guard execution requires Linux") {
		t.Fatalf("guarded non-Linux launch error = %v", err)
	}
}
