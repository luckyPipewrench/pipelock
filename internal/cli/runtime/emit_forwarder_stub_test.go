// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !enterprise

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestBuildEmitSinksForwarderRequiresEnterpriseBuild(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Emit.Forwarder.URL = "https://api.vendor.example/events"
	cfg.Emit.Forwarder.DestinationAllowlist = []string{"api.vendor.example"}
	cfg.Emit.Forwarder.SpoolFile = t.TempDir() + "/spool"
	cfg.Emit.Forwarder.CursorFile = t.TempDir() + "/cursor"
	_, err := BuildEmitSinks(cfg)
	if err == nil || !strings.Contains(err.Error(), "enterprise build") {
		t.Fatalf("BuildEmitSinks error = %v", err)
	}
}
