// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMCPIdentityRegisterRealProcessLoadsAndVerifies(t *testing.T) {
	reg := newE2ERegistration(t, config.MCPIdentitySchemeHTTP, false)
	service := startIdentityE2EServer(t, identityE2EServerOpts{Hold: reg.MappedPath})
	upstream := service.url(config.MCPIdentitySchemeHTTP)
	output, err := runIdentityCmd(t, defaultIdentityProbe(), "register", "--upstream", upstream, "--name", "local-tools", "--mapped-file", reg.MappedPath)
	if err != nil {
		t.Fatalf("register live service: %v", err)
	}
	path := writeE2EConfig(t, "", output)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("load generated registration: %v", err)
	}
	inspection, err := runIdentityCmd(t, defaultIdentityProbe(), "inspect", "--config", path, "--upstream", upstream)
	if err != nil || !strings.Contains(inspection, "verification: verified") {
		t.Fatalf("inspect generated registration: %v\n%s", err, inspection)
	}
}
