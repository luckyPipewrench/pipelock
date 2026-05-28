//go:build !enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"testing"
)

func TestNewServer_ConductorEnabledRequiresEnterpriseBuild(t *testing.T) {
	setTestFleetLicense(t)
	cfgPath := writeServerTestConfig(t, conductorLicenseGateConfigYAML(t))

	_, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if !errors.Is(err, errConductorEnterpriseBuildRequired) {
		t.Fatalf("NewServer with conductor.enabled on core build: want errConductorEnterpriseBuildRequired, got %v", err)
	}
}
