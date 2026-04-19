// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// TestValidate_RedactionEnabledBlockedUntilEnforced guards the startup
// gate introduced in response to GPT review #1 (2026-04-19). An operator
// setting redaction.enabled=true must get a loud startup failure until
// the transport pipeline actually enforces redaction, so nobody believes
// they are protected by an unwired feature.
func TestValidate_RedactionEnabledBlockedUntilEnforced(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Redaction = redact.Config{
		Enabled:        true,
		DefaultProfile: "p",
		Profiles: map[string]redact.ProfileSpec{
			"p": {Classes: []string{"ipv4"}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should reject redaction.enabled=true until enforcement ships")
	}
	if !strings.Contains(err.Error(), "enabled=true is not supported") {
		t.Fatalf("error must explain the gate, got: %v", err)
	}
}

// TestValidate_RedactionDisabledPermitted confirms the default-disabled
// path continues to validate cleanly.
func TestValidate_RedactionDisabledPermitted(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	// Redaction defaults to disabled; Validate must succeed.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default Validate should pass, got %v", err)
	}
}
