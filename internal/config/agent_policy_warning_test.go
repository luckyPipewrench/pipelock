// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateWithWarnings_UnboundAgentPolicy(t *testing.T) {
	cfg := Defaults()
	cfg.Agents = map[string]AgentProfile{
		"unbound": {Mode: ModeAudit},
		"listener-bound": {
			Listeners: []string{":8891"},
			Mode:      ModeAudit,
		},
		"cidr-bound": {
			SourceCIDRs: []string{"192.0.2.0/24"},
			Mode:        ModeAudit,
		},
		"_default": {Mode: ModeAudit},
	}
	cfg.AllowEphemeralListenersForTesting()

	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatal(err)
	}
	var matches []Warning
	for _, warning := range warnings {
		if strings.HasPrefix(warning.Field, "agents.") {
			matches = append(matches, warning)
		}
	}
	if len(matches) != 1 || matches[0].Field != "agents.unbound" {
		t.Fatalf("agent policy warnings = %+v, want only agents.unbound", matches)
	}
	if !strings.Contains(matches[0].Message, "attribution only") || !strings.Contains(matches[0].Message, "listeners") {
		t.Fatalf("warning does not explain behavior and remedy: %+v", matches[0])
	}
}

func TestValidateWithWarnings_BoundDefaultAgentPolicy(t *testing.T) {
	cfg := Defaults()
	cfg.DefaultAgentIdentity = "sidecar"
	cfg.BindDefaultAgentIdentity = true
	cfg.Agents = map[string]AgentProfile{"sidecar": {Mode: ModeStrict}}

	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range warnings {
		if warning.Field == "agents.sidecar" {
			t.Fatalf("bound default profile produced migration warning: %+v", warning)
		}
	}
}
