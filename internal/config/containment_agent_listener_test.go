// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateContainmentAgentListener(t *testing.T) {
	t.Parallel()
	agents := map[string]AgentProfile{
		"contained": {Listeners: []string{"127.0.0.1:8889"}},
		"other":     {Listeners: []string{"[::1]:8890"}},
	}
	for _, tc := range []struct {
		name     string
		listener string
		wantErr  string
	}{
		{name: "omitted keeps the shared listener", listener: ""},
		{name: "declared ipv4 listener", listener: "127.0.0.1:8889"},
		{name: "declared ipv6 listener", listener: "[::1]:8890"},
		{name: "undeclared listener", listener: "127.0.0.1:8891", wantErr: "not declared under any agents"},
		{name: "shared proxy port", listener: "127.0.0.1:8888", wantErr: "shared proxy port"},
		{name: "non-loopback host", listener: "10.0.0.5:8889", wantErr: "numeric loopback"},
		{name: "hostname is not numeric", listener: "localhost:8889", wantErr: "numeric loopback"},
		{name: "missing port", listener: "127.0.0.1", wantErr: "containment.agent_listener"},
		{name: "port out of range", listener: "127.0.0.1:70000", wantErr: "invalid port"},
		{name: "ipv4-mapped ipv6 loopback", listener: "[::ffff:127.0.0.1]:8889", wantErr: "IPv4-mapped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateContainmentAgentListener(tc.listener, agents, 8888)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateContainmentAgentListener(%q) = %v, want nil", tc.listener, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateContainmentAgentListener(%q) = %v, want error containing %q", tc.listener, err, tc.wantErr)
			}
		})
	}
}

// A listener declared only by a profile the license gate disabled is still
// refused, but the refusal must name the license cause rather than tell the
// operator to declare a listener that is already declared.
func TestValidateContainmentAgentListenerLicenseDisabledProfile(t *testing.T) {
	t.Parallel()
	active := map[string]AgentProfile{"_default": {}}
	disabled := map[string][]string{
		"contained-agent": {"127.0.0.1:8889"},
		"second-agent":    {"[::1]:8890", "127.0.0.1:8889"},
		"listenerless":    nil,
	}
	for _, tc := range []struct {
		name     string
		listener string
		agents   map[string]AgentProfile
		disabled map[string][]string
		reason   string
		want     []string
		notWant  []string
	}{
		{
			name: "declared only by disabled profiles", listener: "127.0.0.1:8889",
			agents: active, disabled: disabled, reason: "no license key is configured",
			want:    []string{`"127.0.0.1:8889"`, "agents.contained-agent, agents.second-agent", "disabled because no license key is configured", LicenseDisabledProfileRefusal},
			notWant: []string{"not declared under any agents"},
		},
		{
			name: "disabled declaration matches in canonical form", listener: "[0:0:0:0:0:0:0:1]:8890",
			agents: active, disabled: disabled, reason: "no license key is configured",
			want: []string{"agents.second-agent,", LicenseDisabledProfileRefusal},
		},
		{
			name: "empty reason falls back", listener: "127.0.0.1:8889",
			agents: active, disabled: map[string][]string{"contained-agent": {"127.0.0.1:8889"}},
			want: []string{"agents.contained-agent, which was disabled because no valid license is loaded", LicenseDisabledProfileRefusal},
		},
		{
			name: "genuinely undeclared keeps the declare hint", listener: "127.0.0.1:8891",
			agents: active, disabled: disabled, reason: "no license key is configured",
			want:    []string{"not declared under any agents.<name>.listeners"},
			notWant: []string{LicenseDisabledProfileRefusal},
		},
		{
			name: "active declaration wins", listener: "127.0.0.1:8889",
			agents:   map[string]AgentProfile{"contained-agent": {Listeners: []string{"127.0.0.1:8889"}}},
			disabled: disabled, reason: "no license key is configured",
		},
		{
			name: "no disabled record keeps the declare hint", listener: "127.0.0.1:8889",
			agents:  active,
			want:    []string{"not declared under any agents.<name>.listeners"},
			notWant: []string{LicenseDisabledProfileRefusal},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateContainmentAgentListener(tc.listener, tc.agents, tc.disabled, tc.reason, 8888)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("validateContainmentAgentListener(%q) = %v, want nil", tc.listener, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateContainmentAgentListener(%q) = nil, want refusal", tc.listener)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error = %q, want substring %q", err, w)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(err.Error(), nw) {
					t.Errorf("error = %q, must not contain %q", err, nw)
				}
			}
		})
	}
}

// Validate must route the license-gate record into the listener check, so
// the whole-config path reports the license cause and still refuses.
func TestValidateReportsLicenseDisabledAgentListener(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		listener string
		disabled map[string][]string
		want     string
		notWant  string
	}{
		{name: "disabled profile", listener: "127.0.0.1:8889", disabled: map[string][]string{"contained-agent": {"127.0.0.1:8889"}}, want: LicenseDisabledProfileRefusal, notWant: "not declared under any agents"},
		{name: "undeclared", listener: "127.0.0.1:8891", disabled: map[string][]string{"contained-agent": {"127.0.0.1:8889"}}, want: "not declared under any agents", notWant: LicenseDisabledProfileRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Internal = nil
			cfg.Containment.AgentListener = tc.listener
			cfg.LicenseDisabledAgents = tc.disabled
			cfg.LicenseDisabledReason = "no license key is configured"
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want refusal")
			}
			if !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), tc.notWant) {
				t.Fatalf("Validate() = %q, want %q and not %q", err, tc.want, tc.notWant)
			}
		})
	}
}

func TestCloneCopiesLicenseDisabledAgents(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.LicenseDisabledAgents = map[string][]string{"contained-agent": {"127.0.0.1:8889"}}
	cfg.LicenseDisabledReason = "no license key is configured"
	clone := cfg.Clone()
	clone.LicenseDisabledAgents["contained-agent"][0] = "127.0.0.1:9999"
	clone.LicenseDisabledAgents["other"] = nil
	if got := cfg.LicenseDisabledAgents["contained-agent"][0]; got != "127.0.0.1:8889" {
		t.Fatalf("clone aliased the listener slice: original now %q", got)
	}
	if _, ok := cfg.LicenseDisabledAgents["other"]; ok {
		t.Fatal("clone aliased the disabled-agents map")
	}
	if clone.LicenseDisabledReason != cfg.LicenseDisabledReason {
		t.Fatalf("clone reason = %q, want %q", clone.LicenseDisabledReason, cfg.LicenseDisabledReason)
	}
}

// The docs gate classifies this refusal by its fixed phrase; the two copies
// must not drift, or an enterprise run of the gate fails on a license skip.
func TestLicenseDisabledProfileRefusalMatchesDocsGate(t *testing.T) {
	t.Parallel()
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "check-config-examples.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "'"+LicenseDisabledProfileRefusal+"'") {
		t.Fatalf("scripts/check-config-examples.sh does not carry the phrase %q", LicenseDisabledProfileRefusal)
	}
}
