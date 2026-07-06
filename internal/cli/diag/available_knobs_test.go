// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestAvailableUnconfiguredKnobsDefaults(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	got := availableUnconfiguredKnobs(cfg)
	for _, want := range []string{
		"trusted_domains",
		"agents",
		"kill_switch",
		"emit",
		"address_protection",
		"mcp_tool_policy.redirect_profiles",
	} {
		if !containsString(got, want) {
			t.Fatalf("missing %q in %v", want, got)
		}
	}
}

func TestAvailableUnconfiguredKnobsOmitsConfigured(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.TrustedDomains = []string{"api.vendor.example"}
	cfg.Agents = map[string]config.AgentProfile{"agent": {Mode: config.ModeBalanced}}
	cfg.KillSwitch.Enabled = true
	cfg.Emit.Webhook.URL = "https://logs.vendor.example/events"
	cfg.AddressProtection.Enabled = true
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.RedirectProfiles = map[string]config.RedirectProfile{
		"fetch_proxy": {Exec: []string{"/proc/self/exe", "internal-redirect", "fetch-proxy"}},
	}

	if got := availableUnconfiguredKnobs(cfg); len(got) != 0 {
		t.Fatalf("availableUnconfiguredKnobs = %v, want none", got)
	}
}

func TestAvailableUnconfiguredKnobsKeepsKillSwitchWhenOnlyPresentationOrExemptionsSet(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.KillSwitch.Message = "deny all"
	cfg.KillSwitch.AllowlistIPs = []string{"192.0.2.0/24"}
	cfg.KillSwitch.APIListen = "127.0.0.1:19091"

	got := availableUnconfiguredKnobs(cfg)
	if !containsString(got, "kill_switch") {
		t.Fatalf("availableUnconfiguredKnobs = %v, want kill_switch without an activation source", got)
	}
}

func TestAvailableUnconfiguredKnobsOmitsKillSwitchWhenAPITokenComesFromEnv(t *testing.T) {
	t.Setenv(config.EnvKillSwitchAPIToken, strings.Repeat("x", 16))

	cfg := config.Defaults()
	got := availableUnconfiguredKnobs(cfg)
	if containsString(got, "kill_switch") {
		t.Fatalf("availableUnconfiguredKnobs = %v, want kill_switch omitted when API token is supplied by env", got)
	}
}

func TestAvailableUnconfiguredKnobsKeepsAddressProtectionWhenOnlyAllowlistSet(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.AddressProtection.AllowedAddresses = []string{"0x1111111111111111111111111111111111111111"}

	got := availableUnconfiguredKnobs(cfg)
	if !containsString(got, "address_protection") {
		t.Fatalf("availableUnconfiguredKnobs = %v, want address_protection when detector is disabled", got)
	}
}

func TestAvailableUnconfiguredKnobsKeepsRedirectProfilesWhenPolicyDisabled(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.MCPToolPolicy.RedirectProfiles = map[string]config.RedirectProfile{
		"fetch_proxy": {Exec: []string{"/proc/self/exe", "internal-redirect", "fetch-proxy"}},
	}

	got := availableUnconfiguredKnobs(cfg)
	if !containsString(got, "mcp_tool_policy.redirect_profiles") {
		t.Fatalf("availableUnconfiguredKnobs = %v, want redirect_profiles when tool policy is disabled", got)
	}
}

func TestDoctorReportsAvailableUnconfiguredKnobsAsInfo(t *testing.T) {
	t.Parallel()

	report := buildDoctorReport(config.Defaults(), configLabelDefaults)
	check := doctorCheckFor(report, doctorCheckAvailableKnobs)
	if check.Status != doctorStatusInfo {
		t.Fatalf("available knob check = %+v, want info", check)
	}
	if !strings.Contains(check.Detail, "available but not configured:") {
		t.Fatalf("detail = %q, want available but not configured", check.Detail)
	}
}

func TestCheckCommandPrintsAvailableUnconfiguredKnobs(t *testing.T) {
	t.Parallel()

	cmd := CheckCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[INFO] available but not configured:") {
		t.Fatalf("check output missing available knobs info:\n%s", out)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
