// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/cli/runtimeconfig"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const doctorCheckAvailableKnobs = "available_unconfigured_knobs"

func formatAvailableUnconfiguredDetail(knobs []string) string {
	return "available but not configured: " + strings.Join(knobs, ", ")
}

func availableUnconfiguredDetail(cfg *config.Config) (string, bool) {
	knobs := availableUnconfiguredKnobs(cfg)
	if len(knobs) == 0 {
		return "", false
	}
	return formatAvailableUnconfiguredDetail(knobs), true
}

func checkDoctorAvailableKnobs(cfg *config.Config) []doctorReportCheck {
	detail, ok := availableUnconfiguredDetail(cfg)
	if !ok {
		return []doctorReportCheck{{
			Name:       doctorCheckAvailableKnobs,
			Surface:    doctorSurfaceConfig,
			Status:     doctorStatusOK,
			Configured: true,
			Detail:     "security-relevant optional knobs are configured where available",
		}}
	}
	return []doctorReportCheck{{
		Name:    doctorCheckAvailableKnobs,
		Surface: doctorSurfaceConfig,
		Status:  doctorStatusInfo,
		Detail:  detail,
		Next:    "configure only the knobs that match this deployment's threat model; rerun `pipelock doctor` to verify reachability",
	}}
}

func availableUnconfiguredAdvisory(cfg *config.Config) string {
	detail, _ := availableUnconfiguredDetail(cfg)
	return detail
}

func availableUnconfiguredKnobs(cfg *config.Config) []string {
	cfg = resolvedAvailableKnobsConfig(cfg)
	candidates := []struct {
		name       string
		configured bool
	}{
		{name: "trusted_domains", configured: len(cfg.TrustedDomains) > 0},
		{name: "agents", configured: len(cfg.Agents) > 0},
		{name: "kill_switch", configured: killSwitchConfigured(cfg)},
		{name: "emit", configured: emitConfigured(cfg)},
		{name: "address_protection", configured: addressProtectionConfigured(cfg)},
		{name: "mcp_tool_policy.redirect_profiles", configured: redirectConfigured(cfg)},
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if !c.configured {
			out = append(out, c.name)
		}
	}
	return out
}

func killSwitchConfigured(cfg *config.Config) bool {
	return cfg.KillSwitch.Enabled ||
		cfg.KillSwitch.SentinelFile != "" ||
		cfg.EffectiveKillSwitchAPITokenConfigured()
}

func emitConfigured(cfg *config.Config) bool {
	return cfg.Emit.Webhook.URL != "" ||
		cfg.Emit.Syslog.Address != "" ||
		cfg.Emit.OTLP.Endpoint != ""
}

func addressProtectionConfigured(cfg *config.Config) bool {
	return cfg.AddressProtection.Enabled
}

func redirectConfigured(cfg *config.Config) bool {
	if !cfg.MCPToolPolicy.Enabled {
		return false
	}
	if len(cfg.MCPToolPolicy.RedirectProfiles) > 0 {
		return true
	}
	for _, rule := range cfg.MCPToolPolicy.Rules {
		if rule.Action == config.ActionRedirect || rule.RedirectProfile != "" {
			return true
		}
	}
	return cfg.MCPToolPolicy.Action == config.ActionRedirect
}

func resolvedAvailableKnobsConfig(cfg *config.Config) *config.Config {
	if cfg == nil {
		return config.Defaults()
	}
	resolved, _ := runtimeconfig.ResolveAndReportConfig(cfg, config.RuntimeResolveOpts{Mode: config.RuntimeForward}, nil, "check")
	return resolved
}
