// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateAirlock_Disabled(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = false
	if err := cfg.validateAirlock(); err != nil {
		t.Errorf("disabled airlock should validate: %v", err)
	}
}

func TestValidateAirlock_ValidDefaults(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = true
	cfg.SessionProfiling.Enabled = true
	if err := cfg.validateAirlock(); err != nil {
		t.Errorf("default airlock config should validate: %v", err)
	}
}

func TestValidateAirlock_InvalidTier(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = true
	cfg.SessionProfiling.Enabled = true
	cfg.Airlock.Triggers.OnElevated = "bogus"
	if err := cfg.validateAirlock(); err == nil {
		t.Error("invalid tier name should fail validation")
	}
}

func TestValidateAirlock_NonMonotonic(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = true
	cfg.SessionProfiling.Enabled = true
	cfg.Airlock.Triggers.OnElevated = AirlockTierHard
	cfg.Airlock.Triggers.OnHigh = AirlockTierSoft // lower than elevated
	cfg.Airlock.Triggers.OnCritical = AirlockTierDrain
	if err := cfg.validateAirlock(); err == nil {
		t.Error("non-monotonic tiers should fail validation")
	}
}

func TestValidateAirlock_InvalidSeverity(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = true
	cfg.SessionProfiling.Enabled = true
	cfg.Airlock.Triggers.OnSeverity = "low"
	err := cfg.validateAirlock()
	if err == nil || !strings.Contains(err.Error(), "on_severity is not enforced") {
		t.Fatalf("validateAirlock() error = %v, want reserved on_severity refusal", err)
	}
}

func TestValidateAirlock_OnSeverityIsRejected(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = true
	cfg.SessionProfiling.Enabled = true
	cfg.Airlock.Triggers.OnSeverity = SeverityCritical
	err := cfg.validateAirlock()
	if err == nil || !strings.Contains(err.Error(), "on_severity is not enforced") {
		t.Fatalf("validateAirlock() error = %v, want reserved on_severity refusal", err)
	}
}

func TestValidateAirlock_NegativeTimers(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = true
	cfg.SessionProfiling.Enabled = true
	cfg.Airlock.Timers.SoftMinutes = -1
	if err := cfg.validateAirlock(); err == nil {
		t.Error("negative timer should fail validation")
	}
}

func TestValidateAirlock_NegativeDrainTimeout(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = true
	cfg.SessionProfiling.Enabled = true
	cfg.Airlock.Timers.DrainTimeoutSeconds = -1
	if err := cfg.validateAirlock(); err == nil {
		t.Error("negative drain timeout should fail validation")
	}
}

func TestValidateAirlock_AnomalyCountIsRejected(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		count int
	}{
		{name: "positive", count: 3},
		{name: "negative", count: -3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Airlock.Enabled = true
			cfg.SessionProfiling.Enabled = true
			cfg.Airlock.Triggers.AnomalyCount = tc.count
			err := cfg.validateAirlock()
			if err == nil || !strings.Contains(err.Error(), "anomaly_count is not enforced") {
				t.Fatalf("validateAirlock(count=%d) error = %v, want reserved anomaly_count refusal", tc.count, err)
			}
		})
	}
}

func TestValidateAirlock_ReservedFieldsRejectedWhenDisabled(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		set  func(*Config)
		want string
	}{
		{
			name: "on_severity",
			set:  func(c *Config) { c.Airlock.Triggers.OnSeverity = SeverityCritical },
			want: "on_severity is not enforced",
		},
		{
			name: "anomaly_count",
			set:  func(c *Config) { c.Airlock.Triggers.AnomalyCount = 3 },
			want: "anomaly_count is not enforced",
		},
		{
			name: "anomaly_window_minutes",
			set:  func(c *Config) { c.Airlock.Triggers.AnomalyWindowMinutes = 5 },
			want: "anomaly_window_minutes is not enforced",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Airlock.Enabled = false
			tc.set(cfg)
			err := cfg.validateAirlock()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateAirlock(disabled, %s) error = %v, want %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestValidateAirlock_AnomalyWindowIsRejected(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		minutes int
	}{
		{name: "positive", minutes: 5},
		{name: "negative", minutes: -5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Airlock.Enabled = true
			cfg.SessionProfiling.Enabled = true
			cfg.Airlock.Triggers.AnomalyWindowMinutes = tc.minutes
			err := cfg.validateAirlock()
			if err == nil || !strings.Contains(err.Error(), "anomaly_window_minutes is not enforced") {
				t.Fatalf("validateAirlock(minutes=%d) error = %v, want reserved anomaly_window_minutes refusal", tc.minutes, err)
			}
		})
	}
}

func TestValidateBrowserShield_Disabled(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.BrowserShield.Enabled = false
	if err := cfg.validateBrowserShield(); err != nil {
		t.Errorf("disabled shield should validate: %v", err)
	}
}

func TestValidateBrowserShield_ValidDefaults(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.BrowserShield.Enabled = true
	if err := cfg.validateBrowserShield(); err != nil {
		t.Errorf("default shield config should validate: %v", err)
	}
}

func TestValidateBrowserShield_InvalidStrictness(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = "ultra"
	if err := cfg.validateBrowserShield(); err == nil {
		t.Error("invalid strictness should fail validation")
	}
}

func TestValidateBrowserShield_InvalidOversizeAction(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.OversizeAction = "ignore"
	if err := cfg.validateBrowserShield(); err == nil {
		t.Error("invalid oversize action should fail validation")
	}
}

func TestValidateBrowserShield_WarnRequiresMinimal(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = ShieldStrictnessStandard
	cfg.BrowserShield.OversizeAction = ShieldOversizeWarn
	if err := cfg.validateBrowserShield(); err == nil {
		t.Error("warn + standard strictness should fail validation")
	}
}

func TestValidateBrowserShield_WarnWithMinimal(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = ShieldStrictnessMinimal
	cfg.BrowserShield.OversizeAction = ShieldOversizeWarn
	if err := cfg.validateBrowserShield(); err != nil {
		t.Errorf("warn + minimal strictness should validate: %v", err)
	}
}

func TestValidateBrowserShield_NegativeMaxBytes(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.MaxShieldBytes = -1
	if err := cfg.validateBrowserShield(); err == nil {
		t.Error("negative max bytes should fail validation")
	}
}

func TestValidateBrowserShield_InvalidExemptDomain(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.ExemptDomains = []string{"https://example.com/path"}
	if err := cfg.validateBrowserShield(); err == nil {
		t.Error("URL in exempt domains should fail validation")
	}
}
