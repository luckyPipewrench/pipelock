// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
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
	if err := cfg.validateAirlock(); err == nil {
		t.Error("invalid severity should fail validation")
	}
}

func TestValidateAirlock_ValidSeverity(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = true
	cfg.SessionProfiling.Enabled = true
	cfg.Airlock.Triggers.OnSeverity = SeverityCritical
	if err := cfg.validateAirlock(); err != nil {
		t.Errorf("critical severity should validate: %v", err)
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

func TestValidateAirlock_NegativeAnomalyCount(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Airlock.Enabled = true
	cfg.SessionProfiling.Enabled = true
	cfg.Airlock.Triggers.AnomalyCount = -1
	if err := cfg.validateAirlock(); err == nil {
		t.Error("negative anomaly count should fail validation")
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
