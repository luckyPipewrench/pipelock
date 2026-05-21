// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// Each v2 category scorer is exercised in two states: feature disabled
// (must produce zero score and at least one finding when defensive
// guidance applies) and feature fully configured (must reach its max
// budget). Edge-case branches are added selectively where the scorer's
// behavior is non-obvious.

func TestScoreLiveLockContracts(t *testing.T) {
	t.Run("disabled emits info finding", func(t *testing.T) {
		cfg := &config.Config{}
		var findings []ScoreFinding
		cat := scoreLiveLockContracts(cfg, &findings)
		if cat.Score != 0 || cat.MaxScore != maxLiveLockScore {
			t.Fatalf("got %+v, want score 0 max %d", cat, maxLiveLockScore)
		}
		if !hasCategoryFinding(findings, CategoryLiveLockContracts) {
			t.Error("disabled should emit a finding")
		}
	})
	t.Run("live mode hits max", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.LearnLock.Enabled = true
		cfg.LearnLock.Mode = config.LockModeLive
		var findings []ScoreFinding
		cat := scoreLiveLockContracts(cfg, &findings)
		if cat.Score != maxLiveLockScore {
			t.Errorf("live mode score = %d, want %d", cat.Score, maxLiveLockScore)
		}
	})
	t.Run("capture mode warns", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.LearnLock.Enabled = true
		cfg.LearnLock.Mode = config.LockModeCapture
		var findings []ScoreFinding
		_ = scoreLiveLockContracts(cfg, &findings)
		var found bool
		for _, f := range findings {
			if f.Severity == scoreSevWarning && strings.Contains(f.Message, "silent") {
				found = true
			}
		}
		if !found {
			t.Error("capture mode should produce a warning")
		}
	})
}

func TestScoreRedaction(t *testing.T) {
	t.Run("disabled emits warning", func(t *testing.T) {
		var findings []ScoreFinding
		cat := scoreRedaction(&config.Config{}, &findings)
		if cat.Score != 0 || !hasCategoryFinding(findings, CategoryRedaction) {
			t.Errorf("disabled should score 0 and emit finding; got %+v findings=%d", cat, len(findings))
		}
	})
	t.Run("fully configured hits max", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Redaction.Enabled = true
		cfg.Redaction.DefaultProfile = "p1"
		cfg.Redaction.Profiles = map[string]redact.ProfileSpec{"p1": {}}
		cfg.Redaction.StrictReload = true
		var findings []ScoreFinding
		cat := scoreRedaction(cfg, &findings)
		if cat.Score != maxRedactionScore {
			t.Errorf("score = %d, want %d", cat.Score, maxRedactionScore)
		}
	})
}

func TestScoreBrowserShield(t *testing.T) {
	cfg := &config.Config{}
	cfg.BrowserShield.Enabled = true
	cfg.BrowserShield.Strictness = "aggressive"
	cat := scoreBrowserShield(cfg, &[]ScoreFinding{})
	if cat.Score != maxBrowserShieldScore {
		t.Errorf("aggressive should hit max %d, got %d", maxBrowserShieldScore, cat.Score)
	}

	cfg2 := &config.Config{}
	cfg2.BrowserShield.Enabled = true
	cfg2.BrowserShield.Strictness = "minimal"
	var findings []ScoreFinding
	_ = scoreBrowserShield(cfg2, &findings)
	if !hasCategoryFinding(findings, CategoryBrowserShield) {
		t.Error("minimal strictness should warn")
	}
}

func TestScoreMediationEnvelope(t *testing.T) {
	cfg := &config.Config{}
	cfg.MediationEnvelope.Enabled = true
	cfg.MediationEnvelope.Sign = true
	cat := scoreMediationEnvelope(cfg, &[]ScoreFinding{})
	if cat.Score != maxMediationScore {
		t.Errorf("signed envelope should hit max, got %d", cat.Score)
	}

	cfg2 := &config.Config{}
	cfg2.MediationEnvelope.Enabled = true
	var findings []ScoreFinding
	_ = scoreMediationEnvelope(cfg2, &findings)
	if !hasCategoryFinding(findings, CategoryMediationEnvelope) {
		t.Error("envelope without signing should produce info finding")
	}
}

func TestScoreFlightRecorder(t *testing.T) {
	cfg := &config.Config{}
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.SignCheckpoints = true
	cfg.FlightRecorder.Redact = true
	cat := scoreFlightRecorder(cfg, &[]ScoreFinding{})
	if cat.Score != maxFlightRecorderScore {
		t.Errorf("signed+redact should hit max, got %d", cat.Score)
	}

	cfg2 := &config.Config{}
	cfg2.FlightRecorder.Enabled = true // no signing, no redact
	var findings []ScoreFinding
	_ = scoreFlightRecorder(cfg2, &findings)
	// Two warnings expected: no signing, no redact.
	warnings := 0
	for _, f := range findings {
		if f.Severity == scoreSevWarning {
			warnings++
		}
	}
	if warnings < 2 {
		t.Errorf("expected at least 2 warnings, got %d", warnings)
	}
}

func TestScoreRequestBodyScanning(t *testing.T) {
	t.Run("disabled is critical", func(t *testing.T) {
		var findings []ScoreFinding
		_ = scoreRequestBodyScanning(&config.Config{}, &findings)
		var found bool
		for _, f := range findings {
			if f.Severity == scoreSevCritical && f.Category == CategoryRequestBody {
				found = true
			}
		}
		if !found {
			t.Error("disabled request body scanning should be a critical finding")
		}
	})
	t.Run("fully configured hits max", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.ScanHeaders = true
		cat := scoreRequestBodyScanning(cfg, &[]ScoreFinding{})
		if cat.Score != maxRequestBodyScore {
			t.Errorf("score = %d, want %d", cat.Score, maxRequestBodyScore)
		}
	})
}

func TestScoreCrossRequestDetection(t *testing.T) {
	cfg := &config.Config{}
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	cat := scoreCrossRequestDetection(cfg, &[]ScoreFinding{})
	if cat.Score != maxCrossRequestScore {
		t.Errorf("score = %d, want %d", cat.Score, maxCrossRequestScore)
	}
}

func TestScoreAddressProtection(t *testing.T) {
	cfg := &config.Config{}
	cfg.AddressProtection.Enabled = true
	cfg.AddressProtection.Action = config.ActionBlock
	cfg.AddressProtection.UnknownAction = config.ActionBlock
	cat := scoreAddressProtection(cfg, &[]ScoreFinding{})
	if cat.Score != maxAddressScore {
		t.Errorf("score = %d, want %d", cat.Score, maxAddressScore)
	}
}

func TestScoreSeedPhraseDetection_DefaultsOn(t *testing.T) {
	// Nil Enabled means default true. Verify the security-by-default path.
	cat := scoreSeedPhraseDetection(&config.Config{}, &[]ScoreFinding{})
	if cat.Score != maxSeedPhraseScore {
		t.Errorf("default seed-phrase config should score max %d, got %d", maxSeedPhraseScore, cat.Score)
	}
}

func TestScoreSeedPhraseDetection_ExplicitlyDisabled(t *testing.T) {
	cfg := &config.Config{}
	off := false
	cfg.SeedPhraseDetection.Enabled = &off
	var findings []ScoreFinding
	cat := scoreSeedPhraseDetection(cfg, &findings)
	if cat.Score != 0 {
		t.Errorf("explicitly disabled should score 0, got %d", cat.Score)
	}
	if !hasCategoryFinding(findings, CategorySeedPhrase) {
		t.Error("explicitly disabled seed-phrase detection should emit a finding")
	}
}

func TestScoreSeedPhraseDetection_ChecksumDisabledWarns(t *testing.T) {
	cfg := &config.Config{}
	off := false
	cfg.SeedPhraseDetection.VerifyChecksum = &off
	var findings []ScoreFinding
	_ = scoreSeedPhraseDetection(cfg, &findings)
	if !hasCategoryFinding(findings, CategorySeedPhrase) {
		t.Error("checksum-disabled seed-phrase detection should emit a finding")
	}
}

func TestScoreGitProtection(t *testing.T) {
	cfg := &config.Config{}
	cfg.GitProtection.Enabled = true
	cfg.GitProtection.PrePushScan = true
	cfg.GitProtection.BlockedCommands = []string{"force-push"}
	cat := scoreGitProtection(cfg, &[]ScoreFinding{})
	if cat.Score != maxGitProtectionScore {
		t.Errorf("score = %d, want %d", cat.Score, maxGitProtectionScore)
	}
}

func TestScoreFileSentry_NoWatchPathsWarns(t *testing.T) {
	cfg := &config.Config{}
	cfg.FileSentry.Enabled = true
	// Intentionally no WatchPaths — config is enabled but inert.
	var findings []ScoreFinding
	_ = scoreFileSentry(cfg, &findings)
	if !hasCategoryFinding(findings, CategoryFileSentry) {
		t.Error("enabled file sentry with no watch_paths should warn")
	}
}

func TestScoreFileSentry_DisabledEmitsFinding(t *testing.T) {
	var findings []ScoreFinding
	cat := scoreFileSentry(&config.Config{}, &findings)
	if cat.Score != 0 {
		t.Errorf("disabled file sentry score = %d, want 0", cat.Score)
	}
	if !hasCategoryFinding(findings, CategoryFileSentry) {
		t.Error("disabled file sentry should emit a finding")
	}
}

// hasCategoryFinding returns true if any finding's Category matches.
func hasCategoryFinding(findings []ScoreFinding, category string) bool {
	for _, f := range findings {
		if f.Category == category {
			return true
		}
	}
	return false
}
