// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Category name constants — shared with the assess remediation lookup so
// the two files cannot drift. Keep these aligned with the cases in
// internal/cli/assess/score.go auditRemediation().
const (
	CategoryLiveLockContracts = "Live-Lock Contracts"
	CategoryRedaction         = "Redaction"
	CategoryBrowserShield     = "Browser Shield"
	CategoryMediationEnvelope = "Mediation Envelope"
	CategoryFlightRecorder    = "Flight Recorder"
	CategoryRequestBody       = "Request Body Scanning"
	CategoryCrossRequest      = "Cross-Request Detection"
	CategoryAddressProtect    = "Address Protection"
	CategorySeedPhrase        = "Seed-Phrase Detection"
	CategoryGitProtection     = "Git Protection"
	CategoryFileSentry        = "File Sentry"
)

// Point budgets for new v2 categories. Sum = 70.
const (
	maxLiveLockScore       = 10
	maxRedactionScore      = 10
	maxBrowserShieldScore  = 5
	maxMediationScore      = 5
	maxFlightRecorderScore = 5
	maxRequestBodyScore    = 10
	maxCrossRequestScore   = 5
	maxAddressScore        = 5
	maxSeedPhraseScore     = 5
	maxGitProtectionScore  = 5
	maxFileSentryScore     = 5
)

// Browser-shield strictness levels — repeated across the scorer and
// would-be-extracted by goconst anyway.
const (
	browserShieldAggressive = "aggressive"
	browserShieldStandard   = "standard"
	browserShieldMinimal    = "minimal"
)

// scoreLiveLockContracts evaluates the contract gate (formerly "learn lock").
// Live mode is the enforcement posture; shadow is observation only.
func scoreLiveLockContracts(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.LearnLock.Enabled {
		score += 4
		switch cfg.LearnLock.Mode {
		case config.LockModeLive:
			score += 6
		case config.LockModeShadow:
			score += 3
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevInfo,
				Category: CategoryLiveLockContracts,
				Message:  "Contract gate is in shadow mode — drift is observed but never blocked",
			})
		case config.LockModeCapture, "":
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: CategoryLiveLockContracts,
				Message:  "Contract gate is enabled but mode is silent (no signal, no receipts)",
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: CategoryLiveLockContracts,
			Message:  "Live-lock contracts are disabled — agent behavior drift is not gated",
		})
	}
	return ScoreCategory{Name: CategoryLiveLockContracts, Score: min(score, maxLiveLockScore), MaxScore: maxLiveLockScore}
}

// scoreRedaction evaluates class-preserving redaction.
func scoreRedaction(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.Redaction.Enabled {
		score += 4
		if cfg.Redaction.DefaultProfile != "" {
			score += 2
		}
		if len(cfg.Redaction.Profiles) > 0 {
			score += 2
		}
		if cfg.Redaction.StrictReload {
			score += 2
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevInfo,
				Category: CategoryRedaction,
				Message:  "Redaction strict_reload is off — dictionary corruption falls back to last snapshot instead of failing closed",
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevWarning,
			Category: CategoryRedaction,
			Message:  "Redaction is disabled — provider request/response bodies are not class-preserved",
		})
	}
	return ScoreCategory{Name: CategoryRedaction, Score: min(score, maxRedactionScore), MaxScore: maxRedactionScore}
}

// scoreBrowserShield evaluates DOM/script shielding for fetch responses.
func scoreBrowserShield(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.BrowserShield.Enabled {
		score += 2
		switch cfg.BrowserShield.Strictness {
		case browserShieldAggressive:
			score += 3
		case browserShieldStandard:
			score += 2
		case browserShieldMinimal:
			score += 1
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevInfo,
				Category: CategoryBrowserShield,
				Message:  "Browser shield strictness is minimal — DOM injection vectors are largely unfiltered",
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: CategoryBrowserShield,
			Message:  "Browser shield is disabled — fetch responses are not stripped of DOM traps or tracking pixels",
		})
	}
	return ScoreCategory{Name: CategoryBrowserShield, Score: min(score, maxBrowserShieldScore), MaxScore: maxBrowserShieldScore}
}

// scoreMediationEnvelope evaluates RFC 9421 outbound signature and SPIFFE
// federation. Signing without a key path is a misconfiguration that
// pipelock catches at startup; we flag the absence of opt-in here.
func scoreMediationEnvelope(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.MediationEnvelope.Enabled {
		score += 2
		if cfg.MediationEnvelope.Sign {
			score += 3
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevInfo,
				Category: CategoryMediationEnvelope,
				Message:  "Mediation envelope is enabled but outbound signing is off — downstream verifiers cannot attest the request",
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: CategoryMediationEnvelope,
			Message:  "Mediation envelope is disabled — no federation verification of inbound or signed receipts on outbound",
		})
	}
	return ScoreCategory{Name: CategoryMediationEnvelope, Score: min(score, maxMediationScore), MaxScore: maxMediationScore}
}

// scoreFlightRecorder evaluates tamper-evident decision recording.
func scoreFlightRecorder(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.FlightRecorder.Enabled {
		score += 2
		if cfg.FlightRecorder.SignCheckpoints {
			score += 2
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: CategoryFlightRecorder,
				Message:  "Flight recorder runs but does not sign checkpoints — recorded evidence has no tamper-evident proof",
			})
		}
		if cfg.FlightRecorder.Redact {
			score += 1
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: CategoryFlightRecorder,
				Message:  "Flight recorder is not running DLP on evidence — secrets observed in scanned content land in the recorder verbatim",
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: CategoryFlightRecorder,
			Message:  "Flight recorder is disabled — no replayable per-decision evidence is produced",
		})
	}
	return ScoreCategory{Name: CategoryFlightRecorder, Score: min(score, maxFlightRecorderScore), MaxScore: maxFlightRecorderScore}
}

// scoreRequestBodyScanning evaluates body-level DLP and injection for
// arbitrary HTTP/HTTPS request bodies traversing the proxy.
func scoreRequestBodyScanning(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.RequestBodyScanning.Enabled {
		score += 4
		if cfg.RequestBodyScanning.Action == config.ActionBlock {
			score += 3
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: CategoryRequestBody,
				Message:  fmt.Sprintf("Request body scanning action is %q — consider 'block' for enforcement", cfg.RequestBodyScanning.Action),
			})
		}
		if cfg.RequestBodyScanning.ScanHeaders {
			score += 3
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: CategoryRequestBody,
				Message:  "Request header DLP is off — secrets in Authorization, X-API-Key, or similar headers will not be detected",
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevCritical,
			Category: CategoryRequestBody,
			Message:  "Request body scanning is disabled — secrets sent in POST/PUT bodies are not detected",
		})
	}
	return ScoreCategory{Name: CategoryRequestBody, Score: min(score, maxRequestBodyScore), MaxScore: maxRequestBodyScore}
}

// scoreCrossRequestDetection evaluates entropy-budget and fragment
// reassembly detection across multiple outbound requests in a session.
func scoreCrossRequestDetection(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.CrossRequestDetection.Enabled {
		score += 2
		if cfg.CrossRequestDetection.EntropyBudget.Enabled {
			score += 2
		}
		if cfg.CrossRequestDetection.FragmentReassembly.Enabled {
			score += 1
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: CategoryCrossRequest,
			Message:  "Cross-request detection is disabled — secrets split across multiple requests will not be reassembled",
		})
	}
	return ScoreCategory{Name: CategoryCrossRequest, Score: min(score, maxCrossRequestScore), MaxScore: maxCrossRequestScore}
}

// scoreAddressProtection evaluates blockchain address detection and the
// poisoning/lookalike guard. Enforce mode is the value here.
func scoreAddressProtection(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.AddressProtection.Enabled {
		score += 2
		if cfg.AddressProtection.Action == config.ActionBlock {
			score += 2
		}
		switch cfg.AddressProtection.UnknownAction {
		case config.ActionBlock:
			score += 1
		case config.ActionWarn:
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevInfo,
				Category: CategoryAddressProtect,
				Message:  "Address protection allows unknown addresses with a warning — a strict allowlist with action=block tightens the surface",
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: CategoryAddressProtect,
			Message:  "Address protection is disabled — blockchain address poisoning is not detected",
		})
	}
	return ScoreCategory{Name: CategoryAddressProtect, Score: min(score, maxAddressScore), MaxScore: maxAddressScore}
}

// scoreSeedPhraseDetection evaluates BIP-39 mnemonic detection.
// Note: Enabled defaults to true when nil (security-by-default).
func scoreSeedPhraseDetection(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	enabled := cfg.SeedPhraseDetection.Enabled == nil || *cfg.SeedPhraseDetection.Enabled
	if enabled {
		score += 3
		verify := cfg.SeedPhraseDetection.VerifyChecksum == nil || *cfg.SeedPhraseDetection.VerifyChecksum
		if verify {
			score += 2
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: CategorySeedPhrase,
				Message:  "Seed-phrase checksum verification is disabled — mnemonic-like word lists are matched without BIP-39 validation",
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevCritical,
			Category: CategorySeedPhrase,
			Message:  "Seed-phrase detection is disabled — BIP-39 mnemonic leaks will not be detected",
		})
	}
	return ScoreCategory{Name: CategorySeedPhrase, Score: min(score, maxSeedPhraseScore), MaxScore: maxSeedPhraseScore}
}

// scoreGitProtection evaluates git-aware pre-push and command gating.
func scoreGitProtection(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.GitProtection.Enabled {
		score += 2
		if cfg.GitProtection.PrePushScan {
			score += 2
		}
		if len(cfg.GitProtection.BlockedCommands) > 0 {
			score += 1
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: CategoryGitProtection,
			Message:  "Git protection is disabled — pre-push secret scans and command gating are inactive",
		})
	}
	return ScoreCategory{Name: CategoryGitProtection, Score: min(score, maxGitProtectionScore), MaxScore: maxGitProtectionScore}
}

// scoreFileSentry evaluates filesystem-watch DLP on operator-defined paths.
func scoreFileSentry(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.FileSentry.Enabled {
		score += 2
		if len(cfg.FileSentry.WatchPaths) > 0 {
			score += 2
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: CategoryFileSentry,
				Message:  "File sentry is enabled but no watch_paths configured — the feature has no effect",
			})
		}
		scanContent := cfg.FileSentry.ScanContent == nil || *cfg.FileSentry.ScanContent
		if scanContent {
			score += 1
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: CategoryFileSentry,
			Message:  "File sentry is disabled — filesystem-watch DLP is inactive",
		})
	}
	return ScoreCategory{Name: CategoryFileSentry, Score: min(score, maxFileSentryScore), MaxScore: maxFileSentryScore}
}

// scoreV2Categories returns the schema-v2 category set: features that
// shipped in v2.1-v2.5 and were absent from the original audit.
func scoreV2Categories(cfg *config.Config, findings *[]ScoreFinding) []ScoreCategory {
	return []ScoreCategory{
		scoreLiveLockContracts(cfg, findings),
		scoreRedaction(cfg, findings),
		scoreBrowserShield(cfg, findings),
		scoreMediationEnvelope(cfg, findings),
		scoreFlightRecorder(cfg, findings),
		scoreRequestBodyScanning(cfg, findings),
		scoreCrossRequestDetection(cfg, findings),
		scoreAddressProtection(cfg, findings),
		scoreSeedPhraseDetection(cfg, findings),
		scoreGitProtection(cfg, findings),
		scoreFileSentry(cfg, findings),
	}
}
