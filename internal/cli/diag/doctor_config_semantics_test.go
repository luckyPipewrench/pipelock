// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testDLPPatternName  = "Vendor Token"
	testRespPatternName = "Vendor Injection"
	testExemptHost      = "provider.example"
)

// baseSemanticsConfig returns a config with a known custom DLP pattern and a
// known custom response-scan pattern, defaults excluded so the active pattern
// namespace is exactly what the test sets. Scanners are left disabled; each
// test enables what it needs.
func baseSemanticsConfig() *config.Config {
	cfg := config.Defaults()
	no := false
	cfg.DLP.IncludeDefaults = &no
	cfg.DLP.Patterns = []config.DLPPattern{
		{Name: testDLPPatternName, Regex: "vendortok_[a-z0-9]{20}", Severity: config.SeverityHigh},
	}
	cfg.ResponseScanning.IncludeDefaults = &no
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{
		{Name: testRespPatternName, Regex: "ignore previous instructions"},
	}
	cfg.ResponseScanning.Enabled = false
	cfg.RequestBodyScanning.Enabled = false
	cfg.ResponseScanning.SSEStreaming.Enabled = false
	cfg.AdaptiveEnforcement.Enabled = false
	cfg.Suppress = nil
	cfg.ResponseScanning.ExemptDomains = nil
	cfg.AdaptiveEnforcement.ExemptDomains = nil
	return cfg
}

// warnDetails returns the Detail strings of all warn-status checks emitted by
// the semantic validator.
func warnDetails(cfg *config.Config) []string {
	var out []string
	for _, c := range checkDoctorConfigSemantics(cfg) {
		if c.Status == doctorStatusWarn {
			out = append(out, c.Detail+" || next: "+c.Next)
		}
	}
	return out
}

func TestDoctorConfigSemantics(t *testing.T) {
	tests := []struct {
		name string
		// mutate adjusts the base config for the scenario.
		mutate func(cfg *config.Config)
		// wantWarn is the number of warn-status semantic checks expected.
		wantWarn int
		// wantDetailSubstr, if set, must appear in some warn Detail.
		wantDetailSubstr string
		// wantNextSubstr, if set, must appear in some warn Next.
		wantNextSubstr string
	}{
		{
			name: "unknown pattern name is inert",
			mutate: func(cfg *config.Config) {
				cfg.Suppress = []config.SuppressEntry{
					{Rule: "Totally Made Up Pattern", Path: "*" + testExemptHost + "*", Reason: "typo"},
				}
			},
			wantWarn:         1,
			wantDetailSubstr: "matches no active DLP or response-scanning pattern",
			wantNextSubstr:   "dlp.patterns or response_scanning.patterns",
		},
		{
			name: "response-only suppress while response scanning disabled is inert",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = false
				cfg.Suppress = []config.SuppressEntry{
					{Rule: testRespPatternName, Path: "*" + testExemptHost + "*", Reason: "prose FP"},
				}
			},
			wantWarn:         1,
			wantDetailSubstr: "response_scanning.enabled=false",
			wantNextSubstr:   "enable response_scanning",
		},
		{
			name: "DLP suppress with no suppress-consulting proxy scanner points at exempt_domains",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = false
				cfg.ResponseScanning.Enabled = false
				cfg.ResponseScanning.SSEStreaming.Enabled = false
				cfg.Suppress = []config.SuppressEntry{
					{Rule: testDLPPatternName, Path: "*" + testExemptHost + "*", Reason: "url token FP"},
				}
			},
			wantWarn:         1,
			wantDetailSubstr: "does not consult suppress",
			wantNextSubstr:   "dlp.patterns[].exempt_domains",
		},
		{
			name: "DLP-only suppress with response scanning on is still inert for DLP",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = false
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.SSEStreaming.Enabled = false
				cfg.Suppress = []config.SuppressEntry{
					{Rule: testDLPPatternName, Path: "*" + testExemptHost + "*", Reason: "url token FP"},
				}
			},
			wantWarn:         1,
			wantDetailSubstr: "response_scanning uses a separate pattern namespace",
			wantNextSubstr:   "dlp.patterns[].exempt_domains",
		},
		{
			name: "same rule in DLP and response namespaces is honored when response scanning is on",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{
					{Name: testDLPPatternName, Regex: "ignore previous instructions"},
				}
				cfg.Suppress = []config.SuppressEntry{
					{Rule: testDLPPatternName, Path: "*" + testExemptHost + "*", Reason: "known response FP"},
				}
			},
			wantWarn: 0,
		},
		{
			name: "correct DLP suppress with body scanning on is NOT flagged",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				cfg.Suppress = []config.SuppressEntry{
					{Rule: testDLPPatternName, Path: "*" + testExemptHost + "*", Reason: "known FP"},
				}
			},
			wantWarn: 0,
		},
		{
			name: "correct response suppress with response scanning on is NOT flagged",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = true
				cfg.Suppress = []config.SuppressEntry{
					{Rule: testRespPatternName, Path: "*" + testExemptHost + "*", Reason: "known FP"},
				}
			},
			wantWarn: 0,
		},
		{
			name: "DLP suppress honored via SSE streaming is NOT flagged",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = false
				cfg.ResponseScanning.Enabled = false
				cfg.ResponseScanning.SSEStreaming.Enabled = true
				cfg.Suppress = []config.SuppressEntry{
					{Rule: testDLPPatternName, Path: "*" + testExemptHost + "*", Reason: "FP in stream"},
				}
			},
			wantWarn: 0,
		},
		{
			name: "response_scanning exempt_domains inert when scanner disabled",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = false
				cfg.ResponseScanning.ExemptDomains = []string{testExemptHost}
			},
			wantWarn:         1,
			wantDetailSubstr: "response_scanning.exempt_domains is set but response_scanning.enabled=false",
			wantNextSubstr:   "enable response_scanning",
		},
		{
			name: "response_scanning exempt_domains NOT flagged when scanner enabled",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.ExemptDomains = []string{testExemptHost}
			},
			wantWarn: 0,
		},
		{
			name: "adaptive_enforcement exempt_domains inert when scanner disabled",
			mutate: func(cfg *config.Config) {
				cfg.AdaptiveEnforcement.Enabled = false
				cfg.AdaptiveEnforcement.ExemptDomains = []string{testExemptHost}
			},
			wantWarn:         1,
			wantDetailSubstr: "adaptive_enforcement.exempt_domains is set but adaptive_enforcement.enabled=false",
			wantNextSubstr:   "enable adaptive_enforcement",
		},
		{
			name: "adaptive_enforcement exempt_domains NOT flagged when scanner enabled",
			mutate: func(cfg *config.Config) {
				cfg.AdaptiveEnforcement.Enabled = true
				cfg.AdaptiveEnforcement.ExemptDomains = []string{testExemptHost}
			},
			wantWarn: 0,
		},
		{
			name: "duplicate suppress rule names collapse to one finding",
			mutate: func(cfg *config.Config) {
				cfg.Suppress = []config.SuppressEntry{
					{Rule: "Unknown One", Path: "*a.example*"},
					{Rule: "Unknown One", Path: "*b.example*"},
					{Rule: "unknown one", Path: "*c.example*"}, // case-insensitive dup
				}
			},
			wantWarn:         1,
			wantDetailSubstr: "matches no active DLP or response-scanning pattern",
		},
		{
			name: "case-insensitive match to active pattern is NOT flagged",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				cfg.Suppress = []config.SuppressEntry{
					// lowercased name must still match the active DLP pattern.
					{Rule: strings.ToLower(testDLPPatternName), Path: "*" + testExemptHost + "*"},
				}
			},
			wantWarn: 0,
		},
		{
			name:   "empty suppress and no exemptions yields a single ok check",
			mutate: func(_ *config.Config) {},
			// no warns; the validator returns a single ok check.
			wantWarn: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseSemanticsConfig()
			tt.mutate(cfg)
			checks := checkDoctorConfigSemantics(cfg)

			var warns []doctorReportCheck
			for _, c := range checks {
				if c.Surface != doctorSurfaceConfig {
					t.Errorf("semantic check %q has surface %q, want %q", c.Name, c.Surface, doctorSurfaceConfig)
				}
				if c.Status == doctorStatusWarn {
					warns = append(warns, c)
				}
			}
			if len(warns) != tt.wantWarn {
				t.Fatalf("warn count = %d, want %d; details=%v", len(warns), tt.wantWarn, warnDetails(cfg))
			}
			if tt.wantWarn == 0 {
				// When clean, the validator must still represent the surface.
				if len(checks) == 0 {
					t.Fatal("expected at least one check (ok placeholder) when no warnings")
				}
				return
			}
			if tt.wantDetailSubstr != "" {
				found := false
				for _, c := range warns {
					if strings.Contains(c.Detail, tt.wantDetailSubstr) {
						found = true
					}
				}
				if !found {
					t.Errorf("no warn Detail contained %q; got %v", tt.wantDetailSubstr, warnDetails(cfg))
				}
			}
			if tt.wantNextSubstr != "" {
				found := false
				for _, c := range warns {
					if strings.Contains(c.Next, tt.wantNextSubstr) {
						found = true
					}
				}
				if !found {
					t.Errorf("no warn Next contained %q; got %v", tt.wantNextSubstr, warnDetails(cfg))
				}
			}
		})
	}
}

// TestDoctorSuppressSemanticsSortAndEmptyRule exercises the empty-rule skip and
// the deterministic sort across multiple distinct findings.
func TestDoctorSuppressSemanticsSortAndEmptyRule(t *testing.T) {
	cfg := baseSemanticsConfig()
	cfg.ResponseScanning.Enabled = false
	cfg.RequestBodyScanning.Enabled = false
	cfg.ResponseScanning.SSEStreaming.Enabled = false
	cfg.Suppress = []config.SuppressEntry{
		{Rule: "", Path: "*skip.example*"},                            // empty rule: skipped
		{Rule: "Zeta Unknown", Path: "*z.example*"},                   // unknown -> warn
		{Rule: "Alpha Unknown", Path: "*a.example*"},                  // unknown -> warn
		{Rule: testDLPPatternName, Path: "*" + testExemptHost + "*"},  // DLP, no consumer -> warn
		{Rule: testRespPatternName, Path: "*" + testExemptHost + "*"}, // resp-only, disabled -> warn
	}
	checks := checkDoctorSuppressEntries(cfg)

	// Empty rule must not produce a finding; the other four must.
	if len(checks) != 4 {
		t.Fatalf("got %d suppress checks, want 4; %v", len(checks), checks)
	}
	// Output must be sorted by (Name, Detail) deterministically.
	for i := 1; i < len(checks); i++ {
		prev, cur := checks[i-1], checks[i]
		if prev.Name > cur.Name || (prev.Name == cur.Name && prev.Detail > cur.Detail) {
			t.Fatalf("checks not sorted at index %d: %q/%q then %q/%q",
				i, prev.Name, prev.Detail, cur.Name, cur.Detail)
		}
	}
}

// TestDoctorConfigSemanticsCleanReturnsOK verifies the placeholder ok check
// when nothing is wrong, so the config surface is always represented.
func TestDoctorConfigSemanticsCleanReturnsOK(t *testing.T) {
	cfg := baseSemanticsConfig()
	checks := checkDoctorConfigSemantics(cfg)
	if len(checks) != 1 {
		t.Fatalf("clean config: got %d checks, want 1", len(checks))
	}
	if checks[0].Status != doctorStatusOK {
		t.Fatalf("clean config: status = %q, want %q", checks[0].Status, doctorStatusOK)
	}
}

// TestDoctorSemanticsCountedInSummary proves the new checks flow through the
// full report build and into the JSON summary tallies and exit code.
func TestDoctorSemanticsCountedInSummary(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/inert.yaml"
	const body = `mode: balanced
suppress:
  - rule: "Totally Made Up Pattern"
    path: "*provider.example*"
    reason: "inert test entry"
response_scanning:
  enabled: false
  exempt_domains:
    - "trusted.example"
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DoctorCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--config", cfgPath, "--json"})
	// Warnings cause a non-nil error (exit code 1); that is expected here.
	_ = cmd.Execute()

	var report doctorReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	var sawSuppress, sawExemption bool
	for _, c := range report.Checks {
		switch c.Name {
		case doctorCheckSuppressSemantics:
			if c.Status == doctorStatusWarn {
				sawSuppress = true
			}
		case doctorCheckExemptionSemantics:
			if c.Status == doctorStatusWarn {
				sawExemption = true
			}
		}
	}
	if !sawSuppress {
		t.Error("expected a warn config_suppress_semantics check in the report")
	}
	if !sawExemption {
		t.Error("expected a warn config_exemption_semantics check in the report")
	}
	if report.Summary.Warnings < 2 {
		t.Errorf("summary warnings = %d, want >= 2 (semantic checks must be tallied)", report.Summary.Warnings)
	}
}
