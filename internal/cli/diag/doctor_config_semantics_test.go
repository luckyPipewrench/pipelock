// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

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
	cfg.ResponseScanning.MCPServers = nil
	cfg.AdaptiveEnforcement.ExemptDomains = nil
	cfg.CrossRequestDetection.Enabled = false
	cfg.CrossRequestDetection.EntropyBudget.Enabled = false
	cfg.CrossRequestDetection.EntropyBudget.ExemptDomains = nil
	cfg.BrowserShield.ExemptDomains = nil
	cfg.TLSInterception.PassthroughDomains = nil
	cfg.RequestBodyScanning.IgnoreHeaders = nil
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
			name: "response_scanning exempt_domains notes core caveat when scanner disabled",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = false
				cfg.ResponseScanning.ExemptDomains = []string{testExemptHost}
			},
			wantWarn:         1,
			wantDetailSubstr: "full-trust streaming bypass is inactive",
			wantNextSubstr:   "broad full-trust streaming bypass",
		},
		{
			name: "response_scanning exempt_domains warns with narrowest knob first when scanner enabled",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.ExemptDomains = []string{testExemptHost}
			},
			wantWarn:         1,
			wantDetailSubstr: "responses are fully unscanned for injection",
			wantNextSubstr:   "response_scanning.size_exempt_domains",
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
			name: "response MCP trust inert when response scanning disabled",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = false
				cfg.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{{
					Server: "docs-cache",
					Trust:  config.ResponseTrustReasoning,
				}}
			},
			wantWarn:         1,
			wantDetailSubstr: "response_scanning.mcp_servers marks \"docs-cache\" but response_scanning.enabled=false",
			wantNextSubstr:   "enable response_scanning",
		},
		{
			name: "MCP response reasoning trust is not taint trust",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{{
					Server: "docs-cache",
					Trust:  config.ResponseTrustReasoning,
				}}
			},
			wantWarn:         1,
			wantDetailSubstr: "taint.allowlisted_domains does not apply to MCP response taint",
			wantNextSubstr:   "taint.trusted_mcp_servers",
		},
		{
			name: "MCP response reasoning trust with taint trust is NOT flagged",
			mutate: func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{{
					Server: "docs-cache",
					Trust:  config.ResponseTrustReasoning,
				}}
				cfg.Taint.TrustedMCPServers = []string{"docs-cache"}
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
			name: "cross request entropy exemption inert when parent disabled",
			mutate: func(cfg *config.Config) {
				cfg.CrossRequestDetection.Enabled = false
				cfg.CrossRequestDetection.EntropyBudget.Enabled = true
				cfg.CrossRequestDetection.EntropyBudget.ExemptDomains = []string{testExemptHost}
			},
			wantWarn:         1,
			wantDetailSubstr: "cross_request_detection.enabled=false",
			wantNextSubstr:   "enable cross_request_detection",
		},
		{
			name: "cross request entropy exemption inert when entropy budget disabled",
			mutate: func(cfg *config.Config) {
				cfg.CrossRequestDetection.Enabled = true
				cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
				cfg.CrossRequestDetection.EntropyBudget.Enabled = false
				cfg.CrossRequestDetection.EntropyBudget.ExemptDomains = []string{testExemptHost}
			},
			wantWarn:         1,
			wantDetailSubstr: "cross_request_detection.entropy_budget.enabled=false",
			wantNextSubstr:   "enable cross_request_detection",
		},
		{
			name: "cross request entropy exemption NOT flagged when entropy budget enabled",
			mutate: func(cfg *config.Config) {
				cfg.CrossRequestDetection.Enabled = true
				cfg.CrossRequestDetection.EntropyBudget.Enabled = true
				cfg.CrossRequestDetection.EntropyBudget.ExemptDomains = []string{testExemptHost}
			},
			wantWarn: 0,
		},
		{
			name: "browser shield exemption inert when shield disabled",
			mutate: func(cfg *config.Config) {
				cfg.BrowserShield.Enabled = false
				cfg.BrowserShield.ExemptDomains = []string{"browser.vendor.example"}
			},
			wantWarn:         1,
			wantDetailSubstr: "browser_shield.exempt_domains is set but browser_shield.enabled=false",
			wantNextSubstr:   "enable browser_shield",
		},
		{
			name: "browser shield pristine default baseline NOT flagged when shield disabled",
			mutate: func(cfg *config.Config) {
				cfg.BrowserShield.Enabled = false
				cfg.BrowserShield.ExemptDomains = append([]string(nil), config.Defaults().BrowserShield.ExemptDomains...)
			},
			wantWarn: 0,
		},
		{
			name: "browser shield exemption NOT flagged when shield enabled",
			mutate: func(cfg *config.Config) {
				cfg.BrowserShield.Enabled = true
				cfg.BrowserShield.ExemptDomains = []string{"browser.vendor.example"}
			},
			wantWarn: 0,
		},
		{
			name: "browser shield pristine default baseline NOT flagged when shield enabled",
			mutate: func(cfg *config.Config) {
				cfg.BrowserShield.Enabled = true
				cfg.BrowserShield.ExemptDomains = append([]string(nil), config.Defaults().BrowserShield.ExemptDomains...)
			},
			wantWarn: 0,
		},
		{
			name: "TLS passthrough exemption inert when TLS interception disabled",
			mutate: func(cfg *config.Config) {
				cfg.TLSInterception.Enabled = false
				cfg.TLSInterception.PassthroughDomains = []string{"tls.vendor.example"}
			},
			wantWarn:         1,
			wantDetailSubstr: "tls_interception.passthrough_domains is set but tls_interception.enabled=false",
			wantNextSubstr:   "enable tls_interception",
		},
		{
			name: "TLS pristine default passthrough baseline NOT flagged when TLS interception disabled",
			mutate: func(cfg *config.Config) {
				cfg.TLSInterception.Enabled = false
				cfg.TLSInterception.PassthroughDomains = append([]string(nil), config.Defaults().TLSInterception.PassthroughDomains...)
			},
			wantWarn: 0,
		},
		{
			name: "TLS passthrough exemption NOT flagged when TLS interception enabled",
			mutate: func(cfg *config.Config) {
				cfg.TLSInterception.Enabled = true
				cfg.TLSInterception.PassthroughDomains = []string{"tls.vendor.example"}
			},
			wantWarn: 0,
		},
		{
			name: "TLS pristine default passthrough baseline NOT flagged when TLS interception enabled",
			mutate: func(cfg *config.Config) {
				cfg.TLSInterception.Enabled = true
				cfg.TLSInterception.PassthroughDomains = append([]string(nil), config.Defaults().TLSInterception.PassthroughDomains...)
			},
			wantWarn: 0,
		},
		{
			name: "request header ignore entry inert when request scanning disabled",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = false
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
				cfg.RequestBodyScanning.IgnoreHeaders = []string{"X-Provider-Trace"}
			},
			wantWarn:         1,
			wantDetailSubstr: "request_body_scanning.enabled=false",
			wantNextSubstr:   "header_mode=all",
		},
		{
			name: "request header ignore entry inert when header scanning disabled",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = false
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
				cfg.RequestBodyScanning.IgnoreHeaders = []string{"X-Provider-Trace"}
			},
			wantWarn:         1,
			wantDetailSubstr: "request_body_scanning.scan_headers=false",
			wantNextSubstr:   "header_mode=all",
		},
		{
			name: "request header ignore entry inert outside all header mode",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
				cfg.RequestBodyScanning.IgnoreHeaders = []string{"X-Provider-Trace"}
			},
			wantWarn:         1,
			wantDetailSubstr: "request_body_scanning.header_mode is not all",
			wantNextSubstr:   "header_mode=all",
		},
		{
			name: "request header complete default ignore baseline NOT flagged when request scanning disabled",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = false
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
				cfg.RequestBodyScanning.IgnoreHeaders = append([]string(nil), defaultRequestBodyIgnoreHeaders()...)
			},
			wantWarn: 0,
		},
		{
			name: "request header default ignore baseline is not warned outside all header mode",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
				cfg.RequestBodyScanning.IgnoreHeaders = append([]string(nil), defaultRequestBodyIgnoreHeaders()...)
			},
			wantWarn: 0,
		},
		{
			name: "request header pristine default ignore baseline NOT flagged when all-header scanning enabled",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
				cfg.RequestBodyScanning.IgnoreHeaders = append([]string(nil), defaultRequestBodyIgnoreHeaders()...)
			},
			wantWarn: 0,
		},
		{
			name: "request header ignore entry NOT flagged in all header mode",
			mutate: func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
				cfg.RequestBodyScanning.IgnoreHeaders = []string{"X-Provider-Trace"}
			},
			wantWarn: 0,
		},
		{
			name: "query entropy param exclusion with complete metadata is NOT flagged",
			mutate: func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
					Scheme:  "https",
					Host:    "api.vendor.example",
					Path:    "/v1/search/recent",
					Param:   "query",
					Reason:  "structured query",
					Owner:   "platform-security",
					Expires: "2099-12-31",
				}}
			},
			wantWarn: 0,
		},
		{
			name: "query entropy param exclusion expiring today is NOT flagged",
			mutate: func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
					Scheme:  "https",
					Host:    "api.vendor.example",
					Path:    "/v1/search/recent",
					Param:   "query",
					Reason:  "structured query",
					Owner:   "platform-security",
					Expires: time.Now().UTC().Format("2006-01-02"),
				}}
			},
			wantWarn: 0,
		},
		{
			name: "query entropy param exclusion missing advisory fields",
			mutate: func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
					Scheme: "https",
					Host:   "api.vendor.example",
					Path:   "/v1/search/recent",
					Param:  "query",
				}}
			},
			wantWarn:         3,
			wantDetailSubstr: "missing advisory",
			wantNextSubstr:   "YYYY-MM-DD",
		},
		{
			name: "query entropy param exclusion expired",
			mutate: func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
					Scheme:  "https",
					Host:    "api.vendor.example",
					Path:    "/v1/search/recent",
					Param:   "query",
					Reason:  "structured query",
					Owner:   "platform-security",
					Expires: "2000-01-01",
				}}
			},
			wantWarn:         1,
			wantDetailSubstr: "expired on 2000-01-01",
			wantNextSubstr:   "review whether",
		},
		{
			name: "query entropy param exclusion malformed expires",
			mutate: func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
					Scheme:  "https",
					Host:    "api.vendor.example",
					Path:    "/v1/search/recent",
					Param:   "query",
					Reason:  "structured query",
					Owner:   "platform-security",
					Expires: "not-a-date",
				}}
			},
			wantWarn:         1,
			wantDetailSubstr: `invalid expires "not-a-date"`,
			wantNextSubstr:   "valid YYYY-MM-DD",
		},
		{
			name: "query entropy param exclusion redundant with host-wide exclusion",
			mutate: func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.QueryEntropyExclusions = []string{"*.vendor.example"}
				cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
					Scheme:  "https",
					Host:    "api.vendor.example",
					Path:    "/v1/search/recent",
					Param:   "query",
					Reason:  "structured query",
					Owner:   "platform-security",
					Expires: "2099-12-31",
				}}
			},
			wantWarn:         1,
			wantDetailSubstr: "redundant because query_entropy_exclusions already covers host api.vendor.example",
			wantNextSubstr:   "prefer the endpoint-parameter exemption",
		},
		{
			name: "query entropy param exclusion inert when entropy disabled",
			mutate: func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.EntropyThreshold = 0
				cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
					Scheme:  "https",
					Host:    "api.vendor.example",
					Path:    "/v1/search/recent",
					Param:   "query",
					Reason:  "structured query",
					Owner:   "platform-security",
					Expires: "2099-12-31",
				}}
			},
			wantWarn:         1,
			wantDetailSubstr: "entropy_threshold<=0",
			wantNextSubstr:   "re-enable entropy",
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

func TestCheckConfigAdvisoriesIncludesQueryEntropyParamExclusions(t *testing.T) {
	cfg := baseSemanticsConfig()
	cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
		Scheme: "https",
		Host:   "api.vendor.example",
		Path:   "/v1/search/recent",
		Param:  "query",
	}}
	advisories := checkConfigAdvisories(cfg)
	var found bool
	for _, advisory := range advisories {
		if strings.Contains(advisory, "query_entropy_param_exclusions") && strings.Contains(advisory, "missing advisory") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("checkConfigAdvisories() missing query entropy param advisory; got %v", advisories)
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

func TestAnalyzeConfigSemanticsNilConfig(t *testing.T) {
	if findings := AnalyzeConfigSemantics(nil); findings != nil {
		t.Fatalf("AnalyzeConfigSemantics(nil) = %+v, want nil", findings)
	}
}

func TestAnalyzeConfigSemanticsPristineDefaultsHaveNoFindings(t *testing.T) {
	cfg := config.Defaults()
	cfg.ApplyDefaults()

	findings := AnalyzeConfigSemantics(cfg)
	t.Logf("findings count = %d", len(findings))
	if len(findings) != 0 {
		t.Fatalf("AnalyzeConfigSemantics(defaults) findings count = %d, want 0: %+v", len(findings), findings)
	}
}

func TestDoctorConfigSemanticsPristineDefaultsReturnOK(t *testing.T) {
	cfg := config.Defaults()
	cfg.ApplyDefaults()

	checks := checkDoctorConfigSemantics(cfg)
	if len(checks) != 1 {
		t.Fatalf("checkDoctorConfigSemantics(defaults) checks = %d, want 1 OK placeholder: %+v", len(checks), checks)
	}
	if checks[0].Status != doctorStatusOK {
		t.Fatalf("checkDoctorConfigSemantics(defaults) status = %q, want %q: %+v", checks[0].Status, doctorStatusOK, checks)
	}
}

func TestConfigSemanticHelperBranches(t *testing.T) {
	if got := normalizeConfigSemanticSubject("request_body_scanning.ignore_headers", " X-Provider-Trace "); got != "x-provider-trace" {
		t.Fatalf("normalized header subject = %q, want x-provider-trace", got)
	}
	if got := normalizeConfigSemanticSubject("response_scanning.mcp_servers", " docs-cache "); got != "docs-cache" {
		t.Fatalf("normalized MCP subject = %q, want docs-cache", got)
	}

	added := operatorAddedStrings([]string{"", "  *.googlevideo.com  ", "tls.vendor.example"}, config.Defaults().TLSInterception.PassthroughDomains)
	if len(added) != 1 || added[0] != "tls.vendor.example" {
		t.Fatalf("operatorAddedStrings = %v, want [tls.vendor.example]", added)
	}

	headers := operatorAddedHeaderNames([]string{"", "accept", "X-Provider-Trace"}, defaultRequestBodyIgnoreHeaders())
	if len(headers) != 1 || headers[0] != "X-Provider-Trace" {
		t.Fatalf("operatorAddedHeaderNames = %v, want [X-Provider-Trace]", headers)
	}
	headers = operatorAddedHeaderNames(defaultRequestBodyIgnoreHeaders(), defaultRequestBodyIgnoreHeaders())
	if len(headers) != 0 {
		t.Fatalf("operatorAddedHeaderNames(defaults) = %v, want none", headers)
	}

	if !requestHeaderIgnoreListConsumed(config.RequestBodyScanning{
		Enabled:     true,
		ScanHeaders: true,
		HeaderMode:  config.HeaderModeAll,
	}) {
		t.Fatal("requestHeaderIgnoreListConsumed() = false, want true")
	}
	detail := requestHeaderIgnoreListInertDetail(config.RequestBodyScanning{
		Enabled:     true,
		ScanHeaders: true,
		HeaderMode:  config.HeaderModeAll,
	})
	if !strings.Contains(detail, "header ignore-list scanning is disabled") {
		t.Fatalf("fallback inert detail = %q", detail)
	}

	findings := []ConfigSemanticFinding{
		{Scope: "z", Detail: "b"},
		{Scope: "a", Detail: "c"},
		{Scope: "a", Detail: "b"},
	}
	sortConfigSemanticFindings(findings)
	if findings[0].Scope != "a" || findings[0].Detail != "b" ||
		findings[1].Scope != "a" || findings[1].Detail != "c" ||
		findings[2].Scope != "z" {
		t.Fatalf("sortConfigSemanticFindings = %+v", findings)
	}

	tuple := queryEntropyParamAdvisoryTuple(config.QueryEntropyParamExclusion{
		Host:  "api.vendor.example",
		Path:  "/v1/search",
		Param: "query",
	})
	if tuple != "https://api.vendor.example/v1/search?query" {
		t.Fatalf("default scheme tuple = %q", tuple)
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

func TestDoctorResponseScanExemptDomainsAdvisoryNarrowestFirst(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/response-exempt.yaml"
	const body = `mode: balanced
response_scanning:
  enabled: true
  exempt_domains:
    - "provider.example"
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := DoctorCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--config", cfgPath, "--no-color"})
	_ = cmd.Execute()
	out := buf.String()

	sizeIdx := strings.Index(out, "response_scanning.size_exempt_domains")
	patternIdx := strings.Index(out, "dlp.patterns[].exempt_domains")
	broadIdx := strings.Index(out, "keep response_scanning.exempt_domains")
	if sizeIdx < 0 || patternIdx < 0 || broadIdx < 0 {
		t.Fatalf("doctor output missing expected advisory knobs:\n%s", out)
	}
	if sizeIdx >= broadIdx || patternIdx >= broadIdx {
		t.Fatalf("doctor must recommend narrow knobs before broad exempt_domains warning:\n%s", out)
	}
	if !strings.Contains(out, "responses are fully unscanned for injection") ||
		!strings.Contains(out, "oversized over-cap responses") {
		t.Fatalf("doctor output missing full-unscanned over-cap warning:\n%s", out)
	}
}

func TestAnalyzeConfigSemanticsPublicKinds(t *testing.T) {
	cfg := baseSemanticsConfig()
	cfg.RequestBodyScanning.Enabled = false
	cfg.ResponseScanning.Enabled = false
	cfg.ResponseScanning.SSEStreaming.Enabled = false
	cfg.Suppress = []config.SuppressEntry{
		{Rule: testDLPPatternName, Path: "*" + testExemptHost + "*", Reason: "url token FP"},
	}
	cfg.ResponseScanning.MCPServers = []config.MCPResponseServerTrust{{
		Server: "reasoning-cache",
		Trust:  config.ResponseTrustReasoning,
	}}

	findings := AnalyzeConfigSemantics(cfg)
	var sawMisdirectedSuppress, sawInertTrust bool
	for _, finding := range findings {
		if finding.Scope == "suppress" && finding.Kind == ConfigSemanticKindMisdirected {
			sawMisdirectedSuppress = true
		}
		if finding.Scope == "response_scanning.mcp_servers" && finding.Kind == ConfigSemanticKindInert {
			sawInertTrust = true
		}
		if finding.Severity != ConfigSemanticSeverityWarn {
			t.Fatalf("Severity = %q, want %q", finding.Severity, ConfigSemanticSeverityWarn)
		}
	}
	if !sawMisdirectedSuppress {
		t.Fatalf("AnalyzeConfigSemantics() missing misdirected suppress finding: %+v", findings)
	}
	if !sawInertTrust {
		t.Fatalf("AnalyzeConfigSemantics() missing inert MCP trust finding: %+v", findings)
	}
}

func TestDoctorConfigSemanticsSuppressesDefaultHeaderSubsetWhenInert(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/pipelock.yaml"
	const body = `mode: balanced
request_body_scanning:
  enabled: false
  scan_headers: true
  header_mode: all
  ignore_headers:
    - Accept
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(config): %v", err)
	}

	findings := AnalyzeConfigSemantics(cfg)
	for _, finding := range findings {
		if finding.Scope == "request_body_scanning.ignore_headers" &&
			finding.Subject == "accept" &&
			finding.Kind == ConfigSemanticKindInert {
			t.Fatalf("default header was flagged inert: %+v", finding)
		}
	}
}

func TestDoctorConfigSemanticsSuppressesDefaultDomainSubsetWhenInert(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/pipelock.yaml"
	const body = `mode: balanced
browser_shield:
  enabled: false
  exempt_domains:
    - docs.github.com
`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(config): %v", err)
	}

	findings := AnalyzeConfigSemantics(cfg)
	for _, finding := range findings {
		if finding.Scope == "browser_shield.exempt_domains" &&
			finding.Subject == "docs.github.com" &&
			finding.Kind == ConfigSemanticKindInert {
			t.Fatalf("default browser shield domain was flagged inert: %+v", finding)
		}
	}
}

func TestDoctorConfigSemanticsAnalyzerRefactorGolden(t *testing.T) {
	cfg := baseSemanticsConfig()
	cfg.RequestBodyScanning.Enabled = false
	cfg.ResponseScanning.Enabled = false
	cfg.ResponseScanning.SSEStreaming.Enabled = false
	cfg.Suppress = []config.SuppressEntry{
		{Rule: "Totally Made Up Pattern", Path: "*provider.example*"},
		{Rule: testDLPPatternName, Path: "*" + testExemptHost + "*"},
	}
	cfg.ResponseScanning.ExemptDomains = []string{testExemptHost}

	checks := semanticFindingsToDoctorChecks(AnalyzeConfigSemantics(cfg))
	got, err := json.MarshalIndent(checks, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	want := strings.ReplaceAll(strings.TrimSpace(`[
  {
    "name": "config_suppress_semantics",
    "surface": "config",
    "status": "warn",
    "configured": true,
    "reachable": false,
    "enforcing": false,
    "detail": "suppress entry names DLP pattern \"Vendor Token\", but no suppress-consulting DLP proxy scanner is enabled (request_body_scanning=false, sse_streaming=false; response_scanning uses a separate pattern namespace); URL-query DLP would match this pattern but does not consult suppress, so the suppress has no effect on the proxy path",
    "next": "to exempt a URL-query match, set dlp.patterns[].exempt_domains for this pattern; suppress: only reaches body/header DLP, generic SSE DLP, response scanning, and the audit/git scanners"
  },
  {
    "name": "config_suppress_semantics",
    "surface": "config",
    "status": "warn",
    "configured": true,
    "reachable": false,
    "enforcing": false,
    "detail": "suppress entry names pattern \"Totally Made Up Pattern\", which matches no active DLP or response-scanning pattern; this exemption is inert for the proxy enforcement path",
    "next": "fix the rule name to match a pattern in dlp.patterns or response_scanning.patterns, move audit/git-only suppressions to the config used for those commands, or remove the entry; run PIPELOCK_DOCTOR again to confirm"
  },
  {
    "name": "config_exemption_semantics",
    "surface": "config",
    "status": "warn",
    "configured": true,
    "reachable": false,
    "enforcing": false,
    "detail": "response_scanning.exempt_domains is set while response_scanning.enabled=false; the full-trust streaming bypass is inactive, but immutable core response findings may still be treated as trusted/warn-only for matching hosts",
    "next": "prefer narrower knobs first: use response_scanning.size_exempt_domains for large-response false positives, or dlp.patterns[].exempt_domains for one noisy DLP pattern; enable response_scanning only when the whole host should get the broad full-trust streaming bypass, or remove the broad list"
  }
]`), "PIPELOCK_DOCTOR", "`pipelock doctor`")
	if string(got) != want {
		t.Fatalf("semantic doctor checks changed:\n got:\n%s\nwant:\n%s", got, want)
	}
}
