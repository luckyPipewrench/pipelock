// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// fakeGoogleKeyURL builds a URL carrying a fake Google API key shape. The
// literal prefix is split so gosec G101 does not flag it as a hardcoded
// credential; the value is not a real secret.
func fakeGoogleKeyURL() string {
	return "https://evil.example/?k=" + "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
}

// runExplainCmd runs the explain command with the given args and returns its
// stdout and the RunE error. Output is captured via cmd.SetOut (never os.Pipe).
func runExplainCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := explainCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// decodeExplainJSON runs explain with --json and decodes the report.
func decodeExplainJSON(t *testing.T, args ...string) (explainReport, error) {
	t.Helper()
	out, err := runExplainCmd(t, append([]string{"--json"}, args...)...)
	var report explainReport
	if jsonErr := json.Unmarshal([]byte(out), &report); jsonErr != nil {
		t.Fatalf("explain --json output is not valid JSON: %v\noutput: %q", jsonErr, out)
	}
	return report, err
}

// writeConfig writes a YAML config to a temp file and returns its path.
func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestExplainCmd_CleanURLAllowed(t *testing.T) {
	report, err := decodeExplainJSON(t, "https://example.com/path")
	if err != nil {
		t.Fatalf("clean URL should not return an error, got: %v", err)
	}
	if !report.Allowed {
		t.Fatalf("expected ALLOWED, got blocked by %s: %s", report.Scanner, report.Reason)
	}
	if report.Remediation != nil {
		t.Errorf("allowed verdict should carry no remediation, got %+v", report.Remediation)
	}
	if report.Host != "example.com" {
		t.Errorf("host = %q, want example.com", report.Host)
	}
}

func TestExplainCmd_Verdicts(t *testing.T) {
	tests := []struct {
		name            string
		url             string
		wantScanner     string
		wantTargetView  string
		wantImmutable   bool
		remediationHas  string // substring the remediation knob MUST contain
		remediationLack string // substring the remediation knob must NOT contain (empty = skip)
	}{
		{
			name:            "url_dlp_names_exempt_domains_not_suppress",
			url:             fakeGoogleKeyURL(),
			wantScanner:     scanner.ScannerDLP,
			wantTargetView:  explainViewURLQuery,
			remediationHas:  "dlp.patterns[].exempt_domains",
			remediationLack: "", // suppress IS mentioned, but as inert; checked separately below
		},
		{
			name:           "high_entropy_query_names_query_entropy_exclusions",
			url:            "https://evil.example/?sig=Zx9KqWvB3nMpLrT7yFhJ2dGsQ8aEcVbN4uXoIzPwRmKtYgD5fHl",
			wantScanner:    scanner.ScannerEntropy,
			wantTargetView: explainViewURLQuery,
			remediationHas: "query_entropy_exclusions",
		},
		{
			name:            "high_entropy_path_names_path_entropy_exemption",
			url:             "https://evil.example/Zx9KqWvB3nMpLrT7yFhJ2dGsQ8aEcVbN4uXoIzPwRmKtYgD5fHl?preview=true",
			wantScanner:     scanner.ScannerEntropy,
			wantTargetView:  explainViewPath,
			remediationHas:  "path-entropy gate",
			remediationLack: "Add the host to `fetch_proxy.monitoring.query_entropy_exclusions`",
		},
		{
			name:           "private_ip_literal_core_ssrf_immutable",
			url:            "http://127.0.0.1/internal",
			wantScanner:    scanner.ScannerCoreSSRF,
			wantTargetView: explainViewHost,
			wantImmutable:  true,
			remediationHas: "ssrf.ip_allowlist",
		},
		{
			name:           "scheme_block_immutable",
			url:            "ftp://example.com/x",
			wantScanner:    scanner.ScannerScheme,
			wantTargetView: explainViewScheme,
			wantImmutable:  true,
			remediationHas: "http",
		},
		{
			name:           "core_dlp_immutable",
			url:            "https://evil.example/?k=AKIA" + "IOSFODNN7EXAMPLE",
			wantScanner:    scanner.ScannerCoreDLP,
			wantTargetView: explainViewURLQuery,
			wantImmutable:  true,
			remediationHas: "immutable safety floor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := decodeExplainJSON(t, tt.url)
			if err == nil {
				t.Fatalf("blocked URL should return a non-nil error (exit code)")
			}
			var exitErr *cliutil.ExitError
			if !errors.As(err, &exitErr) || exitErr.Code != cliutil.ExitSecurity {
				t.Fatalf("blocked URL should carry ExitSecurity, got %v", err)
			}
			if report.Allowed {
				t.Fatalf("expected BLOCKED, got allowed")
			}
			if report.Scanner != tt.wantScanner {
				t.Fatalf("scanner = %q, want %q (reason: %s)", report.Scanner, tt.wantScanner, report.Reason)
			}
			if report.TargetView != tt.wantTargetView {
				t.Errorf("target_view = %q, want %q", report.TargetView, tt.wantTargetView)
			}
			if report.Remediation == nil {
				t.Fatalf("blocked verdict must carry remediation")
			}
			if report.Remediation.Immutable != tt.wantImmutable {
				t.Errorf("remediation.immutable = %v, want %v", report.Remediation.Immutable, tt.wantImmutable)
			}
			if tt.remediationHas != "" && !strings.Contains(report.Remediation.Knob, tt.remediationHas) {
				t.Errorf("remediation knob %q does not contain %q", report.Remediation.Knob, tt.remediationHas)
			}
			if tt.remediationLack != "" && strings.Contains(report.Remediation.Knob, tt.remediationLack) {
				t.Errorf("remediation knob %q must not contain %q", report.Remediation.Knob, tt.remediationLack)
			}
		})
	}
}

// TestExplainCmd_URLDLPDoesNotPointAtSuppress is the load-bearing assertion:
// URL DLP must name dlp.patterns[].exempt_domains, and must explicitly tell the
// operator that the top-level suppress: list is INERT for a URL-DLP block.
// Pointing at suppress: as the fix is the exact bug this command exists to
// prevent.
func TestExplainCmd_URLDLPDoesNotPointAtSuppress(t *testing.T) {
	report, err := decodeExplainJSON(t, fakeGoogleKeyURL())
	if err == nil {
		t.Fatal("expected a block error")
	}
	if report.Scanner != scanner.ScannerDLP {
		t.Fatalf("expected scanner=dlp, got %q", report.Scanner)
	}
	if report.Remediation == nil {
		t.Fatal("URL-DLP block should include remediation")
	}
	knob := report.Remediation.Knob
	if !strings.Contains(knob, "dlp.patterns[].exempt_domains") {
		t.Errorf("URL-DLP remediation must name dlp.patterns[].exempt_domains, got: %q", knob)
	}
	// suppress must be mentioned ONLY to say it does NOT apply.
	if !strings.Contains(knob, "suppress") || !strings.Contains(knob, "does NOT consult") {
		t.Errorf("URL-DLP remediation must explicitly mark suppress: as inert, got: %q", knob)
	}
}

func TestExplainCmd_Blocklist(t *testing.T) {
	cfg := writeConfig(t, `
mode: balanced
fetch_proxy:
  listen: "127.0.0.1:0"
  monitoring:
    blocklist:
      - "blocked.example"
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://blocked.example/x")
	if err == nil {
		t.Fatal("blocklisted URL should error")
	}
	if report.Scanner != scanner.ScannerBlocklist {
		t.Fatalf("scanner = %q, want blocklist (reason: %s)", report.Scanner, report.Reason)
	}
	if report.TargetView != explainViewHost {
		t.Errorf("target_view = %q, want host", report.TargetView)
	}
	if report.Remediation == nil {
		t.Fatal("blocklist verdict should include remediation")
	}
	if !strings.Contains(report.Remediation.Knob, "fetch_proxy.monitoring.blocklist") {
		t.Errorf("blocklist remediation must name the blocklist knob, got: %q", report.Remediation.Knob)
	}
	if report.ConfigFile != cfg {
		t.Errorf("config_file = %q, want %q", report.ConfigFile, cfg)
	}
}

func TestExplainCmd_StrictAllowlist(t *testing.T) {
	cfg := writeConfig(t, `
mode: strict
api_allowlist:
  - "api.allowed.example"
fetch_proxy:
  listen: "127.0.0.1:0"
`)
	report, err := decodeExplainJSON(t, "--config", cfg, "https://not-allowed.example/x")
	if err == nil {
		t.Fatal("non-allowlisted URL in strict mode should error")
	}
	if report.Scanner != scanner.ScannerAllowlist {
		t.Fatalf("scanner = %q, want allowlist (reason: %s)", report.Scanner, report.Reason)
	}
	if report.Remediation == nil {
		t.Fatal("allowlist verdict should include remediation")
	}
	if !strings.Contains(report.Remediation.Knob, "api_allowlist") {
		t.Errorf("allowlist remediation must name api_allowlist, got: %q", report.Remediation.Knob)
	}
}

func TestExplainCmd_EmptyURL(t *testing.T) {
	_, err := runExplainCmd(t, "   ")
	if err == nil {
		t.Fatal("empty/whitespace URL should error")
	}
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != cliutil.ExitConfig {
		t.Fatalf("empty URL should carry ExitConfig, got %v", err)
	}
}

func TestExplainCmd_MalformedURL(t *testing.T) {
	// A URL the parser cannot read is an input error (exit 2), not a security
	// block (exit 3). The invalid percent-escape makes url.Parse fail.
	_, err := runExplainCmd(t, "https://example.com/%zz")
	if err == nil {
		t.Fatal("malformed URL should error")
	}
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != cliutil.ExitConfig {
		t.Fatalf("malformed URL should carry ExitConfig (input error), got %v", err)
	}
}

func TestExplainCmd_BadConfigPath(t *testing.T) {
	_, err := runExplainCmd(t, "--config", "/no/such/config.yaml", "https://example.com")
	if err == nil {
		t.Fatal("missing config file should error")
	}
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != cliutil.ExitConfig {
		t.Fatalf("bad config path should carry ExitConfig, got %v", err)
	}
}

func TestExplainCmd_HumanOutputShape(t *testing.T) {
	out, err := runExplainCmd(t, "ftp://example.com/x")
	if err == nil {
		t.Fatal("expected a block error")
	}
	for _, want := range []string{
		"Pipelock Explain",
		"Verdict: BLOCKED",
		"Scanner: scheme",
		"Remediation:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q\noutput:\n%s", want, out)
		}
	}
}

func TestExplainCmd_JSONOutputShape(t *testing.T) {
	report, err := decodeExplainJSON(t, "https://example.com/clean")
	if err != nil {
		t.Fatalf("clean URL JSON should not error: %v", err)
	}
	if report.URL != "https://example.com/clean" {
		t.Errorf("url = %q", report.URL)
	}
	if report.Mode == "" {
		t.Error("mode should be populated")
	}
	if report.Version == "" {
		t.Error("version should be populated")
	}
}

func TestExplainCmd_RegisteredOnRoot(t *testing.T) {
	root := rootCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "explain" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("explain command is not registered on the root command")
	}
}

func TestExplainHostIsIPLiteral(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"example.com", false},
		{"sub.example.com", false},
		{"", false},
		{"::1", true},
		{"fe80::1", true},
		{"1.2.3", false}, // not four octets
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := explainHostIsIPLiteral(tt.host); got != tt.want {
				t.Errorf("explainHostIsIPLiteral(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestExplainRemediationFor_AllScannersMapped(t *testing.T) {
	// Every scanner constant the pipeline can emit must have a non-empty
	// remediation knob. A missing mapping is a silent gap: the operator gets a
	// block with no guidance.
	scanners := []string{
		scanner.ScannerDLP, scanner.ScannerCoreDLP, scanner.ScannerEntropy,
		scanner.ScannerSubdomainEntropy, scanner.ScannerBlocklist, scanner.ScannerAllowlist,
		scanner.ScannerSSRF, scanner.ScannerSSRFMetadata, scanner.ScannerCoreSSRF,
		scanner.ScannerRateLimit, scanner.ScannerLength, scanner.ScannerDataBudget,
		scanner.ScannerCRLF, scanner.ScannerPathTraversal, scanner.ScannerScheme,
		scanner.ScannerCoreResponse, scanner.ScannerContext, scanner.ScannerParser,
		"some_unknown_scanner",
	}
	for _, s := range scanners {
		t.Run(s, func(t *testing.T) {
			rem := explainRemediationFor(scanner.Result{Scanner: s})
			if rem == nil || rem.Knob == "" {
				t.Errorf("scanner %q has no remediation knob", s)
			}
		})
	}
}

func TestExplainRemediationFor_SSRFNamesActualTrustedDomainsField(t *testing.T) {
	rem := explainRemediationFor(scanner.Result{Scanner: scanner.ScannerSSRF})
	if rem == nil {
		t.Fatal("expected SSRF remediation")
	}
	if !strings.Contains(rem.Knob, "top-level `trusted_domains`") {
		t.Fatalf("SSRF remediation must name top-level trusted_domains, got: %q", rem.Knob)
	}
	if strings.Contains(rem.Knob, "ssrf.trusted_domains") {
		t.Fatalf("SSRF remediation must not name inert ssrf.trusted_domains, got: %q", rem.Knob)
	}
}

func TestExplainCmd_DLPPatternNameExtracted(t *testing.T) {
	report, err := decodeExplainJSON(t, fakeGoogleKeyURL())
	if err == nil {
		t.Fatal("expected a block")
	}
	if report.PatternName != "Google API Key" {
		t.Errorf("pattern_name = %q, want \"Google API Key\"", report.PatternName)
	}
}

func TestExplainPatternName(t *testing.T) {
	tests := []struct {
		name   string
		result scanner.Result
		want   string
	}{
		{"allowed", scanner.Result{Allowed: true}, ""},
		{"dlp_hard_block", scanner.Result{Scanner: scanner.ScannerDLP, Reason: "DLP match: Google API Key (high)"}, "Google API Key"},
		{"core_dlp", scanner.Result{Scanner: scanner.ScannerCoreDLP, Reason: "core DLP match: AWS Access ID (critical)"}, "AWS Access ID"},
		{"dlp_no_severity_suffix", scanner.Result{Scanner: scanner.ScannerDLP, Reason: "DLP match: SomeName"}, "SomeName"},
		{"entropy_has_no_pattern", scanner.Result{Scanner: scanner.ScannerEntropy, Reason: "high entropy query param"}, ""},
		{"hard_block_wins_over_warn_match", scanner.Result{Scanner: scanner.ScannerDLP, WarnMatches: []scanner.WarnMatch{{PatternName: "WarnPat"}}, Reason: "DLP match: HardBlock (high)"}, "HardBlock"},
		{"warn_match_does_not_become_block_pattern", scanner.Result{Scanner: scanner.ScannerEntropy, WarnMatches: []scanner.WarnMatch{{PatternName: "WarnPat"}}, Reason: "high entropy query param"}, ""},
		{"blocklist_pattern", scanner.Result{Scanner: scanner.ScannerBlocklist, Reason: "domain blocked: evil.example matches *.example"}, "*.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := explainPatternName(tt.result); got != tt.want {
				t.Errorf("explainPatternName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExplainCmd_HumanOutputRendersBroaderAndPattern exercises the human
// renderer's broader-option and pattern-name branches via a URL-DLP block.
func TestExplainCmd_HumanOutputRendersBroaderAndPattern(t *testing.T) {
	out, err := runExplainCmd(t, fakeGoogleKeyURL())
	if err == nil {
		t.Fatal("expected a block")
	}
	for _, want := range []string{
		"Scanner: dlp",
		"Pattern: Google API Key",
		"Target:  url_query",
		"broader:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q\noutput:\n%s", want, out)
		}
	}
}

// TestExplainCmd_AllowedDNSDependentNote verifies an allowed verdict against a
// hostname (not an IP literal) flags that the runtime SSRF layer still resolves
// DNS, since explain itself performs no resolution.
func TestExplainCmd_AllowedDNSDependentNote(t *testing.T) {
	report, err := decodeExplainJSON(t, "https://example.com/clean")
	if err != nil {
		t.Fatalf("clean URL should not error: %v", err)
	}
	if !report.Allowed {
		t.Fatal("expected allowed")
	}
	if !report.DNSDependent {
		t.Error("hostname-based allowed verdict should be flagged dns_dependent")
	}
	foundNote := false
	for _, n := range report.Notes {
		if strings.Contains(n, "SSRF layer") {
			foundNote = true
		}
	}
	if !foundNote {
		t.Errorf("expected a DNS-resolution note, got notes: %v", report.Notes)
	}
}

func TestExplainCmd_HumanOutputAllowed(t *testing.T) {
	out, err := runExplainCmd(t, "https://example.com/clean")
	if err != nil {
		t.Fatalf("clean URL should not error: %v", err)
	}
	for _, want := range []string{"Verdict: ALLOWED", "Score:", "Host:    example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("allowed human output missing %q\noutput:\n%s", want, out)
		}
	}
}

// TestPrintExplainReport_WarnMatches exercises the warn-match rendering branch
// directly, since hard blocks rarely carry warn matches.
func TestPrintExplainReport_WarnMatches(t *testing.T) {
	var buf bytes.Buffer
	report := explainReport{
		URL:     "https://h/x",
		Mode:    "balanced",
		Allowed: false,
		Scanner: scanner.ScannerDLP,
		WarnMatches: []explainWarnMatch{
			{PatternName: "Some Warn Pattern", Severity: "info"},
		},
		Remediation: &explainRemediation{Knob: "do the thing", Broader: "broad thing"},
		Notes:       []string{"a note"},
	}
	printExplainReport(&buf, report)
	out := buf.String()
	for _, want := range []string{"Warn matches:", "Some Warn Pattern (info)", "broader: broad thing", "note: a note"} {
		if !strings.Contains(out, want) {
			t.Errorf("warn-match render missing %q\noutput:\n%s", want, out)
		}
	}
}

func TestExplainHost(t *testing.T) {
	if got := explainHost("https://EXAMPLE.com/x"); got != "example.com" {
		t.Errorf("explainHost lowercases host, got %q", got)
	}
	if got := explainHost("://bad\x00url"); got != "" {
		t.Errorf("explainHost on unparseable URL should be empty, got %q", got)
	}
}

func TestExplainTargetView(t *testing.T) {
	tests := []struct {
		name   string
		result scanner.Result
		url    string
		want   string
	}{
		{"dlp_query_span", scanner.Result{Scanner: scanner.ScannerDLP, Reason: "DLP match: x (high)"}, "https://h/?k=v", explainViewURLQuery},
		{"dlp_path_span", scanner.Result{Scanner: scanner.ScannerDLP, Reason: "DLP match: x (high)"}, "https://h/path", explainViewPath},
		{"entropy_path_with_query", scanner.Result{Scanner: scanner.ScannerEntropy, Reason: "high entropy path segment (5.10 > 5.00 threshold)"}, "https://h/path?debug=true", explainViewPath},
		{"entropy_query", scanner.Result{Scanner: scanner.ScannerEntropy, Reason: "high entropy query param \"sig\" (5.10 > 5.00 threshold)"}, "https://h/path?sig=v", explainViewURLQuery},
		{"subdomain_entropy", scanner.Result{Scanner: scanner.ScannerSubdomainEntropy}, "https://x.h/", explainViewHost},
		{"path_traversal", scanner.Result{Scanner: scanner.ScannerPathTraversal}, "https://h/../x", explainViewPath},
		{"scheme", scanner.Result{Scanner: scanner.ScannerScheme}, "ftp://h/", explainViewScheme},
		{"unknown", scanner.Result{Scanner: "weird"}, "https://h/", explainViewURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := explainTargetView(tt.result, tt.url); got != tt.want {
				t.Errorf("explainTargetView(%q, %q) = %q, want %q", tt.result.Scanner, tt.url, got, tt.want)
			}
		})
	}
}
