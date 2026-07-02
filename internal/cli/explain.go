// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// explain output view labels. For a raw URL the matching surface is URL
// scanning; we report which component of the URL the blocking scanner
// inspects so the operator knows whether the credential is in the host, the
// path, or the query string.
const (
	explainViewURLQuery = "url_query"
	explainViewHost     = "host"
	explainViewPath     = "path"
	explainViewURL      = "url"
	explainViewScheme   = "scheme"

	explainConfigLabelDefaults = "(built-in defaults)"
)

// explainReport is the structured form of an `explain` verdict. It mirrors the
// doctorReport JSON-report pattern: a stable, machine-readable shape that the
// human renderer also consumes. The remediation block is the load-bearing part
// of this command — it names the EXACT knob the blocking scanner consults.
type explainReport struct {
	URL          string              `json:"url"`
	ConfigFile   string              `json:"config_file"`
	Mode         string              `json:"mode"`
	Version      string              `json:"version"`
	Allowed      bool                `json:"allowed"`
	Scanner      string              `json:"scanner,omitempty"`
	Layer        string              `json:"layer,omitempty"`
	TargetView   string              `json:"target_view,omitempty"`
	Host         string              `json:"host,omitempty"`
	PatternName  string              `json:"pattern_name,omitempty"`
	Reason       string              `json:"reason,omitempty"`
	Score        float64             `json:"score"`
	DNSDependent bool                `json:"dns_dependent"`
	Notes        []string            `json:"notes,omitempty"`
	WarnMatches  []explainWarnMatch  `json:"warn_matches,omitempty"`
	Remediation  *explainRemediation `json:"remediation,omitempty"`
}

type explainWarnMatch struct {
	PatternName string `json:"pattern_name"`
	Severity    string `json:"severity"`
}

// explainRemediation carries the correct, per-scanner remediation guidance.
// Knob is the narrowest verified change; Broader is an option with a wider
// blast radius (and its tradeoff). Both are empty when a block is structural
// and has no legitimate exemption (CRLF, path traversal, bad scheme, core
// immutable floors).
type explainRemediation struct {
	// Knob is the narrowest config change that lifts THIS block for a
	// known-good destination, named for the scanner that actually consults it.
	Knob string `json:"knob,omitempty"`
	// Broader is a wider exemption and the tradeoff of using it. Empty when
	// none applies.
	Broader string `json:"broader,omitempty"`
	// Immutable is set when the block comes from a safety floor that cannot be
	// disabled by config (core DLP/SSRF/response).
	Immutable bool `json:"immutable,omitempty"`
}

func explainCmd() *cobra.Command {
	var configFile string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "explain <url>",
		Short: "Explain a URL verdict and the exact remediation for a block",
		Long: `Run a URL through the scanner pipeline using the loaded config and explain
the verdict so a block is remediable. For a blocked URL, explain prints the
scanner/layer that produced the verdict, the matching pattern (for DLP and
blocklist), which part of the URL was inspected, the destination host, the
effective config path, and — most importantly — the EXACT remediation knob
that scanner consults, plus any broader option and its tradeoff.

explain does not perform network access. It runs the layers that fire before
DNS resolution (scheme, CRLF, path traversal, allowlist, blocklist, core SSRF
literal, core/URL DLP, path and subdomain entropy). The hostname-based SSRF
layer (layer 8) resolves DNS at runtime, so explain reports when a verdict
would additionally depend on resolution rather than reaching out itself. IP
literals that resolve to private ranges are still caught here by the immutable
core SSRF literal check, which needs no resolution.

Examples:
  pipelock explain https://example.com/path
  pipelock explain --config pipelock.yaml https://example.com/download?id=42
  pipelock explain --json https://10.0.0.1/internal`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgLabel, err := explainLoadConfig(configFile)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			report, err := buildExplainReport(cmd, cfg, cfgLabel, args[0])
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return fmt.Errorf("encode explain report JSON: %w", err)
				}
			} else {
				printExplainReport(cmd.OutOrStdout(), report)
			}
			// A blocked verdict exits non-zero so scripts can branch on it,
			// matching `pipelock check --url`'s contract.
			if !report.Allowed {
				return cliutil.ExitCodeError(cliutil.ExitSecurity, errExplainBlocked)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path (default: built-in defaults)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output report as JSON")

	// `explain mcp-response` explains an MCP response block and names the
	// per-server suppress knob (the stdio MCP equivalent of a URL verdict).
	cmd.AddCommand(explainMCPResponseCmd())

	return cmd
}

// errExplainBlocked is the sentinel returned when explain reports a blocked
// URL. It carries the security exit code so callers can branch on a block
// without parsing output.
var errExplainBlocked = errors.New("url blocked")

func explainLoadConfig(path string) (*config.Config, string, error) {
	if path == "" {
		return config.Defaults(), explainConfigLabelDefaults, nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, "", fmt.Errorf("config load error: %w", err)
	}
	return cfg, path, nil
}

func buildExplainReport(cmd *cobra.Command, cfg *config.Config, cfgLabel, rawURL string) (explainReport, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return explainReport{}, errors.New("empty URL: provide a URL to explain")
	}
	// A URL the parser cannot even read is an input error (exit 2), not a
	// security block (exit 3). Genuine scheme/scanner rejections of a
	// well-formed URL still flow through as a blocked verdict below.
	if _, err := url.Parse(rawURL); err != nil {
		return explainReport{}, fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}

	report := explainReport{
		URL:        rawURL,
		ConfigFile: cfgLabel,
		Mode:       cfg.Mode,
		Version:    cliutil.Version,
	}

	// Merge any installed rule bundles into the config exactly as the runtime
	// scanner would, so URL-DLP patterns from bundles are reflected in the
	// verdict. Surface bundle load errors as warnings, not a hard failure.
	bundleResult := rules.MergeIntoConfig(cfg, cliutil.Version)
	for _, e := range bundleResult.Errors {
		report.Notes = append(report.Notes, fmt.Sprintf("rule bundle %s skipped: %s", e.Name, e.Reason))
	}

	// Disable the hostname-based SSRF layer so explain performs no DNS. The
	// immutable core SSRF literal check still runs (it inspects IP literals,
	// not resolved names), so private-IP literals are still caught. Detect
	// whether the running config WOULD consult the DNS-dependent SSRF layer so
	// we can flag the verdict as resolution-dependent.
	ssrfActive := cfg.Internal != nil
	cfg.Internal = nil

	sc := scanner.New(cfg)
	result := sc.Scan(cmd.Context(), rawURL)

	report.Allowed = result.Allowed
	report.Scanner = result.Scanner
	report.Layer = result.Scanner
	report.Reason = result.Reason
	report.Score = result.Score
	report.Host = explainHost(rawURL)
	report.TargetView = explainTargetView(result, rawURL)
	for _, w := range result.WarnMatches {
		report.WarnMatches = append(report.WarnMatches, explainWarnMatch{
			PatternName: w.PatternName,
			Severity:    w.Severity,
		})
	}
	report.PatternName = explainPatternName(result)

	if result.Allowed {
		// Even an allowed verdict can depend on DNS: if the hostname-based
		// SSRF layer is active in the live config and the host is not an IP
		// literal, the runtime verdict could still block on resolution.
		if ssrfActive && !explainHostIsIPLiteral(report.Host) {
			report.DNSDependent = true
			report.Notes = append(report.Notes,
				"this config's SSRF layer (layer 8) resolves DNS at runtime; explain did not resolve, so a private/metadata IP or DNS failure could still block this URL when proxied")
		}
		return report, nil
	}

	report.Remediation = explainRemediationFor(result)
	return report, nil
}

// explainHost returns the lowercased hostname for display, or empty if the URL
// cannot be parsed (a parse failure is itself a verdict, reported separately).
func explainHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

func explainHostIsIPLiteral(host string) bool {
	if host == "" {
		return false
	}
	// net/url strips brackets from IPv6 literals in Hostname(); a colon in the
	// bare hostname therefore signals an IPv6 literal.
	if strings.Contains(host, ":") {
		return true
	}
	// Dotted-quad IPv4 literal: four numeric octets, no letters.
	return strings.Count(host, ".") == 3 && !strings.ContainsAny(host, "abcdefghijklmnopqrstuvwxyz")
}

// explainTargetView reports which component of the URL the blocking scanner
// inspected. For a URL scan the surface is always URL scanning; this names the
// specific view so the operator knows where the offending content lives.
func explainTargetView(result scanner.Result, rawURL string) string {
	if view := explainTargetViewFromSpans(result.Spans()); view != "" {
		return view
	}
	switch result.Scanner {
	case scanner.ScannerScheme:
		return explainViewScheme
	case scanner.ScannerDLP, scanner.ScannerCoreDLP:
		if view := explainURLComponentView(rawURL); view != "" {
			return view
		}
		return explainViewURL
	case scanner.ScannerEntropy:
		if strings.Contains(result.Reason, "query ") {
			return explainViewURLQuery
		}
		return explainViewPath
	case scanner.ScannerSubdomainEntropy, scanner.ScannerSSRF, scanner.ScannerSSRFMetadata,
		scanner.ScannerCoreSSRF, scanner.ScannerBlocklist, scanner.ScannerAllowlist:
		return explainViewHost
	case scanner.ScannerPathTraversal:
		return explainViewPath
	default:
		return explainViewURL
	}
}

func explainTargetViewFromSpans(spans []scanner.MatchSpan) string {
	for _, span := range spans {
		label := span.ViewLabel
		switch {
		case strings.Contains(label, "query"):
			return explainViewURLQuery
		case strings.Contains(label, "subdomain"):
			return explainViewHost
		case strings.Contains(label, "path"):
			return explainViewPath
		case strings.Contains(label, "url"):
			return explainViewURL
		}
	}
	return ""
}

func explainURLComponentView(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	switch {
	case u.RawQuery != "":
		return explainViewURLQuery
	case u.Path != "" && u.Path != "/":
		return explainViewPath
	case u.Hostname() != "":
		return explainViewHost
	default:
		return explainViewURL
	}
}

// dlpReasonPatternPrefixes are the DLP reason-string prefixes the scanner
// emits before the matched pattern name. The scanner Result has no dedicated
// pattern-name field for a hard block, so we recover the name from the reason
// string, which is formatted as `[core ]DLP match: <name> (<severity>)`.
var dlpReasonPatternPrefixes = []string{"core DLP match: ", "DLP match: "}

// explainPatternName extracts the matched pattern name when one is available.
// For warn-mode matches the name is on the WarnMatch; for a DLP hard block the
// name is embedded in the reason string. Returns empty when no pattern name is
// recoverable (e.g. entropy, SSRF, scheme blocks have no named pattern).
func explainPatternName(result scanner.Result) string {
	if result.Allowed {
		return ""
	}
	switch result.Scanner {
	case scanner.ScannerDLP, scanner.ScannerCoreDLP:
		for _, prefix := range dlpReasonPatternPrefixes {
			if rest, ok := strings.CutPrefix(result.Reason, prefix); ok {
				// Trim the trailing " (<severity>)" suffix.
				if idx := strings.LastIndex(rest, " ("); idx >= 0 {
					return rest[:idx]
				}
				return rest
			}
		}
	case scanner.ScannerBlocklist:
		if _, pattern, ok := strings.Cut(result.Reason, " matches "); ok {
			return pattern
		}
	}
	return ""
}

// explainRemediationFor maps a blocking scanner to its CORRECT remediation
// knob. This mapping is the entire point of the command: a hint must name a
// knob the blocking scanner ACTUALLY consults. The knob→scanner facts are
// authoritative per internal/scanner and internal/config:
//
//   - URL DLP (dlp / core_dlp) does NOT consult top-level suppress:. The
//     correct knob is per-pattern dlp.patterns[].exempt_domains. (core_dlp is
//     an immutable floor and cannot be exempted.)
//   - Query entropy is a SEPARATE gate from DLP, tuned by
//     fetch_proxy.monitoring.query_entropy_exclusions.
//   - Path entropy and subdomain entropy use
//     fetch_proxy.monitoring.subdomain_entropy_exclusions.
//   - Domain blocklist is fetch_proxy.monitoring.blocklist.
//   - Allowlist (strict mode) is api_allowlist (or switch mode).
//   - SSRF (hostname/metadata) is trusted_domains / ssrf.ip_allowlist;
//     core_ssrf is an immutable private-range floor.
//   - CRLF / path traversal / scheme are never legitimate and have no knob.
//   - Rate limit / length / data budget are protective ceilings, tuned by
//     their own numeric knobs.
func explainRemediationFor(result scanner.Result) *explainRemediation {
	// scanner.GuidanceForResult is the single source: it draws from the label-
	// keyed guidance table and uses the scan Reason to pick same-label variants
	// (query vs path entropy), so explain and the audit remediation_hint cannot
	// drift. The default covers a label with no mapped guidance.
	if g, ok := scanner.GuidanceForResult(result.Scanner, result.Reason); ok {
		return &explainRemediation{
			Knob:      g.OperatorKnob,
			Broader:   g.OperatorBroader,
			Immutable: g.Immutable,
		}
	}
	return &explainRemediation{
		Knob: "No specific remediation is mapped for this scanner. Inspect the reason and the effective config before changing policy.",
	}
}

func printExplainReport(w io.Writer, report explainReport) {
	_, _ = fmt.Fprintln(w, "Pipelock Explain")
	_, _ = fmt.Fprintln(w, "================")
	_, _ = fmt.Fprintf(w, "URL:     %s\n", report.URL)
	_, _ = fmt.Fprintf(w, "Config:  %s\n", report.ConfigFile)
	_, _ = fmt.Fprintf(w, "Mode:    %s\n", report.Mode)
	if report.Host != "" {
		_, _ = fmt.Fprintf(w, "Host:    %s\n", report.Host)
	}
	_, _ = fmt.Fprintln(w)

	if report.Allowed {
		_, _ = fmt.Fprintln(w, "Verdict: ALLOWED")
		_, _ = fmt.Fprintf(w, "Score:   %.2f\n", report.Score)
		for _, note := range report.Notes {
			_, _ = fmt.Fprintf(w, "note: %s\n", note)
		}
		return
	}

	_, _ = fmt.Fprintln(w, "Verdict: BLOCKED")
	_, _ = fmt.Fprintf(w, "Scanner: %s\n", report.Scanner)
	_, _ = fmt.Fprintf(w, "Layer:   %s\n", report.Layer)
	if report.TargetView != "" {
		_, _ = fmt.Fprintf(w, "Target:  %s\n", report.TargetView)
	}
	if report.PatternName != "" {
		_, _ = fmt.Fprintf(w, "Pattern: %s\n", report.PatternName)
	}
	if report.Reason != "" {
		_, _ = fmt.Fprintf(w, "Reason:  %s\n", report.Reason)
	}
	_, _ = fmt.Fprintf(w, "Score:   %.2f\n", report.Score)

	if len(report.WarnMatches) > 0 {
		_, _ = fmt.Fprintln(w, "Warn matches:")
		for _, m := range report.WarnMatches {
			_, _ = fmt.Fprintf(w, "  - %s (%s)\n", m.PatternName, m.Severity)
		}
	}

	if report.Remediation != nil {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Remediation:")
		_, _ = fmt.Fprintf(w, "  %s\n", report.Remediation.Knob)
		if report.Remediation.Broader != "" {
			_, _ = fmt.Fprintf(w, "  broader: %s\n", report.Remediation.Broader)
		}
	}
	for _, note := range report.Notes {
		_, _ = fmt.Fprintf(w, "note: %s\n", note)
	}
}
