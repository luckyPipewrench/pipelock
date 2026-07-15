// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/evidence/display"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
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

	explainSurfaceCommand = "command"
	explainSurfaceTool    = "tool"
	explainSurfaceFile    = "file"

	explainFileReadLimitBytes = 1 << 20
	explainSummaryMaxBytes    = 240
)

const (
	explainResponseScanExemptNarrowAdvice = "response_scanning.exempt_domains configured: prefer narrower knobs first - use `response_scanning.size_exempt_domains` for large-response false positives, or `dlp.patterns[].exempt_domains` for one noisy DLP pattern."
	explainResponseScanExemptDisabled     = "With `response_scanning.enabled=false`, the full-trust streaming bypass is inactive; immutable core response findings may still be treated as trusted/warn-only for matching hosts."
	explainResponseScanExemptBlastRadius  = "Use `response_scanning.exempt_domains` only when the whole host is trusted: responses are fully unscanned for injection, including oversized over-cap responses that stream unscanned."
)

// explainReport is the structured form of an `explain` verdict. It mirrors the
// doctorReport JSON-report pattern: a stable, machine-readable shape that the
// human renderer also consumes. The remediation block is the load-bearing part
// of this command — it names the EXACT knob the blocking scanner consults.
type explainReport struct {
	URL           string              `json:"url"`
	Surface       string              `json:"surface,omitempty"`
	BlockedAction string              `json:"blocked_action,omitempty"`
	ConfigFile    string              `json:"config_file"`
	Mode          string              `json:"mode"`
	Version       string              `json:"version"`
	Allowed       bool                `json:"allowed"`
	Scanner       string              `json:"scanner,omitempty"`
	Layer         string              `json:"layer,omitempty"`
	TargetView    string              `json:"target_view,omitempty"`
	Host          string              `json:"host,omitempty"`
	PatternName   string              `json:"pattern_name,omitempty"`
	Reason        string              `json:"reason,omitempty"`
	Score         float64             `json:"score"`
	DNSDependent  bool                `json:"dns_dependent"`
	Notes         []string            `json:"notes,omitempty"`
	WarnMatches   []explainWarnMatch  `json:"warn_matches,omitempty"`
	AgentReason   string              `json:"agent_reason,omitempty"`
	Remediation   *explainRemediation `json:"remediation,omitempty"`
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
	var commandInput string
	var toolName string
	var toolInput string
	var filePath string
	var showRaw bool
	var hexdump bool

	cmd := &cobra.Command{
		Use:   "explain <url> [--command <command> | --tool <name> --input <json> | --file <path>]",
		Short: "Explain a URL, command, tool, or file verdict and the exact remediation for a block",
		Long: `Run a URL through the scanner pipeline, or run a hook surface through
the decide path, using the loaded config and explain the verdict so a block is
remediable. For a block, explain prints the scanner/layer that produced the
verdict, the matching pattern or policy rule, the inspected surface, the
effective config path, and — most importantly — the EXACT remediation knob
that scanner or decide label consults, plus any broader option and its
tradeoff.

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
  pipelock explain --json https://10.0.0.1/internal
  pipelock explain --command "grep .env.example"
  pipelock explain --tool "mcp__x__run" --input '{"cmd":"grep .env.example"}'
  pipelock explain --file ./fixture.txt`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          validateExplainArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := explainModeFromFlags(cmd)
			cfg, cfgLabel, err := explainLoadConfigForMode(configFile, mode)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			var report explainReport
			if mode == "" {
				report, err = buildExplainReport(cmd, cfg, cfgLabel, args[0])
			} else {
				action, blockedAction, actionErr := explainActionForMode(mode, commandInput, toolName, toolInput, filePath)
				if actionErr != nil {
					return cliutil.ExitCodeError(cliutil.ExitConfig, actionErr)
				}
				report, err = buildExplainSurfaceReport(cmd, cfg, cfgLabel, mode, blockedAction, action)
			}
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
				printExplainReport(cmd.OutOrStdout(), report, explainPrintOptions{ShowRaw: showRaw, Hexdump: hexdump})
			}
			// A blocked verdict exits non-zero so scripts can branch on it,
			// matching `pipelock check --url`'s contract.
			if !report.Allowed {
				blockErr := errExplainBlocked
				if report.Surface != "" {
					blockErr = errExplainActionBlocked
				}
				return cliutil.ExitCodeError(cliutil.ExitSecurity, blockErr)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path (default: built-in defaults)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output report as JSON")
	cmd.Flags().StringVar(&commandInput, "command", "", "explain a shell command hook verdict")
	cmd.Flags().StringVar(&toolName, "tool", "", "explain a tool-use hook verdict for this tool name")
	cmd.Flags().StringVar(&toolInput, "input", "", "JSON tool input for --tool")
	cmd.Flags().StringVar(&filePath, "file", "", "explain a file-write hook verdict by scanning this file's content")
	cmd.Flags().BoolVar(&showRaw, "show-raw", false, "append raw field bytes in human output")
	cmd.Flags().BoolVar(&hexdump, "hexdump", false, "append canonical raw field hexdumps in human output")

	// `explain mcp-response` explains an MCP response block and names the
	// per-server suppress knob (the stdio MCP equivalent of a URL verdict).
	cmd.AddCommand(explainEventCmd())
	cmd.AddCommand(explainMCPResponseCmd())

	return cmd
}

// errExplainBlocked is the sentinel returned when explain reports a blocked
// URL. It carries the security exit code so callers can branch on a block
// without parsing output.
var errExplainBlocked = errors.New("url blocked")

var errExplainActionBlocked = errors.New("action blocked")

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

func explainLoadConfigForMode(path, mode string) (*config.Config, string, error) {
	if mode == "" {
		return explainLoadConfig(path)
	}
	return explainLoadSurfaceConfig(path)
}

func explainLoadSurfaceConfig(path string) (*config.Config, string, error) {
	if path != "" {
		cfg, err := config.Load(path)
		if err != nil {
			return nil, "", fmt.Errorf("config load error: %w", err)
		}
		cfg.ApplyDefaults()
		cfg.DLP.ScanEnv = false
		return cfg, path, nil
	}

	cfg := config.Defaults()
	cfg.MCPToolPolicy = config.MCPToolPolicy{
		Enabled: true,
		Action:  config.ActionBlock,
		Rules:   policy.DefaultToolPolicyRules(),
	}
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPInputScanning.Action = config.ActionBlock
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionBlock
	cfg.ApplyDefaults()
	cfg.DLP.ScanEnv = false

	return cfg, explainConfigLabelDefaults, nil
}

func validateExplainArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("explain accepts at most one positional URL")
	}

	modeCount := 0
	modeNames := make([]string, 0, 4)
	if len(args) == 1 {
		modeCount++
		modeNames = append(modeNames, "url")
	}
	for _, name := range []string{explainSurfaceCommand, explainSurfaceTool, explainSurfaceFile} {
		if cmd.Flags().Changed(name) {
			modeCount++
			modeNames = append(modeNames, "--"+name)
		}
	}
	if cmd.Flags().Changed("input") && !cmd.Flags().Changed(explainSurfaceTool) {
		return fmt.Errorf("--input can only be used with --tool")
	}

	switch modeCount {
	case 0:
		return fmt.Errorf("provide exactly one explain target: URL, --command, --tool, or --file")
	case 1:
		return validateExplainModeValues(cmd)
	default:
		return fmt.Errorf("provide exactly one explain target, got %s", strings.Join(modeNames, " and "))
	}
}

func validateExplainModeValues(cmd *cobra.Command) error {
	commandValue, _ := cmd.Flags().GetString(explainSurfaceCommand)
	if cmd.Flags().Changed(explainSurfaceCommand) && strings.TrimSpace(commandValue) == "" {
		return fmt.Errorf("--command cannot be empty")
	}
	toolValue, _ := cmd.Flags().GetString(explainSurfaceTool)
	if cmd.Flags().Changed(explainSurfaceTool) {
		if strings.TrimSpace(toolValue) == "" {
			return fmt.Errorf("--tool cannot be empty")
		}
		inputValue, _ := cmd.Flags().GetString("input")
		if !cmd.Flags().Changed("input") || strings.TrimSpace(inputValue) == "" {
			return fmt.Errorf("--input is required with --tool")
		}
		if !json.Valid([]byte(inputValue)) {
			return fmt.Errorf("--input must be valid JSON")
		}
	}
	fileValue, _ := cmd.Flags().GetString(explainSurfaceFile)
	if cmd.Flags().Changed(explainSurfaceFile) && strings.TrimSpace(fileValue) == "" {
		return fmt.Errorf("--file cannot be empty")
	}
	return nil
}

func explainModeFromFlags(cmd *cobra.Command) string {
	switch {
	case cmd.Flags().Changed(explainSurfaceCommand):
		return explainSurfaceCommand
	case cmd.Flags().Changed(explainSurfaceTool):
		return explainSurfaceTool
	case cmd.Flags().Changed(explainSurfaceFile):
		return explainSurfaceFile
	default:
		return ""
	}
}

func explainActionForMode(mode, commandInput, toolName, toolInput, filePath string) (decide.Action, string, error) {
	switch mode {
	case explainSurfaceCommand:
		commandInput = strings.TrimSpace(commandInput)
		return decide.Action{
			Source: "explain",
			Kind:   decide.EventShellExecution,
			Shell:  &decide.ShellPayload{Command: commandInput},
		}, explainLimitSummary(commandInput), nil
	case explainSurfaceTool:
		toolName = strings.TrimSpace(toolName)
		return decide.Action{
			Source: "explain",
			Kind:   decide.EventToolUse,
			ToolUse: &decide.ToolUsePayload{
				ToolName:  toolName,
				ToolInput: toolInput,
			},
		}, explainLimitSummary("tool " + toolName), nil
	case explainSurfaceFile:
		cleanPath, content, err := explainReadFileContent(filePath)
		if err != nil {
			return decide.Action{}, "", err
		}
		return decide.Action{
			Source: "explain",
			Kind:   decide.EventWriteFile,
			Write: &decide.WritePayload{
				FilePath: cleanPath,
				Content:  content,
			},
		}, explainLimitSummary("write_file " + cleanPath), nil
	default:
		return decide.Action{}, "", fmt.Errorf("unknown explain mode %q", mode)
	}
}

func explainReadFileContent(path string) (string, string, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return "", "", fmt.Errorf("read --file %q: %w", cleanPath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(f, explainFileReadLimitBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("read --file %q: %w", cleanPath, err)
	}
	if len(data) > explainFileReadLimitBytes {
		return "", "", fmt.Errorf("--file %q exceeds explain read cap of %d bytes", cleanPath, explainFileReadLimitBytes)
	}
	return cleanPath, string(data), nil
}

func explainLimitSummary(s string) string {
	if len(s) <= explainSummaryMaxBytes {
		return s
	}
	return s[:explainSummaryMaxBytes] + "..."
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

	sc, err := scanner.New(cfg)
	if err != nil {
		return report, fmt.Errorf("create scanner: %w", err)
	}
	defer sc.Close()
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
	report.Notes = append(report.Notes, explainResponseScanExemptNotes(cfg, report.Host)...)

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

func explainResponseScanExemptNotes(cfg *config.Config, host string) []string {
	if cfg == nil || len(cfg.ResponseScanning.ExemptDomains) == 0 {
		return nil
	}
	if !cfg.ResponseScanning.Enabled {
		return []string{explainResponseScanExemptNarrowAdvice + " " + explainResponseScanExemptDisabled}
	}
	notes := []string{explainResponseScanExemptNarrowAdvice + " " + explainResponseScanExemptBlastRadius}
	if host == "" {
		return notes
	}
	for _, domain := range cfg.ResponseScanning.ExemptDomains {
		if scanner.MatchDomain(host, domain) {
			notes = append(notes, fmt.Sprintf("this host matches `response_scanning.exempt_domains` (%s): responses are fully unscanned for injection, including oversized over-cap responses that stream unscanned", domain))
			return notes
		}
	}
	return notes
}

func buildExplainSurfaceReport(cmd *cobra.Command, cfg *config.Config, cfgLabel, surface, blockedAction string, action decide.Action) (explainReport, error) {
	report := explainReport{
		Surface:       surface,
		BlockedAction: blockedAction,
		ConfigFile:    cfgLabel,
		Mode:          cfg.Mode,
		Version:       cliutil.Version,
		TargetView:    surface,
	}

	bundleResult := rules.MergeIntoConfig(cfg, cliutil.Version)
	for _, e := range bundleResult.Errors {
		report.Notes = append(report.Notes, fmt.Sprintf("rule bundle %s skipped: %s", e.Name, e.Reason))
	}

	sc, err := scanner.New(cfg)
	if err != nil {
		return report, fmt.Errorf("create scanner: %w", err)
	}
	defer sc.Close()
	pc := policy.New(cfg.MCPToolPolicy)
	decision := decide.Decide(cmd.Context(), cfg, sc, pc, action)

	report.Allowed = decision.Outcome == decide.Allow
	if report.Allowed {
		return report, nil
	}

	primary := explainPrimaryEvidence(decision)
	report.Scanner = primary.Scanner
	report.Layer = primary.Scanner
	report.PatternName = primary.Pattern
	report.Reason = explainEvidenceReason(primary, decision)
	report.Remediation = explainRemediationForEvidence(primary)
	if report.Remediation != nil {
		if g, ok := scanner.GuidanceForResult(primary.Scanner, report.Reason); ok {
			report.AgentReason = g.AgentReason
		}
	}
	return report, nil
}

func explainPrimaryEvidence(decision decide.Decision) decide.Evidence {
	for _, e := range decision.Evidence {
		if e.Action == config.ActionBlock {
			return e
		}
	}
	if len(decision.Evidence) > 0 {
		return decision.Evidence[0]
	}
	return decide.Evidence{
		Scanner: scanner.DecideStructuralLabel,
		Detail:  decision.UserMessage,
		Action:  config.ActionBlock,
	}
}

func explainEvidenceReason(e decide.Evidence, decision decide.Decision) string {
	if e.Detail != "" {
		return e.Detail
	}
	if e.Pattern != "" {
		return e.Pattern
	}
	return decision.UserMessage
}

func explainRemediationForEvidence(e decide.Evidence) *explainRemediation {
	reason := e.Detail
	if reason == "" {
		reason = e.Pattern
	}
	if g, ok := scanner.GuidanceForResult(e.Scanner, reason); ok {
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

type explainPrintOptions struct {
	ShowRaw bool
	Hexdump bool
}

func printExplainReport(w io.Writer, report explainReport, opts explainPrintOptions) {
	_, _ = fmt.Fprintln(w, "Pipelock Explain")
	_, _ = fmt.Fprintln(w, "================")
	if report.Surface != "" {
		printExplainField(w, "Surface", report.Surface, false, opts)
		if report.BlockedAction != "" {
			printExplainField(w, "Action", report.BlockedAction, false, opts)
		}
	} else {
		printExplainField(w, "URL", report.URL, true, opts)
	}
	printExplainField(w, "Config", report.ConfigFile, false, opts)
	printExplainField(w, "Mode", report.Mode, false, opts)
	if report.Host != "" {
		printExplainField(w, "Host", report.Host, true, opts)
	}
	_, _ = fmt.Fprintln(w)

	if report.Allowed {
		_, _ = fmt.Fprintln(w, "Verdict: ALLOWED")
		_, _ = fmt.Fprintf(w, "Score:   %.2f\n", report.Score)
		for _, note := range report.Notes {
			printExplainField(w, "note", note, false, opts)
		}
		return
	}

	_, _ = fmt.Fprintln(w, "Verdict: BLOCKED")
	printExplainField(w, "Scanner", report.Scanner, false, opts)
	printExplainField(w, "Layer", report.Layer, false, opts)
	if report.TargetView != "" {
		printExplainField(w, "Target", report.TargetView, true, opts)
	}
	if report.PatternName != "" {
		printExplainField(w, "Pattern", report.PatternName, false, opts)
	}
	if report.Reason != "" {
		printExplainField(w, "Reason", report.Reason, false, opts)
	}
	_, _ = fmt.Fprintf(w, "Score:   %.2f\n", report.Score)

	if len(report.WarnMatches) > 0 {
		_, _ = fmt.Fprintln(w, "Warn matches:")
		for _, m := range report.WarnMatches {
			printExplainField(w, "  -", fmt.Sprintf("%s (%s)", m.PatternName, m.Severity), false, opts)
		}
	}

	if report.Remediation != nil {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Remediation:")
		printExplainField(w, "  ", report.Remediation.Knob, false, opts)
		if report.Remediation.Broader != "" {
			printExplainField(w, "  broader", report.Remediation.Broader, false, opts)
		}
	}
	if report.AgentReason != "" {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Agent reason:")
		printExplainField(w, "  ", report.AgentReason, false, opts)
	}
	for _, note := range report.Notes {
		printExplainField(w, "note", note, false, opts)
	}
}

func printExplainField(w io.Writer, label, raw string, hostAware bool, opts explainPrintOptions) {
	res := display.Sanitize(raw)
	if hostAware {
		if host := explainDisplayHost(raw); host != "" {
			hostRes := display.SanitizeHost(host)
			res.Annotations = append(res.Annotations, hostRes.Annotations...)
			res.PunycodeASCII = hostRes.PunycodeASCII
			res.PunycodeUnicode = hostRes.PunycodeUnicode
			res.Suspicious = res.Suspicious || hostRes.Suspicious
		} else {
			res = display.SanitizeHost(raw)
		}
	}
	switch {
	case label == "note":
		_, _ = fmt.Fprintf(w, "note: %s\n", res.Safe)
	case label == "  -":
		_, _ = fmt.Fprintf(w, "  - %s\n", res.Safe)
	case strings.TrimSpace(label) == "":
		_, _ = fmt.Fprintf(w, "  %s\n", res.Safe)
	default:
		_, _ = fmt.Fprintf(w, "%-8s %s\n", label+":", res.Safe)
	}
	if res.Suspicious {
		for _, ann := range res.Annotations {
			_, _ = fmt.Fprintf(w, "  ⚠ display anomaly: %s at byte %d: %s\n", ann.Class, ann.Offset, ann.Detail)
		}
		if res.PunycodeASCII != "" && res.PunycodeASCII != res.PunycodeUnicode {
			_, _ = fmt.Fprintf(w, "  punycode: ASCII %s / Unicode %s\n", res.PunycodeASCII, res.PunycodeUnicode)
		}
	}
	if opts.ShowRaw {
		_, _ = fmt.Fprintf(w, "  raw: %q\n", raw)
	}
	if opts.Hexdump {
		_, _ = fmt.Fprintf(w, "  hexdump:\n%s\n", display.Hexdump(raw))
	}
}

func explainDisplayHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if strings.Contains(raw, ".") || strings.HasPrefix(strings.ToLower(raw), "xn--") {
		return raw
	}
	return ""
}
