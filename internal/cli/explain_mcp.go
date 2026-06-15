// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// mcpExplainReport is the structured form of an `explain mcp-response` verdict.
// Like explainReport, the remediation block is the load-bearing part: for an
// MCP response block it names the EXACT per-server suppress entry that lifts the
// block without weakening any other server or scanner.
type mcpExplainReport struct {
	ConfigFile  string                 `json:"config_file"`
	Mode        string                 `json:"mode"`
	Version     string                 `json:"version"`
	ServerName  string                 `json:"server_name,omitempty"`
	Target      string                 `json:"target,omitempty"`
	Allowed     bool                   `json:"allowed"`
	Scanner     string                 `json:"scanner,omitempty"`
	Action      string                 `json:"action,omitempty"`
	Patterns    []string               `json:"patterns,omitempty"`
	Notes       []string               `json:"notes,omitempty"`
	Remediation *mcpExplainRemediation `json:"remediation,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// mcpExplainRemediation names the narrowest verified change for an MCP response
// block: a per-server suppress entry. SuppressEntries is the exact YAML the
// operator adds; Caution states what suppressing allows through for that server.
type mcpExplainRemediation struct {
	// SuppressEntries lists one suppress entry per blocking pattern, already
	// scoped to this server's response target.
	SuppressEntries []config.SuppressEntry `json:"suppress_entries"`
	// RequiresServerName is true when the proxy must be launched with
	// --server-name for the suppress target to take effect.
	RequiresServerName bool `json:"requires_server_name,omitempty"`
	// Caution explains the security tradeoff of suppressing a response pattern.
	Caution string `json:"caution"`
}

// explainMCPResponseScanner is the scanner-surface label reported for MCP
// response-injection blocks. Kept distinct from the URL scanner labels so the
// JSON consumer can tell the surfaces apart.
const explainMCPResponseScanner = "mcp_response_scanning"

func explainMCPResponseCmd() *cobra.Command {
	var configFile string
	var serverName string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "mcp-response",
		Short: "Explain an MCP response block and the exact per-server suppression knob",
		Long: `Read a single JSON-RPC 2.0 MCP response from stdin, scan it for prompt
injection exactly as the MCP response scanner would, and explain any block - naming
the EXACT suppress entry that lifts it for one server without weakening any
other server or any other scanner.

Unlike URL DLP, MCP response scanning consults the top-level suppress: list
scoped by a per-server target ("mcp://<server-name>/response"). The remediation
names that target, which only takes effect when the proxy is launched with
--server-name. Suppressing a response pattern lets that pattern's content
through for THAT server's responses only; scope it to a first-party server you
control.

explain mcp-response performs no network access.

Examples:
  echo '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"..."}]}}' | pipelock explain mcp-response --server-name code-assistant
  pipelock explain mcp-response --config pipelock.yaml --server-name code-assistant < response.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgLabel, err := explainLoadConfig(configFile)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			line, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("read MCP response from stdin: %w", err))
			}
			report := buildMCPExplainReport(cfg, cfgLabel, serverName, line)
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return fmt.Errorf("encode mcp explain report JSON: %w", err)
				}
			} else {
				printMCPExplainReport(cmd.OutOrStdout(), report)
			}
			// A parse error is an input problem (exit 2); a block is a security
			// verdict (exit 3); clean is success.
			if report.Error != "" {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errMCPExplainParse)
			}
			if !report.Allowed {
				return cliutil.ExitCodeError(cliutil.ExitSecurity, errExplainBlocked)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path (default: built-in defaults)")
	cmd.Flags().StringVar(&serverName, "server-name", "", "MCP server identity for the suggested suppress target (mcp://<name>/response)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output report as JSON")

	return cmd
}

// errMCPExplainParse is returned when the supplied response is not a valid
// JSON-RPC line. It carries the config exit code (input error, not a block).
var errMCPExplainParse = fmt.Errorf("invalid MCP response")

// mcpResponseTarget mirrors mcp.MCPProxyOpts.responseTarget: the suppress
// target for a server's MCP responses, or "" when no server name is given.
func mcpResponseTarget(serverName string) string {
	if serverName == "" {
		return ""
	}
	return "mcp://" + serverName + "/response"
}

// mcpResponseTargetDisplay is the suppress target shown to the operator and
// used in the suggested suppress entries. With no --server-name it returns the
// placeholder mcp://<server-name>/response so the report's Target field and the
// remediation entries stay consistent and the operator sees the exact shape to
// produce.
func mcpResponseTargetDisplay(serverName string) string {
	if t := mcpResponseTarget(serverName); t != "" {
		return t
	}
	return "mcp://<server-name>/response"
}

func buildMCPExplainReport(cfg *config.Config, cfgLabel, serverName string, line []byte) mcpExplainReport {
	report := mcpExplainReport{
		ConfigFile: cfgLabel,
		Mode:       cfg.Mode,
		Version:    cliutil.Version,
		ServerName: serverName,
		Target:     mcpResponseTargetDisplay(serverName),
	}

	// Merge installed rule bundles exactly as the runtime scanner would so
	// bundle response patterns are reflected. Surface load errors as notes.
	bundleResult := rules.MergeIntoConfig(cfg, cliutil.Version)
	for _, e := range bundleResult.Errors {
		report.Notes = append(report.Notes, fmt.Sprintf("rule bundle %s skipped: %s", e.Name, e.Reason))
	}

	// MCP response scanning does not touch DNS; disabling the SSRF layer keeps
	// scanner construction self-contained and avoids resolution.
	cfg.Internal = nil
	sc := scanner.New(cfg)
	defer sc.Close()

	// Scan with NO suppression so explain reports what WOULD block; the
	// remediation then names the suppress entry that lifts it. Dispatch exactly
	// as the runtime proxy does (tools/list responses bypass generic response
	// scanning when tool scanning is enabled) so explain never reports a block
	// the proxy would not produce.
	verdict := mcp.ScanResponseDispatch(line, sc, cfg.MCPToolScanning.Enabled, mcp.ResponseScanOptions{})

	if verdict.Error != "" {
		report.Error = verdict.Error
		return report
	}
	if verdict.Clean {
		report.Allowed = true
		return report
	}

	report.Scanner = explainMCPResponseScanner
	report.Action = verdict.Action
	report.Patterns = dedupePatternNames(verdict.Matches)
	report.Remediation = mcpExplainRemediationFor(report.Patterns, serverName)
	if serverName == "" {
		report.Notes = append(report.Notes,
			"no --server-name given: the suppress target is empty and no suppress entry can match. "+
				"Re-run with --server-name <name> matching how the proxy is launched.")
	}
	return report
}

// dedupePatternNames returns the unique blocking pattern names in sorted order.
func dedupePatternNames(matches []scanner.ResponseMatch) []string {
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if m.PatternName != "" {
			seen[m.PatternName] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// mcpExplainRemediationFor builds the per-server suppress remediation: one
// entry per blocking pattern, scoped to this server's response target.
func mcpExplainRemediationFor(patterns []string, serverName string) *mcpExplainRemediation {
	target := mcpResponseTargetDisplay(serverName)
	entries := make([]config.SuppressEntry, 0, len(patterns))
	for _, p := range patterns {
		entries = append(entries, config.SuppressEntry{
			Rule:   p,
			Path:   target,
			Reason: "false positive on first-party server " + serverNameOrPlaceholder(serverName),
		})
	}
	return &mcpExplainRemediation{
		SuppressEntries:    entries,
		RequiresServerName: serverName == "",
		Caution: "Suppressing a response pattern allows that pattern's content through for " +
			"THIS server's responses only. Use it for a first-party server you control; a " +
			"first-party tool can still relay untrusted content, so prefer tightening detection " +
			"precision when the pattern itself is wrong.",
	}
}

func serverNameOrPlaceholder(serverName string) string {
	if serverName == "" {
		return "<server-name>"
	}
	return serverName
}

func printMCPExplainReport(w io.Writer, report mcpExplainReport) {
	_, _ = fmt.Fprintln(w, "Pipelock Explain - MCP Response")
	_, _ = fmt.Fprintln(w, "==============================")
	_, _ = fmt.Fprintf(w, "Config:  %s\n", report.ConfigFile)
	_, _ = fmt.Fprintf(w, "Mode:    %s\n", report.Mode)
	if report.ServerName != "" {
		_, _ = fmt.Fprintf(w, "Server:  %s\n", report.ServerName)
	}
	if report.Target != "" {
		_, _ = fmt.Fprintf(w, "Target:  %s\n", report.Target)
	}
	_, _ = fmt.Fprintln(w)

	if report.Error != "" {
		_, _ = fmt.Fprintf(w, "Verdict: ERROR\n")
		_, _ = fmt.Fprintf(w, "Reason:  %s\n", report.Error)
		return
	}
	if report.Allowed {
		_, _ = fmt.Fprintln(w, "Verdict: ALLOWED")
		for _, note := range report.Notes {
			_, _ = fmt.Fprintf(w, "note: %s\n", note)
		}
		return
	}

	_, _ = fmt.Fprintln(w, "Verdict: BLOCKED")
	_, _ = fmt.Fprintf(w, "Scanner: %s\n", report.Scanner)
	_, _ = fmt.Fprintf(w, "Action:  %s\n", report.Action)
	if len(report.Patterns) > 0 {
		_, _ = fmt.Fprintf(w, "Patterns: %s\n", strings.Join(report.Patterns, ", "))
	}

	if report.Remediation != nil {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Remediation - add to config `suppress:`")
		for _, e := range report.Remediation.SuppressEntries {
			_, _ = fmt.Fprintf(w, "  - rule: %q\n    path: %q\n    reason: %q\n", e.Rule, e.Path, e.Reason)
		}
		if report.Remediation.RequiresServerName {
			_, _ = fmt.Fprintln(w, "  (launch the proxy with --server-name <name> so the target matches)")
		}
		_, _ = fmt.Fprintf(w, "  caution: %s\n", report.Remediation.Caution)
	}
	for _, note := range report.Notes {
		_, _ = fmt.Fprintf(w, "note: %s\n", note)
	}
}
