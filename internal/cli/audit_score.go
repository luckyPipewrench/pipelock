// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Score finding severity levels.
const (
	scoreSevCritical = "critical"
	scoreSevWarning  = "warning"
	scoreSevInfo     = "info"
)

// ScoreCategory represents a scored aspect of the pipelock configuration.
type ScoreCategory struct {
	Name     string `json:"name"`
	Score    int    `json:"score"`
	MaxScore int    `json:"max_score"`
	Detail   string `json:"detail,omitempty"`
}

// ScoreResult holds the overall config security score.
type ScoreResult struct {
	TotalScore int             `json:"total_score"`
	MaxScore   int             `json:"max_score"`
	Percentage int             `json:"percentage"`
	Grade      string          `json:"grade"`
	Categories []ScoreCategory `json:"categories"`
	Findings   []ScoreFinding  `json:"findings,omitempty"`
	ConfigFile string          `json:"config_file,omitempty"`
}

// ScoreFinding is a recommendation for improving the config.
type ScoreFinding struct {
	Severity string `json:"severity"` // critical, warning, info
	Category string `json:"category"`
	Message  string `json:"message"`
}

func auditScoreCmd() *cobra.Command {
	var configFile string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "score",
		Short: "Score a pipelock config for security posture",
		Args:  cobra.NoArgs,
		Long: `Analyze a pipelock configuration file and produce a security posture score.

Checks whether security features are enabled and properly configured.
Identifies overly permissive tool policies and missing protections.

Examples:
  pipelock audit score --config pipelock.yaml
  pipelock audit score --config pipelock.yaml --json
  pipelock audit score  # scores defaults`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfigOrDefault(configFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			result := scoreConfig(cfg, configFile)

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			printScoreResult(cmd, result)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file to score (default: built-in defaults)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output as JSON")

	return cmd
}

// scoreConfig evaluates a config and returns a scored result.
func scoreConfig(cfg *config.Config, cfgFile string) *ScoreResult {
	var categories []ScoreCategory
	var findings []ScoreFinding

	// 1. DLP (15 points)
	categories = append(categories, scoreDLP(cfg, &findings))

	// 2. Response scanning (10 points)
	categories = append(categories, scoreResponseScanning(cfg, &findings))

	// 3. MCP tool scanning (10 points)
	categories = append(categories, scoreMCPToolScanning(cfg, &findings))

	// 4. MCP tool policy (15 points)
	cat, policyFindings := scoreMCPToolPolicy(cfg)
	categories = append(categories, cat)
	findings = append(findings, policyFindings...)

	// 5. MCP input scanning (5 points)
	categories = append(categories, scoreMCPInputScanning(cfg, &findings))

	// 6. MCP session binding (5 points)
	categories = append(categories, scoreMCPSessionBinding(cfg, &findings))

	// 7. Kill switch (10 points)
	categories = append(categories, scoreKillSwitch(cfg, &findings))

	// 8. Enforcement mode (10 points)
	categories = append(categories, scoreEnforcement(cfg, &findings))

	// 9. Domain blocklist (5 points)
	categories = append(categories, scoreDomainBlocklist(cfg, &findings))

	// 10. Adaptive enforcement (5 points)
	categories = append(categories, scoreAdaptiveEnforcement(cfg, &findings))

	// 11. Tool chain detection (5 points)
	categories = append(categories, scoreToolChainDetection(cfg, &findings))

	// 12. Sandbox (5 points)
	categories = append(categories, scoreSandbox(cfg, &findings))

	total := 0
	maxTotal := 0
	for _, c := range categories {
		total += c.Score
		maxTotal += c.MaxScore
	}

	pct := 0
	if maxTotal > 0 {
		pct = (total * 100) / maxTotal
	}

	return &ScoreResult{
		TotalScore: total,
		MaxScore:   maxTotal,
		Percentage: pct,
		Grade:      scoreGrade(pct),
		Categories: categories,
		Findings:   findings,
		ConfigFile: cfgFile,
	}
}

func scoreGrade(pct int) string {
	switch {
	case pct >= 90:
		return "A"
	case pct >= 80:
		return "B"
	case pct >= 70:
		return "C"
	case pct >= 60:
		return "D"
	default:
		return "F"
	}
}

// maxDLPScore is the maximum points awarded for DLP configuration.
const maxDLPScore = 15

func scoreDLP(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	patternCount := len(cfg.DLP.Patterns)
	// DLP is enabled when patterns exist (no separate Enabled field).
	if patternCount > 0 {
		score += 5
		switch {
		case patternCount >= 40:
			score += 5 // comprehensive pattern coverage
		case patternCount >= 20:
			score += 3
		default:
			score += 1
		}
		if cfg.DLP.ScanEnv {
			score += 3 // env leak scanning enabled
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: "DLP",
				Message:  "Environment variable leak scanning is disabled (dlp.scan_env: false)",
			})
		}
		if cfg.FetchProxy.Monitoring.EntropyThreshold > 0 {
			score += 2 // entropy detection configured
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevCritical,
			Category: "DLP",
			Message:  "No DLP patterns configured — secrets can leak in URLs and request bodies",
		})
	}
	return ScoreCategory{Name: "DLP", Score: min(score, maxDLPScore), MaxScore: maxDLPScore, Detail: fmt.Sprintf("%d patterns", patternCount)}
}

// maxResponseScanningScore is the maximum points for response scanning.
const maxResponseScanningScore = 10

func scoreResponseScanning(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.ResponseScanning.Enabled {
		score += 4
		if len(cfg.ResponseScanning.Patterns) >= 10 {
			score += 3
		} else if len(cfg.ResponseScanning.Patterns) > 0 {
			score += 1
		}
		if cfg.ResponseScanning.Action == config.ActionBlock || cfg.ResponseScanning.Action == config.ActionAsk {
			score += 3 // blocking or HITL on injection
		} else {
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: "Response Scanning",
				Message:  fmt.Sprintf("Response scanning action is %q — consider 'block' or 'ask' for enforcement", cfg.ResponseScanning.Action),
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevCritical,
			Category: "Response Scanning",
			Message:  "Response scanning is disabled — prompt injection in tool results won't be detected",
		})
	}
	return ScoreCategory{Name: "Response Scanning", Score: min(score, maxResponseScanningScore), MaxScore: maxResponseScanningScore, Detail: fmt.Sprintf("%d patterns, action=%s", len(cfg.ResponseScanning.Patterns), cfg.ResponseScanning.Action)}
}

// maxMCPToolScanningScore is the maximum points for tool scanning.
const maxMCPToolScanningScore = 10

func scoreMCPToolScanning(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.MCPToolScanning.Enabled {
		score += 5
		switch cfg.MCPToolScanning.Action {
		case config.ActionBlock:
			score += 5
		case config.ActionAsk:
			score += 4
		default:
			score += 2
			*findings = append(*findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: "MCP Tool Scanning",
				Message:  fmt.Sprintf("Tool scanning action is %q — poisoned tool descriptions won't be blocked", cfg.MCPToolScanning.Action),
			})
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevCritical,
			Category: "MCP Tool Scanning",
			Message:  "MCP tool scanning is disabled — tool poisoning and rug-pull attacks won't be detected",
		})
	}
	return ScoreCategory{Name: "MCP Tool Scanning", Score: min(score, maxMCPToolScanningScore), MaxScore: maxMCPToolScanningScore, Detail: fmt.Sprintf("action=%s", cfg.MCPToolScanning.Action)}
}

// maxMCPToolPolicyScore is the maximum points for tool policy.
const maxMCPToolPolicyScore = 15

func scoreMCPToolPolicy(cfg *config.Config) (ScoreCategory, []ScoreFinding) {
	var findings []ScoreFinding
	score := 0

	if cfg.MCPToolPolicy.Enabled {
		score += 5
		ruleCount := len(cfg.MCPToolPolicy.Rules)
		switch {
		case ruleCount >= 10:
			score += 5
		case ruleCount >= 5:
			score += 3
		case ruleCount > 0:
			score += 1
		default:
			findings = append(findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: "MCP Tool Policy",
				Message:  "Tool policy is enabled but has no rules — no tool calls will be restricted",
			})
		}

		// Check for overpermission patterns.
		// Use effective action (rule override or section-level default) for all checks.
		defaultAction := cfg.MCPToolPolicy.Action
		blockRuleCount := 0
		for _, rule := range cfg.MCPToolPolicy.Rules {
			effective := effectiveAction(rule.Action, defaultAction)
			if effective == config.ActionBlock {
				blockRuleCount++
			}

			// Flag wildcard arg patterns (exact or anchored forms).
			if isWildcardArgPattern(rule.ArgPattern) {
				findings = append(findings, ScoreFinding{
					Severity: scoreSevWarning,
					Category: "MCP Tool Policy",
					Message:  fmt.Sprintf("Rule %q has wildcard arg_pattern %q — matches all arguments, consider narrowing", rule.Name, rule.ArgPattern),
				})
			}

			// Flag warn on high-risk tool patterns (only if effective action is not block).
			if effective != config.ActionBlock && isHighRiskToolPattern(rule.ToolPattern) {
				findings = append(findings, ScoreFinding{
					Severity: scoreSevWarning,
					Category: "MCP Tool Policy",
					Message:  fmt.Sprintf("Rule %q matches high-risk tools but effective action is %q — consider 'block'", rule.Name, effective),
				})
			}
		}

		if blockRuleCount > 0 {
			score += 5 // has blocking rules (explicit or inherited)
		} else if ruleCount > 0 {
			findings = append(findings, ScoreFinding{
				Severity: scoreSevWarning,
				Category: "MCP Tool Policy",
				Message:  "No tool policy rules effectively block — dangerous tool calls will only generate warnings",
			})
		}
	} else {
		findings = append(findings, ScoreFinding{
			Severity: scoreSevWarning,
			Category: "MCP Tool Policy",
			Message:  "MCP tool policy is disabled — no pre-execution rules on tool calls",
		})
	}

	detail := fmt.Sprintf("%d rules", len(cfg.MCPToolPolicy.Rules))
	return ScoreCategory{Name: "MCP Tool Policy", Score: min(score, maxMCPToolPolicyScore), MaxScore: maxMCPToolPolicyScore, Detail: detail}, findings
}

// highRiskToolPatterns are regex fragments that match dangerous tool names.
var highRiskToolPatterns = []string{
	"bash", "shell", "exec", "terminal", "run_command", "execute",
	"write_file", "file_write", "create_file", "modify_file",
	"delete", "remove", "rm", "rmdir",
}

func isHighRiskToolPattern(pattern string) bool {
	lower := strings.ToLower(pattern)
	for _, risk := range highRiskToolPatterns {
		if strings.Contains(lower, risk) {
			return true
		}
	}
	return false
}

// isWildcardArgPattern returns true if an arg_pattern effectively matches
// all input. Catches exact wildcards (.*/.+) and anchored forms (^.*$, ^.+$).
func isWildcardArgPattern(pattern string) bool {
	stripped := strings.TrimPrefix(strings.TrimSuffix(pattern, "$"), "^")
	return stripped == ".*" || stripped == ".+"
}

func effectiveAction(ruleAction, defaultAction string) string {
	if ruleAction != "" {
		return ruleAction
	}
	return defaultAction
}

// maxMCPInputScanningScore is the maximum points for input scanning.
const maxMCPInputScanningScore = 5

func scoreMCPInputScanning(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.MCPInputScanning.Enabled {
		score += 5
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: "MCP Input Scanning",
			Message:  "MCP input scanning is disabled — agent-to-server DLP and injection checks are off",
		})
	}
	return ScoreCategory{Name: "MCP Input Scanning", Score: min(score, maxMCPInputScanningScore), MaxScore: maxMCPInputScanningScore}
}

// maxMCPSessionBindingScore is the maximum points for session binding.
const maxMCPSessionBindingScore = 5

func scoreMCPSessionBinding(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.MCPSessionBinding.Enabled {
		score += 5
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: "MCP Session Binding",
			Message:  "MCP session binding is disabled — tool inventory changes mid-session won't be detected",
		})
	}
	return ScoreCategory{Name: "MCP Session Binding", Score: min(score, maxMCPSessionBindingScore), MaxScore: maxMCPSessionBindingScore}
}

// maxKillSwitchScore is the maximum points for kill switch.
const maxKillSwitchScore = 10

func scoreKillSwitch(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	sources := 0
	if cfg.KillSwitch.Enabled {
		score += 4
		sources++
	}
	if cfg.KillSwitch.APIListen != "" {
		score += 3 // remote kill switch API
		sources++
	}
	if cfg.KillSwitch.SentinelFile != "" {
		score += 3 // sentinel file watch
		sources++
	}
	if sources == 0 {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevWarning,
			Category: "Kill Switch",
			Message:  "No kill switch sources configured — no emergency stop capability",
		})
	}
	return ScoreCategory{Name: "Kill Switch", Score: min(score, maxKillSwitchScore), MaxScore: maxKillSwitchScore, Detail: fmt.Sprintf("%d sources", sources)}
}

// maxEnforcementScore is the maximum points for enforcement mode.
const maxEnforcementScore = 10

func scoreEnforcement(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	enforce := cfg.Enforce == nil || *cfg.Enforce // default true
	if enforce {
		score += 5
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevCritical,
			Category: "Enforcement",
			Message:  "Enforcement is disabled (enforce: false) — pipelock will detect but not block",
		})
	}
	switch cfg.Mode {
	case config.ModeStrict:
		score += 5
	case config.ModeBalanced:
		score += 3
	case config.ModeAudit:
		score += 1
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: "Enforcement",
			Message:  "Mode is 'audit' — all traffic is forwarded regardless of scan results",
		})
	}
	return ScoreCategory{Name: "Enforcement", Score: min(score, maxEnforcementScore), MaxScore: maxEnforcementScore, Detail: fmt.Sprintf("mode=%s, enforce=%v", cfg.Mode, enforce)}
}

// maxDomainBlocklistScore is the maximum points for domain blocklist.
const maxDomainBlocklistScore = 5

func scoreDomainBlocklist(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	blockCount := len(cfg.FetchProxy.Monitoring.Blocklist)
	if blockCount > 0 {
		score += 5
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: "Domain Blocklist",
			Message:  "No domain blocklist configured — known exfiltration domains are not blocked",
		})
	}
	return ScoreCategory{Name: "Domain Blocklist", Score: min(score, maxDomainBlocklistScore), MaxScore: maxDomainBlocklistScore, Detail: fmt.Sprintf("%d entries", blockCount)}
}

// maxAdaptiveScore is the maximum points for adaptive enforcement.
const maxAdaptiveScore = 5

func scoreAdaptiveEnforcement(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.AdaptiveEnforcement.Enabled {
		score += 5
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: "Adaptive Enforcement",
			Message:  "Adaptive enforcement is disabled — no automatic escalation on suspicious patterns",
		})
	}
	return ScoreCategory{Name: "Adaptive Enforcement", Score: min(score, maxAdaptiveScore), MaxScore: maxAdaptiveScore}
}

// maxToolChainScore is the maximum points for tool chain detection.
const maxToolChainScore = 5

func scoreToolChainDetection(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.ToolChainDetection.Enabled {
		score += 3
		if len(cfg.ToolChainDetection.CustomPatterns) > 0 {
			score += 2
		}
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: "Tool Chain Detection",
			Message:  "Tool chain detection is disabled — multi-step attack sequences won't trigger alerts",
		})
	}
	return ScoreCategory{Name: "Tool Chain Detection", Score: min(score, maxToolChainScore), MaxScore: maxToolChainScore}
}

// maxSandboxScore is the maximum points for sandbox configuration.
const maxSandboxScore = 5

func scoreSandbox(cfg *config.Config, findings *[]ScoreFinding) ScoreCategory {
	score := 0
	if cfg.Sandbox.Enabled {
		score += 5
	} else {
		*findings = append(*findings, ScoreFinding{
			Severity: scoreSevInfo,
			Category: "Sandbox",
			Message:  "Sandbox is not enabled — agent processes run without containment",
		})
	}
	return ScoreCategory{Name: "Sandbox", Score: min(score, maxSandboxScore), MaxScore: maxSandboxScore}
}

func printScoreResult(cmd *cobra.Command, r *ScoreResult) {
	cmd.PrintErrln("Pipelock Config Security Score")
	cmd.PrintErrln("==============================")
	if r.ConfigFile != "" {
		cmd.PrintErrf("Config: %s\n", r.ConfigFile)
	} else {
		cmd.PrintErrln("Config: (built-in defaults)")
	}
	cmd.PrintErrln()

	for _, c := range r.Categories {
		bar := scoreBar(c.Score, c.MaxScore)
		detail := ""
		if c.Detail != "" {
			detail = " (" + c.Detail + ")"
		}
		cmd.PrintErrf("  %-25s %s %d/%d%s\n", c.Name, bar, c.Score, c.MaxScore, detail)
	}

	cmd.PrintErrln()
	cmd.PrintErrf("Overall: %d/%d (%d%%) Grade: %s\n", r.TotalScore, r.MaxScore, r.Percentage, r.Grade)

	if len(r.Findings) > 0 {
		cmd.PrintErrln()
		cmd.PrintErrln("Recommendations:")
		for _, f := range r.Findings {
			var prefix string
			switch f.Severity {
			case scoreSevCritical:
				prefix = "  [CRITICAL] "
			case "warning":
				prefix = "  [WARNING]  "
			default:
				prefix = "  [INFO]     "
			}
			cmd.PrintErrf("%s%s\n", prefix, f.Message)
		}
	}
}

func scoreBar(score, maxScore int) string {
	// 10-char bar representing score proportion.
	const barWidth = 10
	filled := 0
	if maxScore > 0 {
		filled = (score * barWidth) / maxScore
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled) + "]"
}
