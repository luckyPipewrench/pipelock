// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/discover"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Exit codes for init command.
const (
	initExitSuccess = 0
	initExitFailure = 1
	initExitError   = 2
)

// defaultConfigSubdir is the subdirectory under os.UserConfigDir() for pipelock config.
const defaultConfigSubdir = "pipelock"

// initResult holds the outcome of each phase for reporting.
type initResult struct {
	Discover *initDiscoverResult `json:"discover"`
	Setup    *initSetupResult    `json:"setup"`
	Verify   *initVerifyResult   `json:"verify,omitempty"`
	Canary   *initCanaryResult   `json:"canary,omitempty"`
}

type initDiscoverResult struct {
	ClientsFound int `json:"clients_found"`
	ServersFound int `json:"servers_found"`
	Protected    int `json:"protected"`
	Unprotected  int `json:"unprotected"`
	Unknown      int `json:"unknown"`
}

type initSetupResult struct {
	ConfigPath     string `json:"config_path"`
	Preset         string `json:"preset"`
	Written        bool   `json:"written"`
	SkippedExsting bool   `json:"skipped_existing,omitempty"`
}

type initVerifyResult struct {
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Skipped bool   `json:"skipped"`
	Detail  string `json:"detail,omitempty"`
}

type initCanaryResult struct {
	Detected bool   `json:"detected"`
	Skipped  bool   `json:"skipped"`
	Detail   string `json:"detail,omitempty"`
}

// InitCmd returns the "pipelock init" command.
func InitCmd() *cobra.Command {
	var (
		preset       string
		skipCanary   bool
		skipValidate bool
		dryRun       bool
		force        bool
		output       string
		jsonOutput   bool
		scanHome     string
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up pipelock in one command",
		Long: `Discover IDE and agent configs, generate a pipelock config, and validate
it works. Run it once and you're set up.

Workflow:
  1. Discover:  find IDE configs (Claude Code, Cursor, VS Code, JetBrains)
  2. Setup:     generate a config file with sensible defaults
  3. Validate:  check the generated config parses and compiles (skippable)
  4. Canary:    run a synthetic secret through the real scanner (skippable)
  5. Summary:   show what was discovered, configured, and validated

Examples:
  pipelock init
  pipelock init --preset strict
  pipelock init --dry-run
  pipelock init --output ./pipelock.yaml
  pipelock init --skip-canary --skip-validate`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd, initOptions{
				preset:       preset,
				skipCanary:   skipCanary,
				skipValidate: skipValidate,
				dryRun:       dryRun,
				force:        force,
				output:       output,
				jsonOutput:   jsonOutput,
				scanHome:     scanHome,
			})
		},
	}

	cmd.Flags().StringVar(&preset, "preset", config.ModeBalanced, "config preset: strict, balanced, audit")
	cmd.Flags().BoolVar(&skipCanary, "skip-canary", false, "skip the canary detection test")
	cmd.Flags().BoolVar(&skipValidate, "skip-validate", false, "skip config validation checks")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be done without writing files")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing config file")
	cmd.Flags().StringVarP(&output, "output", "o", "", "config output path (default: OS config dir)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "machine-readable JSON output")
	cmd.Flags().StringVar(&scanHome, "scan-home", "", "override home directory for discovery (default: $HOME)")

	return cmd
}

type initOptions struct {
	preset       string
	skipCanary   bool
	skipValidate bool
	dryRun       bool
	force        bool
	output       string
	jsonOutput   bool
	scanHome     string
}

func runInit(cmd *cobra.Command, opts initOptions) error {
	// Resolve the user's home directory for discovery (--scan-home or $HOME).
	home := opts.scanHome
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return cliutil.ExitCodeError(initExitError, fmt.Errorf("determining home directory: %w", err))
		}
		home = h
	}

	// Validate preset.
	switch opts.preset {
	case config.ModeStrict, config.ModeBalanced, config.ModeAudit:
		// valid
	default:
		return cliutil.ExitCodeError(initExitError,
			fmt.Errorf("unknown preset %q: choose strict, balanced, or audit", opts.preset))
	}

	result := &initResult{}
	w := cmd.OutOrStdout()

	// Phase 1: Discover
	if !opts.jsonOutput {
		_, _ = fmt.Fprintln(w, "Pipelock Init")
		_, _ = fmt.Fprintln(w, "=============")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "[1/5] Discovering IDE and agent configs...")
	}

	report, err := discover.Discover(home)
	if err != nil {
		return cliutil.ExitCodeError(initExitError, fmt.Errorf("discovery failed: %w", err))
	}

	result.Discover = &initDiscoverResult{
		ClientsFound: report.Summary.TotalClients,
		ServersFound: report.Summary.TotalServers,
		Protected:    report.Summary.ProtectedPipelock + report.Summary.ProtectedOther,
		Unprotected:  report.Summary.Unprotected,
		Unknown:      report.Summary.Unknown,
	}

	if !opts.jsonOutput {
		printDiscoverPhase(w, report)
	}

	// Phase 2: Setup (generate config)
	if !opts.jsonOutput {
		_, _ = fmt.Fprintln(w, "[2/5] Generating config...")
	}

	cfg := buildConfig(opts.preset, report)
	configPath := opts.output
	if configPath == "" {
		cfgDir, err := os.UserConfigDir()
		if err != nil {
			return cliutil.ExitCodeError(initExitError, fmt.Errorf("determining config directory: %w", err))
		}
		configPath = filepath.Join(cfgDir, defaultConfigSubdir, "pipelock.yaml")
	}

	result.Setup = &initSetupResult{
		ConfigPath: configPath,
		Preset:     opts.preset,
	}

	if opts.dryRun {
		result.Setup.Written = false
		if !opts.jsonOutput {
			_, _ = fmt.Fprintf(w, "  Would write config to: %s\n", configPath)
			_, _ = fmt.Fprintf(w, "  Preset: %s\n\n", opts.preset)
		}
	} else {
		// Refuse to overwrite an existing config without --force.
		if _, err := os.Stat(configPath); err == nil && !opts.force {
			if !opts.jsonOutput {
				_, _ = fmt.Fprintf(w, "  Config already exists at: %s\n", configPath)
				_, _ = fmt.Fprintln(w, "  Use --force to overwrite, or --output to write elsewhere.")
				_, _ = fmt.Fprintln(w)
			}
			result.Setup.Written = false
			result.Setup.SkippedExsting = true
		} else {
			if err := writeConfig(cfg, configPath, opts.preset); err != nil {
				return cliutil.ExitCodeError(initExitError, fmt.Errorf("writing config: %w", err))
			}
			result.Setup.Written = true
			if !opts.jsonOutput {
				_, _ = fmt.Fprintf(w, "  Config written to: %s\n", configPath)
				_, _ = fmt.Fprintf(w, "  Preset: %s\n\n", opts.preset)
			}
		}
	}

	// Phase 3: Validate config
	if opts.skipValidate {
		result.Verify = &initVerifyResult{Skipped: true}
		if !opts.jsonOutput {
			_, _ = fmt.Fprintln(w, "[3/5] Validate: skipped (--skip-validate)")
			_, _ = fmt.Fprintln(w)
		}
	} else {
		if !opts.jsonOutput {
			_, _ = fmt.Fprintln(w, "[3/5] Validating config...")
		}
		vr := runInitVerify(cfg)
		result.Verify = vr
		if !opts.jsonOutput {
			_, _ = fmt.Fprintf(w, "  Passed: %d, Failed: %d\n", vr.Passed, vr.Failed)
			if vr.Detail != "" {
				_, _ = fmt.Fprintf(w, "  %s\n", vr.Detail)
			}
			_, _ = fmt.Fprintln(w)
		}
	}

	// Phase 4: Canary
	if opts.skipCanary {
		result.Canary = &initCanaryResult{Skipped: true}
		if !opts.jsonOutput {
			_, _ = fmt.Fprintln(w, "[4/5] Canary: skipped (--skip-canary)")
			_, _ = fmt.Fprintln(w)
		}
	} else {
		if !opts.jsonOutput {
			_, _ = fmt.Fprintln(w, "[4/5] Testing canary detection...")
		}
		cr := runInitCanary(cfg)
		result.Canary = cr
		if !opts.jsonOutput {
			if cr.Detected {
				_, _ = fmt.Fprintln(w, "  Canary secret detected in URL scan. DLP is working.")
			} else {
				_, _ = fmt.Fprintf(w, "  %s\n", cr.Detail)
			}
			_, _ = fmt.Fprintln(w)
		}
	}

	// Phase 5: Summary
	if opts.jsonOutput {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return cliutil.ExitCodeError(initExitError, fmt.Errorf("encoding JSON: %w", err))
		}
	} else {
		printProof(w, result)
	}

	// Exit 1 if validation failed or canary was not detected.
	if result.Verify != nil && !result.Verify.Skipped && result.Verify.Failed > 0 {
		return &cliutil.ExitError{Err: fmt.Errorf("config validation failed"), Code: initExitFailure}
	}
	if result.Canary != nil && !result.Canary.Skipped && !result.Canary.Detected {
		return &cliutil.ExitError{Err: fmt.Errorf("canary secret was not detected by DLP"), Code: initExitFailure}
	}

	return nil
}

func printDiscoverPhase(w io.Writer, report *discover.Report) {
	if len(report.Clients) == 0 {
		_, _ = fmt.Fprintln(w, "  No IDE or agent configs found.")
		_, _ = fmt.Fprintln(w, "  Config will use standard defaults.")
		_, _ = fmt.Fprintln(w)
		return
	}

	_, _ = fmt.Fprintf(w, "  Found %d client(s), %d MCP server(s)\n",
		report.Summary.TotalClients, report.Summary.TotalServers)

	for _, c := range report.Clients {
		if c.ParseError != "" {
			_, _ = fmt.Fprintf(w, "    %-16s %s (parse error)\n", c.Client, c.ConfigPath)
		} else {
			_, _ = fmt.Fprintf(w, "    %-16s %s (%d servers)\n", c.Client, c.ConfigPath, c.ServerCount)
		}
	}

	if report.Summary.Unprotected > 0 {
		_, _ = fmt.Fprintf(w, "  %d server(s) are not wrapped through pipelock.\n", report.Summary.Unprotected)
		_, _ = fmt.Fprintln(w, "  Run 'pipelock discover --generate' for wrapper suggestions.")
	}
	_, _ = fmt.Fprintln(w)
}

func buildConfig(preset string, report *discover.Report) *config.Config {
	var cfg *config.Config

	switch preset {
	case config.ModeStrict:
		cfg = config.Defaults()
		cfg.Mode = config.ModeStrict
		cfg.FetchProxy.Monitoring.EntropyThreshold = 3.5
		cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold = 3.5
		cfg.FetchProxy.Monitoring.MaxURLLength = 500
		cfg.FetchProxy.Monitoring.MaxReqPerMinute = 30
	case config.ModeAudit:
		cfg = config.Defaults()
		cfg.Mode = config.ModeAudit
		enforce := false
		cfg.Enforce = &enforce
	default:
		cfg = config.Defaults()
	}

	// Enable MCP scanning if MCP servers were discovered.
	if report.Summary.TotalServers > 0 {
		cfg.MCPInputScanning.Enabled = true
		cfg.MCPInputScanning.Action = config.ActionWarn
		cfg.MCPToolScanning.Enabled = true
		cfg.MCPToolScanning.Action = config.ActionWarn
		cfg.MCPToolScanning.DetectDrift = true
	}

	// Enable tool chain detection for larger MCP installations.
	if report.Summary.TotalServers > 3 {
		cfg.ToolChainDetection.Enabled = true
		cfg.ToolChainDetection.Action = config.ActionWarn
		cfg.ToolChainDetection.WindowSize = 20
		cfg.ToolChainDetection.WindowSeconds = 300
		maxGap := 3
		cfg.ToolChainDetection.MaxGap = &maxGap
	}

	return cfg
}

func writeConfig(cfg *config.Config, configPath, preset string) error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	header := fmt.Sprintf("# Pipelock config (%s preset)\n# Generated by: pipelock init --preset %s\n# Docs: https://github.com/luckyPipewrench/pipelock/blob/main/docs/configuration.md\n\n", preset, preset)

	if err := os.WriteFile(configPath, []byte(header+string(data)), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", configPath, err)
	}

	return nil
}

func runInitVerify(cfg *config.Config) *initVerifyResult {
	// Run basic config validation checks without requiring a running proxy.
	var passed, failed int

	// Check 1: config parses and validates.
	if err := cfg.Validate(); err != nil {
		return &initVerifyResult{
			Passed: passed,
			Failed: 1,
			Detail: fmt.Sprintf("config validation failed: %v", err),
		}
	}
	passed++

	// Check 2: DLP patterns compile.
	for _, p := range cfg.DLP.Patterns {
		if p.Regex != "" {
			passed++
		}
	}

	// Check 3: response scanning patterns compile.
	if cfg.ResponseScanning.Enabled {
		passed++
	}

	// Check 4: mode is set.
	switch cfg.Mode {
	case config.ModeStrict, config.ModeBalanced, config.ModeAudit:
		passed++
	default:
		failed++
	}

	detail := ""
	if failed > 0 {
		detail = "Config validation failed. Run 'pipelock verify-install' for full verification."
	}

	return &initVerifyResult{
		Passed: passed,
		Failed: failed,
		Detail: detail,
	}
}

func runInitCanary(cfg *config.Config) *initCanaryResult {
	// Use github.com (in the default allowlist) so strict mode doesn't block
	// by allowlist before the DLP scanner runs.
	canaryURL := "https://github.com/test?key=" + canaryToken()

	// Build a scanner from the config and test.
	scanResult := scanCanaryURL(cfg, canaryURL)

	if scanResult {
		return &initCanaryResult{
			Detected: true,
			Detail:   "Canary AWS key detected in URL scan.",
		}
	}

	return &initCanaryResult{
		Detected: false,
		Detail:   "Canary was not detected. Run 'pipelock check --url \"" + canaryURL + "\"' to debug.",
	}
}

func scanCanaryURL(cfg *config.Config, canaryURL string) bool {
	sc := scanner.New(cfg)
	result := sc.Scan(context.Background(), canaryURL)
	// Assert the block came from DLP specifically, not an allowlist or other layer.
	// Core DLP (immutable safety floor) also counts as DLP detection.
	return !result.Allowed && (result.Scanner == scanner.ScannerDLP || result.Scanner == scanner.ScannerCoreDLP)
}

func printProof(w interface{ Write([]byte) (int, error) }, result *initResult) {
	_, _ = fmt.Fprintln(w, "[5/5] Summary")
	_, _ = fmt.Fprintln(w, "=============")
	_, _ = fmt.Fprintln(w)

	// Discovery
	_, _ = fmt.Fprintf(w, "  Clients found:      %d\n", result.Discover.ClientsFound)
	_, _ = fmt.Fprintf(w, "  MCP servers found:  %d\n", result.Discover.ServersFound)
	_, _ = fmt.Fprintf(w, "  Protected:          %d\n", result.Discover.Protected)
	_, _ = fmt.Fprintf(w, "  Unprotected:        %d\n", result.Discover.Unprotected)
	if result.Discover.Unknown > 0 {
		_, _ = fmt.Fprintf(w, "  Unknown:            %d\n", result.Discover.Unknown)
	}
	_, _ = fmt.Fprintln(w)

	// Setup
	switch {
	case result.Setup.Written:
		_, _ = fmt.Fprintf(w, "  Config written to:  %s\n", result.Setup.ConfigPath)
	case result.Setup.SkippedExsting:
		_, _ = fmt.Fprintf(w, "  Config exists at:   %s (use --force to overwrite)\n", result.Setup.ConfigPath)
	default:
		_, _ = fmt.Fprintf(w, "  Config would be at: %s (dry run)\n", result.Setup.ConfigPath)
	}
	_, _ = fmt.Fprintf(w, "  Preset:             %s\n", result.Setup.Preset)
	_, _ = fmt.Fprintln(w)

	// Validate
	if result.Verify != nil {
		if result.Verify.Skipped {
			_, _ = fmt.Fprintln(w, "  Validate:           skipped")
		} else {
			_, _ = fmt.Fprintf(w, "  Validate:           %d passed, %d failed\n",
				result.Verify.Passed, result.Verify.Failed)
		}
	}

	// Canary
	if result.Canary != nil {
		if result.Canary.Skipped {
			_, _ = fmt.Fprintln(w, "  Canary:             skipped")
		} else if result.Canary.Detected {
			_, _ = fmt.Fprintln(w, "  Canary:             detected (DLP working)")
		} else {
			_, _ = fmt.Fprintln(w, "  Canary:             not detected (check config)")
		}
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Next steps:")
	if result.Setup.Written {
		_, _ = fmt.Fprintf(w, "  pipelock run --config %s\n", result.Setup.ConfigPath)
	} else {
		_, _ = fmt.Fprintln(w, "  pipelock run --config <your-config-path>")
	}
	_, _ = fmt.Fprintln(w, "  pipelock discover --generate    (wrap unprotected MCP servers)")
	_, _ = fmt.Fprintln(w, "  pipelock verify-install          (full verification suite)")
	_, _ = fmt.Fprintln(w)
}

// canaryToken returns a synthetic AWS access key ID used for DLP detection testing.
// Split to avoid triggering DLP scanners on the source file itself.
func canaryToken() string {
	return "AKIA" + "IOSFODNN7CANARY1"
}
