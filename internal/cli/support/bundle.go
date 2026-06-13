// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package support implements the `pipelock support bundle` command, which
// collects secret-redacted diagnostics for issue filing.
package support

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	defaultOutputDir = "."
	maxAuditLogLines = 200
	// maxAuditLogLineBytes caps a single scanned log line (1 MiB) so a long
	// line does not trip bufio.Scanner's 64KB default and drop the whole tail.
	maxAuditLogLineBytes = 1 << 20
	bundleFileMode       = 0o600
	bundleDirMode        = 0o750
	redactedSentinel     = "<redacted>"
)

// BundleCmd returns the `support bundle` subcommand.
func BundleCmd() *cobra.Command {
	var configFile string
	var outputPath string
	var jsonManifest bool
	var noLogs bool

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Collect a secret-redacted diagnostics archive for issue filing",
		Long: `Collect diagnostics into a .tar.gz archive that can be attached when
filing a bug report or support issue.

Secret handling before inclusion:
  - License tokens, bearer tokens, API keys → <redacted>
  - Private key material (CA key, signing keys) → presence noted only
  - Environment variable values → names only, never values
  - Webhook URLs → userinfo and token query params → <redacted>
  - Audit-log lines with remaining secret-shaped content → <redacted>

The archive contains:
  - pipelock version and build metadata
  - OS, architecture, and Go runtime version
  - Effective config path and a sanitised config summary
  - Scanner/feature enable flags
  - A redacted tail of the audit log (if configured and readable)
  - Names of pipelock-relevant environment variables (values never included)

Examples:
  pipelock support bundle
  pipelock support bundle --config pipelock.yaml
  pipelock support bundle --output /tmp/pl-diag.tar.gz
  pipelock support bundle --config pipelock.yaml --no-logs
  pipelock support bundle --json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBundle(cmd, configFile, outputPath, jsonManifest, !noLogs)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file to include in bundle (default: built-in defaults)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "output path for the .tar.gz archive (default: ./pipelock-support-<timestamp>.tar.gz)")
	cmd.Flags().BoolVar(&jsonManifest, "json", false, "also write a manifest.json alongside the archive")
	cmd.Flags().BoolVar(&noLogs, "no-logs", false, "omit audit-log-tail.txt even when logging.file is configured")

	return cmd
}

// Cmd returns the top-level `support` command with subcommands wired in.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "support",
		Short: "Operator support utilities",
		Long:  `Utilities for collecting diagnostics and troubleshooting Pipelock deployments.`,
	}
	cmd.AddCommand(BundleCmd())
	return cmd
}

// manifest is the structured summary written to manifest.json inside the bundle.
type manifest struct {
	BundleVersion   int      `json:"bundle_version"`
	GeneratedAt     string   `json:"generated_at"`
	PipelockVersion string   `json:"pipelock_version"`
	BuildDate       string   `json:"build_date"`
	GitCommit       string   `json:"git_commit"`
	GoVersion       string   `json:"go_version"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	ConfigFile      string   `json:"config_file"`
	Config          any      `json:"config"`
	EnvVarNames     []string `json:"env_var_names"`
	Files           []string `json:"files"`
}

func runBundle(cmd *cobra.Command, configFile, outputPath string, writeJSON bool, includeLogs bool) error {
	ts := time.Now().UTC()
	archiveName := fmt.Sprintf("pipelock-support-%s.tar.gz", ts.Format("20060102-150405"))
	if outputPath == "" {
		outputPath = filepath.Join(defaultOutputDir, archiveName)
	}

	// Load config (or defaults).
	var cfg *config.Config
	cfgLabel := "defaults"
	if configFile != "" {
		var err error
		cfg, err = config.Load(configFile)
		if err != nil {
			return fmt.Errorf("config load error: %w", err)
		}
		cfgLabel = configFile
	} else {
		cfg = config.Defaults()
	}

	// Collect the bundle entries.
	entries, err := collectEntries(cfg, cfgLabel, includeLogs)
	if err != nil {
		return fmt.Errorf("collecting bundle entries: %w", err)
	}

	// Build the manifest.
	m := manifest{
		BundleVersion:   1,
		GeneratedAt:     ts.Format(time.RFC3339),
		PipelockVersion: cliutil.Version,
		BuildDate:       cliutil.BuildDate,
		GitCommit:       cliutil.GitCommit,
		GoVersion:       runtime.Version(),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		ConfigFile:      cfgLabel,
		Config:          redactConfig(cfg),
		EnvVarNames:     collectEnvVarNames(),
		Files:           entryNames(entries),
	}

	// Write the .tar.gz archive.
	if err := writeArchive(outputPath, m, entries); err != nil {
		return fmt.Errorf("writing archive: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Support bundle written to: %s\n", outputPath)

	// Optionally write a companion manifest.json.
	if writeJSON {
		manifestPath := strings.TrimSuffix(outputPath, ".tar.gz") + "-manifest.json"
		if err := writeManifestJSON(manifestPath, m); err != nil {
			return fmt.Errorf("writing manifest JSON: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Manifest written to:       %s\n", manifestPath)
	}

	return nil
}

// bundleEntry is a named in-memory file to pack into the archive.
type bundleEntry struct {
	name string
	data []byte
}

// collectEntries assembles all bundle content.
func collectEntries(cfg *config.Config, cfgLabel string, includeLogs bool) ([]bundleEntry, error) {
	var entries []bundleEntry

	// version.txt
	entries = append(entries, bundleEntry{
		name: "version.txt",
		data: []byte(buildVersionText()),
	})

	// config-summary.json — redacted config snapshot.
	cfgJSON, err := marshalIndent(redactConfig(cfg))
	if err != nil {
		return nil, fmt.Errorf("marshalling config summary: %w", err)
	}
	entries = append(entries, bundleEntry{
		name: "config-summary.json",
		data: cfgJSON,
	})

	// scanners.json — enabled scanner flags.
	scanJSON, err := marshalIndent(buildScannerSummary(cfg))
	if err != nil {
		return nil, fmt.Errorf("marshalling scanner summary: %w", err)
	}
	entries = append(entries, bundleEntry{
		name: "scanners.json",
		data: scanJSON,
	})

	// env-var-names.txt — names only, never values.
	entries = append(entries, bundleEntry{
		name: "env-var-names.txt",
		data: []byte(strings.Join(collectEnvVarNames(), "\n") + "\n"),
	})

	// audit-log-tail.txt — last N lines of the audit log if present.
	if includeLogs {
		logTail := readAuditLogTail(cfg, maxAuditLogLines)
		if len(logTail) > 0 {
			redacted := redactLogLines(cfg, logTail)
			entries = append(entries, bundleEntry{
				name: "audit-log-tail.txt",
				data: []byte(strings.Join(redacted, "\n") + "\n"),
			})
		}
	}

	// config-path.txt — the effective config path label.
	entries = append(entries, bundleEntry{
		name: "config-path.txt",
		data: []byte(cfgLabel + "\n"),
	})

	return entries, nil
}

func buildVersionText() string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "pipelock version: %s\n", cliutil.Version)
	_, _ = fmt.Fprintf(&b, "build date:       %s\n", cliutil.BuildDate)
	_, _ = fmt.Fprintf(&b, "git commit:       %s\n", cliutil.GitCommit)
	_, _ = fmt.Fprintf(&b, "go version:       %s\n", runtime.Version())
	_, _ = fmt.Fprintf(&b, "os/arch:          %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return b.String()
}

func buildScannerSummary(cfg *config.Config) map[string]any {
	return map[string]any{
		"mode":                 cfg.Mode,
		"response_scanning":    cfg.ResponseScanning.Enabled,
		"mcp_input_scanning":   cfg.MCPInputScanning.Enabled,
		"mcp_tool_scanning":    cfg.MCPToolScanning.Enabled,
		"mcp_tool_policy":      cfg.MCPToolPolicy.Enabled,
		"mcp_session_binding":  cfg.MCPSessionBinding.Enabled,
		"tool_chain_detection": cfg.ToolChainDetection.Enabled,
		"adaptive_enforcement": cfg.AdaptiveEnforcement.Enabled,
		"tls_interception":     cfg.TLSInterception.Enabled,
		"sandbox":              cfg.Sandbox.Enabled,
		"flight_recorder":      cfg.FlightRecorder.Enabled,
		"dlp_patterns":         len(cfg.DLP.Patterns),
		"dlp_include_defaults": cfg.DLP.IncludeDefaults,
		"dlp_scan_env":         cfg.DLP.ScanEnv,
		"api_allowlist_count":  len(cfg.APIAllowlist),
		"blocklist_count":      len(cfg.FetchProxy.Monitoring.Blocklist),
	}
}

// collectEnvVarNames returns the names of pipelock-relevant environment
// variables that are present in the process environment.
// Values are NEVER included.
func collectEnvVarNames() []string {
	prefixes := []string{
		"PIPELOCK_",
		"HTTPS_PROXY",
		"HTTP_PROXY",
		"NO_PROXY",
		"SENTRY_",
	}
	var names []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) < 1 {
			continue
		}
		name := parts[0]
		for _, prefix := range prefixes {
			if strings.HasPrefix(strings.ToUpper(name), prefix) {
				names = append(names, name)
				break
			}
		}
	}
	return names
}

// readAuditLogTail reads the last n lines of the configured audit log file.
// Returns nil if the log is not configured or not readable.
func readAuditLogTail(cfg *config.Config, n int) []string {
	logFile := cfg.Logging.File
	if logFile == "" {
		return nil
	}
	f, err := os.Open(filepath.Clean(logFile)) // #nosec G304 -- operator-configured log path from local config (same pattern as diag/doctor.go)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	// Bounded line buffer so long JSON log lines don't trip the 64KB Scanner
	// default (which would otherwise drop the whole tail). Keep only the last n
	// lines in a ring so memory stays bounded regardless of file size.
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxAuditLogLineBytes)
	var ring []string
	for sc.Scan() {
		if n > 0 && len(ring) == n {
			ring = ring[1:]
		}
		ring = append(ring, sc.Text())
	}
	// On a read error (including an over-long line) return what we collected
	// rather than silently dropping the entire tail.
	return ring
}

// redactLogLines redacts configured/env/file secret literals, then DLP-scans
// each remaining line. Any line still carrying secret-shaped content is replaced
// wholesale; support diagnostics can lose one line, but must not leak a secret.
func redactLogLines(cfg *config.Config, lines []string) []string {
	sc := scanner.New(cfg)
	secrets := sc.RedactionSecretValues()
	all := make([]string, 0, len(secrets.Env)+len(secrets.File))
	all = append(all, secrets.Env...)
	all = append(all, secrets.File...)

	out := make([]string, len(lines))
	for i, line := range lines {
		redacted := line
		for _, s := range all {
			if s != "" && strings.Contains(redacted, s) {
				redacted = strings.ReplaceAll(redacted, s, redactedSentinel)
			}
		}
		dlp := sc.ScanTextForDLPQuiet(context.Background(), redacted)
		if len(dlp.Matches) > 0 || len(dlp.InformationalMatches) > 0 {
			redacted = redactedSentinel
		}
		out[i] = redacted
	}
	return out
}

func entryNames(entries []bundleEntry) []string {
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.name
	}
	return names
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// writeArchive creates a gzip-compressed tar archive at path containing a
// manifest header and all bundle entries.
func writeArchive(path string, m manifest, entries []bundleEntry) error {
	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(path), bundleDirMode); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, bundleFileMode) // #nosec G304 -- operator-supplied output path
	if err != nil {
		return fmt.Errorf("creating archive file: %w", err)
	}
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Write manifest.json as first entry.
	manifestBytes, err := marshalIndent(m)
	if err != nil {
		return fmt.Errorf("marshalling manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := tarWrite(tw, "manifest.json", manifestBytes); err != nil {
		return err
	}

	// Write each collected entry.
	for _, entry := range entries {
		if err := tarWrite(tw, entry.name, entry.data); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("closing tar writer: %w", err)
	}
	return gw.Close()
}

// tarWrite adds a single file to the tar archive.
func tarWrite(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    int64(bundleFileMode),
		Size:    int64(len(data)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("writing tar header for %s: %w", name, err)
	}
	if _, err := io.Copy(tw, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("writing tar entry for %s: %w", name, err)
	}
	return nil
}

// writeManifestJSON writes a standalone manifest.json next to the archive.
func writeManifestJSON(path string, m manifest) error {
	data, err := marshalIndent(m)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(filepath.Clean(path), data, bundleFileMode)
}
