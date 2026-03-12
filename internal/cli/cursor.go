// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/spf13/cobra"
)

// maxStdinBytes is the maximum stdin payload size for the hook command.
// Read cap+1 bytes so we can distinguish "exactly at cap" from "over cap".
const maxStdinBytes = 10 << 20 // 10 MB

// cursorResponse is the JSON format Cursor expects on stdout.
type cursorResponse struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// cursorHookPayload holds the common fields plus all event-specific fields
// from Cursor hook stdin. Only fields relevant to the event type are populated.
type cursorHookPayload struct {
	HookEventName  string `json:"hook_event_name"`
	ConversationID string `json:"conversation_id"`
	GenerationID   string `json:"generation_id"`

	// beforeShellExecution
	Command string `json:"command"`
	CWD     string `json:"cwd"`

	// beforeMCPExecution
	Server    string `json:"server"`
	ToolName  string `json:"tool_name"`
	ToolInput string `json:"tool_input"`

	// beforeReadFile
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

// hooksJSON represents Cursor's hooks.json file structure (version 1).
// Hooks is keyed by event name, each mapping to an array of hook entries.
type hooksJSON struct {
	Version int                    `json:"version"`
	Hooks   map[string][]hookEntry `json:"hooks"`
}

// hookEntry represents a single hook script in hooks.json.
type hookEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
}

// legacyHooksJSON represents the pre-v0.3.4 hooks.json format where hooks
// was a flat array with an "event" field per entry.
type legacyHooksJSON struct {
	Hooks []legacyHookEntry `json:"hooks"`
}

type legacyHookEntry struct {
	Event   string   `json:"event"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout"`
}

// parseHooksJSON parses hooks.json data, supporting both the current v1 format
// (hooks as a map keyed by event name) and the legacy pre-v0.3.4 format
// (hooks as a flat array with an "event" field per entry).
func parseHooksJSON(data []byte) (*hooksJSON, error) {
	var hooks hooksJSON
	if err := json.Unmarshal(data, &hooks); err == nil && (hooks.Hooks != nil || hooks.Version > 0) {
		if hooks.Version == 0 {
			hooks.Version = 1
		}
		if hooks.Hooks == nil {
			hooks.Hooks = make(map[string][]hookEntry)
		}
		return &hooks, nil
	}

	// Try legacy format (pre-v0.3.4: hooks as array with event field).
	var legacy legacyHooksJSON
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("unrecognized hooks.json format: %w", err)
	}

	result := &hooksJSON{
		Version: 1,
		Hooks:   make(map[string][]hookEntry),
	}
	for _, le := range legacy.Hooks {
		if le.Event != "" {
			result.Hooks[le.Event] = append(result.Hooks[le.Event], hookEntry{
				Command: le.Command,
				Args:    le.Args,
				Timeout: le.Timeout,
			})
		}
	}
	return result, nil
}

func cursorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cursor",
		Short: "Cursor IDE integration",
		Long: `Commands for integrating pipelock with Cursor IDE hooks.

The hook subcommand is called by Cursor before agent actions (shell commands,
MCP tool calls, file reads) and returns allow/deny decisions.

The install subcommand writes hooks.json to register pipelock with Cursor.`,
	}

	cmd.AddCommand(
		cursorHookCmd(),
		cursorInstallCmd(),
	)

	return cmd
}

func cursorHookCmd() *cobra.Command {
	var configFile string

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Evaluate a Cursor hook event from stdin",
		Long: `Reads a Cursor hook event as JSON from stdin and writes an allow/deny
decision as JSON to stdout.

Without --config, uses a security-focused default profile with tool policy
enabled (9 default rules including destructive delete, reverse shell, credential
file access, etc.) and MCP input scanning. This differs from pipelock's base
defaults which have tool policy disabled.

With --config, respects all settings from the provided file, including explicit
"enabled: false" on any feature.

Always exits 0. The "permission" field in the JSON response is the authoritative
decision. Diagnostics go to stderr only.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCursorHook(cmd, configFile)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file")

	return cmd
}

// runCursorHook is the core hook logic, separated for testability.
// It guarantees valid JSON on stdout and exit 0 in all paths.
func runCursorHook(cmd *cobra.Command, configFile string) error {
	stdout := cmd.OutOrStdout()

	// Panic recovery: always produce valid deny JSON.
	defer func() {
		if r := recover(); r != nil {
			writeResponse(stdout, cursorResponse{
				Permission:  decisionDeny,
				UserMessage: "pipelock: internal error",
			})
		}
	}()

	// Read stdin with size cap.
	reader := io.LimitReader(cmd.InOrStdin(), maxStdinBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		writeResponse(stdout, cursorResponse{
			Permission:  decisionDeny,
			UserMessage: "pipelock: failed to read stdin",
		})
		return nil //nolint:nilerr // always exit 0
	}

	if len(data) > maxStdinBytes {
		writeResponse(stdout, cursorResponse{
			Permission:  decisionDeny,
			UserMessage: "pipelock: input too large",
		})
		return nil
	}

	// Parse the hook payload.
	var payload cursorHookPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		writeResponse(stdout, cursorResponse{
			Permission:  decisionDeny,
			UserMessage: "pipelock: invalid JSON input",
		})
		return nil
	}

	// Load or build config.
	cfg, err := loadCursorConfig(configFile)
	if err != nil {
		writeResponse(stdout, cursorResponse{
			Permission:  decisionDeny,
			UserMessage: "pipelock: config error: " + err.Error(),
		})
		return nil
	}

	// Build scanner and policy.
	sc := scanner.New(cfg)
	pc := policy.New(cfg.MCPToolPolicy)

	// Build action from payload.
	action := payloadToAction(payload)

	// Decide.
	decision := decide.Decide(cmd.Context(), cfg, sc, pc, action)

	// Map to Cursor response.
	resp := cursorResponse{
		Permission:   string(decision.Outcome),
		UserMessage:  decision.UserMessage,
		AgentMessage: decision.AgentMessage,
	}

	writeResponse(stdout, resp)
	return nil
}

// loadCursorConfig builds a config for the hook. With --config, loads the file
// and respects operator intent. Without --config, builds cursor-specific
// defaults with tool policy enabled.
func loadCursorConfig(configFile string) (*config.Config, error) {
	var cfg *config.Config

	if configFile != "" {
		var err error
		cfg, err = config.Load(configFile)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", configFile, err)
		}
	} else {
		cfg = config.Defaults()

		// Enable tool policy with default rules for out-of-the-box protection.
		cfg.MCPToolPolicy = config.MCPToolPolicy{
			Enabled: true,
			Action:  config.ActionBlock,
			Rules:   policy.DefaultToolPolicyRules(),
		}

		// Enable MCP input scanning.
		cfg.MCPInputScanning.Enabled = true
		cfg.MCPInputScanning.Action = config.ActionBlock

		// Enable response scanning for injection detection.
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.Action = config.ActionBlock
	}

	cfg.ApplyDefaults()

	// Hook-specific overrides applied AFTER ApplyDefaults, which would
	// repopulate Internal with default CIDRs if it were nil beforehand.
	cfg.Internal = nil      // No DNS needed, skip SSRF checks.
	cfg.DLP.ScanEnv = false // Hook process env != agent env.

	return cfg, nil
}

// payloadToAction converts a Cursor hook payload to a decide.Action.
func payloadToAction(p cursorHookPayload) decide.Action {
	action := decide.Action{
		Source: "cursor",
		Kind:   decide.EventKind(p.HookEventName),
	}

	switch decide.EventKind(p.HookEventName) {
	case decide.EventShellExecution:
		action.Shell = &decide.ShellPayload{
			Command: p.Command,
			CWD:     p.CWD,
		}
	case decide.EventMCPExecution:
		action.MCP = &decide.MCPPayload{
			Server:    p.Server,
			ToolName:  p.ToolName,
			ToolInput: p.ToolInput,
			Command:   p.Command,
		}
	case decide.EventReadFile:
		action.File = &decide.FilePayload{
			FilePath: p.FilePath,
			Content:  p.Content,
		}
	}

	return action
}

// writeResponse marshals a cursorResponse to JSON and writes it to w.
// On marshal failure, writes a hardcoded deny response.
func writeResponse(w io.Writer, resp cursorResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		// Hardcoded fallback: if we can't even marshal, write raw JSON.
		_, _ = io.WriteString(w, `{"permission":"deny","user_message":"pipelock: marshal error"}`)
		_, _ = io.WriteString(w, "\n")
		return
	}
	_, _ = w.Write(data)
	_, _ = io.WriteString(w, "\n")
}

func cursorInstallCmd() *cobra.Command {
	var (
		global  bool
		project bool
		dryRun  bool
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install pipelock hooks into Cursor",
		Long: `Writes hooks.json to register pipelock as a Cursor hook for all
security-relevant events (shell execution, MCP tool calls, file reads).

By default writes to ~/.cursor/hooks.json (user-level). Use --project to
write to .cursor/hooks.json in the current directory (project-level).

If hooks.json already exists, pipelock entries are merged in without
overwriting other hooks. A .bak backup is created before modification.
Runs are idempotent: running twice produces the same result.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCursorInstall(cmd, global, project, dryRun)
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "install to ~/.cursor/hooks.json (default when no scope flag given)")
	cmd.Flags().BoolVar(&project, "project", false, "install to .cursor/hooks.json in current directory")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")

	return cmd
}

func runCursorInstall(cmd *cobra.Command, global, project, dryRun bool) error {
	if global && project {
		return fmt.Errorf("--global and --project are mutually exclusive")
	}

	// Determine target path. When neither flag is set, defaults to global.
	var targetDir string
	if project {
		targetDir = filepath.Join(".", ".cursor")
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("finding home directory: %w", err)
		}
		targetDir = filepath.Join(home, ".cursor")
	}

	targetPath := filepath.Join(targetDir, "hooks.json")

	// Find pipelock binary path.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding pipelock binary: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolving pipelock binary path: %w", err)
	}

	// Build the hook entries.
	newEntries := buildHookEntries(exe)

	// Load existing hooks.json if present.
	existing := &hooksJSON{Version: 1, Hooks: make(map[string][]hookEntry)}
	existingData, readErr := os.ReadFile(filepath.Clean(targetPath))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("reading existing %s: %w", targetPath, readErr)
	}
	if readErr == nil {
		// File exists: parse it (supports both current and legacy formats).
		parsed, err := parseHooksJSON(existingData)
		if err != nil {
			return fmt.Errorf("parsing existing %s: %w", targetPath, err)
		}
		existing = parsed
	}

	// Merge: add new entries that don't already exist.
	merged := mergeHooks(existing, newEntries)

	// Marshal the result.
	output, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling hooks.json: %w", err)
	}
	output = append(output, '\n')

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s:\n%s", targetPath, output)
		return nil
	}

	// Create directory if needed.
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("creating directory %s: %w", targetDir, err)
	}

	// Backup existing file.
	if readErr == nil {
		backupPath := targetPath + ".bak"
		if err := os.WriteFile(backupPath, existingData, 0o600); err != nil {
			return fmt.Errorf("creating backup %s: %w", backupPath, err)
		}
	}

	// Atomic write: temp file + rename.
	tmpFile, err := os.CreateTemp(targetDir, "hooks-*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(output); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("setting permissions: %w", err)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming temp file to %s: %w", targetPath, err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Installed pipelock hooks to %s\n", targetPath)
	return nil
}

// cursorHookTimeout is the default timeout (seconds) for pipelock hook entries.
const cursorHookTimeout = 10

// buildHookEntries creates the 3 hook entries for pipelock, keyed by event name.
func buildHookEntries(exe string) map[string][]hookEntry {
	events := []string{
		"beforeShellExecution",
		"beforeMCPExecution",
		"beforeReadFile",
	}

	quoted := shellQuote(exe)
	result := make(map[string][]hookEntry, len(events))
	for _, event := range events {
		result[event] = []hookEntry{{
			Command: quoted + " cursor hook",
			Timeout: cursorHookTimeout,
		}}
	}
	return result
}

// shellQuote wraps a string in single quotes if it contains characters
// that would be split or interpreted by a POSIX shell. Embedded single
// quotes are escaped with the '\” idiom.
func shellQuote(s string) string {
	safe := true
	for _, c := range s {
		if !isShellSafe(c) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isShellSafe(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '/' || c == '.' ||
		c == '_' || c == '-' || c == '+'
}

// mergeHooks adds new pipelock entries to existing hooks. If a pipelock
// entry already exists for an event, it is replaced with the new entry so
// that binary path changes and timeout updates take effect. Non-pipelock
// hooks are preserved. Extra stale pipelock entries for the same event are
// dropped (deduplication).
func mergeHooks(existing *hooksJSON, newEntries map[string][]hookEntry) *hooksJSON {
	// Preserve existing version if higher than 1 (future-proof).
	version := existing.Version
	if version < 1 {
		version = 1
	}
	result := &hooksJSON{
		Version: version,
		Hooks:   make(map[string][]hookEntry),
	}

	// Preserve existing non-pipelock hooks per event.
	for event, entries := range existing.Hooks {
		for _, h := range entries {
			if !isPipelockHook(h) {
				result.Hooks[event] = append(result.Hooks[event], h)
			}
		}
	}

	// Add new pipelock entries (replaces any old pipelock entries).
	for event, entries := range newEntries {
		result.Hooks[event] = append(result.Hooks[event], entries...)
	}

	return result
}

// isPipelockHook returns true if a hook entry is a pipelock cursor hook.
// The command always ends with "cursor hook" because buildHookEntries
// constructs it as `<binary> cursor hook`.
func isPipelockHook(h hookEntry) bool {
	return strings.HasSuffix(strings.TrimSpace(h.Command), "cursor hook")
}
