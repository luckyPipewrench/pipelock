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

	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/spf13/cobra"
)

const (
	decisionAllow = "allow"
	decisionDeny  = "deny"

	// claudeHookEventPreToolUse is the hook event name for pre-tool-use hooks.
	claudeHookEventPreToolUse = "PreToolUse"
)

// claudeCodePayload is the JSON structure Claude Code sends on stdin.
type claudeCodePayload struct {
	SessionID     string          `json:"session_id"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolUseID     string          `json:"tool_use_id"`
}

// Tool-specific input structs parsed from tool_input.

type bashToolInput struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

type webFetchToolInput struct {
	URL string `json:"url"`
}

type writeToolInput struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

type editToolInput struct {
	FilePath  string `json:"file_path"`
	OldString string `json:"old_string"`
	NewString string `json:"new_string"`
}

// claudeCodeHookOutput is the hook-specific output for Claude Code.
type claudeCodeHookOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// claudeCodeFullResponse is the complete JSON response to Claude Code.
type claudeCodeFullResponse struct {
	HookSpecificOutput claudeCodeHookOutput `json:"hookSpecificOutput"`
}

func claudeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "claude",
		Short: "Claude Code integration",
		Long: `Commands for integrating pipelock with Claude Code hooks.

The hook subcommand is called by Claude Code before agent actions and returns
allow/deny decisions via structured JSON.

The setup subcommand writes hooks to Claude Code's settings.json.
The remove subcommand removes pipelock hooks from settings.json.`,
	}

	cmd.AddCommand(
		claudeHookCmd(),
		claudeSetupCmd(),
		claudeRemoveCmd(),
	)

	return cmd
}

func claudeHookCmd() *cobra.Command {
	var (
		configFile string
		exitCode   bool
	)

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Evaluate a Claude Code hook event from stdin",
		Long: `Reads a Claude Code hook event as JSON from stdin and writes an allow/deny
decision as JSON to stdout.

Without --config, uses a security-focused default profile with tool policy
enabled and MCP input scanning. With --config, respects all settings from
the provided file.

By default, always exits 0 and writes structured JSON with permissionDecision.
With --exit-code, exits 0 for allow and 2 for deny (reason on stderr).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClaudeHook(cmd, configFile, exitCode)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file")
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "use exit code 2 for deny instead of structured JSON")

	return cmd
}

// runClaudeHook is the core hook logic for Claude Code.
// In default mode, it guarantees valid JSON on stdout and exit 0 in all paths.
// In exit-code mode, it exits 0 for allow and returns ExitCodeError(2) for deny.
func runClaudeHook(cmd *cobra.Command, configFile string, exitCodeMode bool) (retErr error) {
	stdout := cmd.OutOrStdout()

	// Panic recovery: fail-closed in both modes.
	defer func() {
		if r := recover(); r != nil {
			if exitCodeMode {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "pipelock: internal error")
				retErr = ExitCodeError(2, errors.New("internal error"))
			} else {
				writeClaudeResponse(stdout, claudeCodeFullResponse{
					HookSpecificOutput: claudeCodeHookOutput{
						HookEventName:            claudeHookEventPreToolUse,
						PermissionDecision:       decisionDeny,
						PermissionDecisionReason: "pipelock: internal error",
					},
				})
			}
		}
	}()

	// Read stdin with size cap (reuses maxStdinBytes from cursor.go).
	reader := io.LimitReader(cmd.InOrStdin(), maxStdinBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil || len(data) == 0 {
		return claudeResult(cmd, exitCodeMode, claudeHookEventPreToolUse, decisionDeny, "pipelock: failed to read stdin")
	}

	if len(data) > maxStdinBytes {
		return claudeResult(cmd, exitCodeMode, claudeHookEventPreToolUse, decisionDeny, "pipelock: input too large")
	}

	// Parse the hook payload.
	var payload claudeCodePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return claudeResult(cmd, exitCodeMode, claudeHookEventPreToolUse, decisionDeny, "pipelock: invalid JSON input")
	}

	// Load or build config (reuses cursor hook config defaults).
	cfg, err := loadCursorConfig(configFile)
	if err != nil {
		return claudeResult(cmd, exitCodeMode, payload.HookEventName, decisionDeny,
			"pipelock: config error: "+err.Error())
	}

	// Build scanner and policy.
	sc := scanner.New(cfg)
	pc := policy.New(cfg.MCPToolPolicy)

	// Route tool_name to decide.Action.
	action, err := claudePayloadToAction(payload)
	if err != nil {
		// Known tool with unparseable tool_input: fail-closed.
		return claudeResult(cmd, exitCodeMode, payload.HookEventName, decisionDeny,
			"pipelock: "+err.Error())
	}
	if action == nil {
		// Unknown tool: default allow.
		return claudeResult(cmd, exitCodeMode, payload.HookEventName, decisionAllow, "")
	}

	// Decide.
	decision := decide.Decide(cfg, sc, pc, *action)

	// Map outcome.
	perm := decisionAllow
	reason := decision.UserMessage
	if decision.Outcome == decide.Deny {
		perm = decisionDeny
	}

	return claudeResult(cmd, exitCodeMode, payload.HookEventName, perm, reason)
}

// claudeResult writes the response (JSON or exit code) based on mode.
func claudeResult(cmd *cobra.Command, exitCodeMode bool, hookEventName, permission, reason string) error {
	if exitCodeMode {
		if permission == decisionDeny {
			if reason != "" {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), reason)
			}
			return ExitCodeError(2, errors.New("action denied"))
		}
		return nil
	}

	writeClaudeResponse(cmd.OutOrStdout(), claudeCodeFullResponse{
		HookSpecificOutput: claudeCodeHookOutput{
			HookEventName:            hookEventName,
			PermissionDecision:       permission,
			PermissionDecisionReason: reason,
		},
	})
	return nil
}

// claudePayloadToAction routes a Claude Code tool_name to a decide.Action.
// Returns nil action for unknown tools (default allow).
// Returns error for known tools with unparseable tool_input (fail-closed).
func claudePayloadToAction(p claudeCodePayload) (*decide.Action, error) {
	action := decide.Action{Source: "claude-code"}

	switch {
	case p.ToolName == "Bash":
		var input bashToolInput
		if err := json.Unmarshal(p.ToolInput, &input); err != nil {
			return nil, fmt.Errorf("parsing Bash tool_input: %w", err)
		}
		action.Kind = decide.EventShellExecution
		action.Shell = &decide.ShellPayload{Command: input.Command}
		return &action, nil

	case p.ToolName == "WebFetch":
		var input webFetchToolInput
		if err := json.Unmarshal(p.ToolInput, &input); err != nil {
			return nil, fmt.Errorf("parsing WebFetch tool_input: %w", err)
		}
		action.Kind = decide.EventWebFetch
		action.WebFetch = &decide.WebFetchPayload{URL: input.URL}
		return &action, nil

	case p.ToolName == "Write":
		var input writeToolInput
		if err := json.Unmarshal(p.ToolInput, &input); err != nil {
			return nil, fmt.Errorf("parsing Write tool_input: %w", err)
		}
		action.Kind = decide.EventWriteFile
		action.Write = &decide.WritePayload{
			FilePath: input.FilePath,
			Content:  input.Content,
		}
		return &action, nil

	case p.ToolName == "Edit":
		var input editToolInput
		if err := json.Unmarshal(p.ToolInput, &input); err != nil {
			return nil, fmt.Errorf("parsing Edit tool_input: %w", err)
		}
		action.Kind = decide.EventWriteFile
		action.Write = &decide.WritePayload{
			FilePath:  input.FilePath,
			Content:   input.NewString,
			OldString: input.OldString,
		}
		return &action, nil

	case strings.HasPrefix(p.ToolName, "mcp__"):
		// MCP tool name format: mcp__<server>__<tool>
		parts := strings.SplitN(p.ToolName, "__", 3)
		server := ""
		toolName := p.ToolName
		if len(parts) >= 3 {
			server = parts[1]
			toolName = parts[2]
		}
		action.Kind = decide.EventMCPExecution
		action.MCP = &decide.MCPPayload{
			Server:    server,
			ToolName:  toolName,
			ToolInput: string(p.ToolInput),
		}
		return &action, nil

	default:
		// Unknown tool: return nil to signal default allow.
		return nil, nil //nolint:nilnil // nil,nil signals "unknown tool, allow by default"
	}
}

// writeClaudeResponse marshals the response to JSON and writes it to w.
// On marshal failure, writes a hardcoded deny response.
func writeClaudeResponse(w io.Writer, resp claudeCodeFullResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		// Hardcoded fallback: if we can't even marshal, write raw JSON.
		_, _ = io.WriteString(w, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"pipelock: marshal error"}}`)
		_, _ = io.WriteString(w, "\n")
		return
	}
	_, _ = w.Write(data)
	_, _ = io.WriteString(w, "\n")
}

// ---------------------------------------------------------------------------
// Settings.json types and merge/remove logic
// ---------------------------------------------------------------------------

// claudeSettings represents the hooks section of Claude Code's settings.json.
type claudeSettings struct {
	Hooks map[string][]claudeMatcherGroup `json:"hooks"`
}

// claudeMatcherGroup is one matcher + its hooks within a hook event.
type claudeMatcherGroup struct {
	Matcher string            `json:"matcher,omitempty"`
	Hooks   []claudeHookEntry `json:"hooks"`
}

// claudeHookEntry is a single hook within a matcher group.
type claudeHookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

// claudeHookTimeout is the default timeout (seconds) for pipelock hook entries.
const claudeHookTimeout = 10

// claudeBuiltinMatcher matches the built-in tools pipelock scans.
const claudeBuiltinMatcher = "Bash|WebFetch|Write|Edit"

// claudeMCPMatcher matches all MCP tool calls.
const claudeMCPMatcher = "mcp__.*"

// parseClaudeSettings parses the hooks section from settings.json data.
func parseClaudeSettings(data []byte) (*claudeSettings, error) {
	var settings claudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, err
	}
	if settings.Hooks == nil {
		settings.Hooks = make(map[string][]claudeMatcherGroup)
	}
	return &settings, nil
}

// isClaudePipelockHook returns true if a hook entry was installed by pipelock.
// The command always ends with "claude hook" because mergeClaudeHooks
// constructs it as `<binary> claude hook`. Mirrors cursor.go's HasSuffix
// detection pattern.
func isClaudePipelockHook(h claudeHookEntry) bool {
	return strings.HasSuffix(strings.TrimSpace(h.Command), "claude hook")
}

// mergeClaudeHooks removes existing pipelock hooks from PreToolUse and adds
// fresh ones. Non-pipelock hooks are preserved even if they share a matcher
// group with a pipelock hook. All other events are copied unchanged.
func mergeClaudeHooks(settings *claudeSettings, exe string) *claudeSettings {
	result := &claudeSettings{
		Hooks: make(map[string][]claudeMatcherGroup),
	}

	// Copy existing groups, filtering out pipelock hooks from PreToolUse.
	for event, groups := range settings.Hooks {
		for _, g := range groups {
			if event == claudeHookEventPreToolUse {
				// Filter individual hooks, keeping non-pipelock ones.
				var kept []claudeHookEntry
				for _, h := range g.Hooks {
					if !isClaudePipelockHook(h) {
						kept = append(kept, h)
					}
				}
				if len(kept) > 0 {
					result.Hooks[event] = append(result.Hooks[event], claudeMatcherGroup{
						Matcher: g.Matcher,
						Hooks:   kept,
					})
				}
				continue
			}
			result.Hooks[event] = append(result.Hooks[event], g)
		}
	}

	// Add fresh pipelock groups to PreToolUse.
	quoted := shellQuote(exe)
	hookCommand := quoted + " claude hook"

	result.Hooks[claudeHookEventPreToolUse] = append(result.Hooks[claudeHookEventPreToolUse],
		claudeMatcherGroup{
			Matcher: claudeBuiltinMatcher,
			Hooks: []claudeHookEntry{{
				Type:    "command",
				Command: hookCommand,
				Timeout: claudeHookTimeout,
			}},
		},
		claudeMatcherGroup{
			Matcher: claudeMCPMatcher,
			Hooks: []claudeHookEntry{{
				Type:    "command",
				Command: hookCommand,
				Timeout: claudeHookTimeout,
			}},
		},
	)

	return result
}

// removeClaudeHooks removes all pipelock hooks from all events.
// Non-pipelock hooks are preserved even if they share a matcher group.
func removeClaudeHooks(settings *claudeSettings) *claudeSettings {
	result := &claudeSettings{
		Hooks: make(map[string][]claudeMatcherGroup),
	}

	for event, groups := range settings.Hooks {
		for _, g := range groups {
			var kept []claudeHookEntry
			for _, h := range g.Hooks {
				if !isClaudePipelockHook(h) {
					kept = append(kept, h)
				}
			}
			if len(kept) > 0 {
				result.Hooks[event] = append(result.Hooks[event], claudeMatcherGroup{
					Matcher: g.Matcher,
					Hooks:   kept,
				})
			}
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Setup command
// ---------------------------------------------------------------------------

func claudeSetupCmd() *cobra.Command {
	var (
		global  bool
		project bool
		dryRun  bool
	)

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Install pipelock hooks into Claude Code",
		Long: `Writes hooks to Claude Code's settings.json to register pipelock as a
PreToolUse hook for security-relevant tools (Bash, WebFetch, Write, Edit,
and all MCP tools).

By default writes to ~/.claude/settings.json (user-level). Use --project
to write to .claude/settings.json in the current directory.

If settings.json already exists, pipelock entries are merged without
overwriting other hooks or settings. A .bak backup is created before
modification. Runs are idempotent: running twice produces the same result.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClaudeSetup(cmd, global, project, dryRun)
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "install to ~/.claude/settings.json (default)")
	cmd.Flags().BoolVar(&project, "project", false, "install to .claude/settings.json in current directory")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")

	return cmd
}

func runClaudeSetup(cmd *cobra.Command, global, project, dryRun bool) error {
	if global && project {
		return fmt.Errorf("--global and --project are mutually exclusive")
	}

	// Determine target path.
	targetDir, err := claudeSettingsDir(project)
	if err != nil {
		return err
	}
	targetPath := filepath.Join(targetDir, "settings.json")

	// Find pipelock binary path.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding pipelock binary: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolving pipelock binary path: %w", err)
	}

	// Read existing settings.json (raw bytes to preserve unknown fields).
	var rawData []byte
	existingData, readErr := os.ReadFile(filepath.Clean(targetPath))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("reading existing %s: %w", targetPath, readErr)
	}
	if readErr == nil {
		rawData = existingData
	}

	// Parse or create settings.
	settings, rawMap, err := parseClaudeSettingsRaw(rawData)
	if err != nil {
		return fmt.Errorf("parsing existing %s: %w", targetPath, err)
	}

	// Merge pipelock hooks.
	merged := mergeClaudeHooks(settings, exe)

	// Serialize with raw field preservation.
	output, err := marshalClaudeSettings(merged, rawMap)
	if err != nil {
		return fmt.Errorf("marshaling settings.json: %w", err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s:\n%s", targetPath, output)
		return nil
	}

	return writeClaudeSettingsFile(cmd, targetPath, targetDir, existingData, readErr, output)
}

// ---------------------------------------------------------------------------
// Remove command
// ---------------------------------------------------------------------------

func claudeRemoveCmd() *cobra.Command {
	var (
		global  bool
		project bool
		dryRun  bool
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove pipelock hooks from Claude Code",
		Long: `Removes all pipelock-managed hooks from Claude Code's settings.json.
Non-pipelock hooks and all other settings are preserved.

A .bak backup is created before modification.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runClaudeRemove(cmd, global, project, dryRun)
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "remove from ~/.claude/settings.json (default)")
	cmd.Flags().BoolVar(&project, "project", false, "remove from .claude/settings.json in current directory")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")

	return cmd
}

func runClaudeRemove(cmd *cobra.Command, global, project, dryRun bool) error {
	if global && project {
		return fmt.Errorf("--global and --project are mutually exclusive")
	}

	targetDir, err := claudeSettingsDir(project)
	if err != nil {
		return err
	}
	targetPath := filepath.Join(targetDir, "settings.json")

	// Read existing settings.json.
	existingData, readErr := os.ReadFile(filepath.Clean(targetPath))
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no settings.json found, nothing to remove")
			return nil
		}
		return fmt.Errorf("reading %s: %w", targetPath, readErr)
	}

	settings, rawMap, err := parseClaudeSettingsRaw(existingData)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", targetPath, err)
	}

	removed := removeClaudeHooks(settings)

	output, err := marshalClaudeSettings(removed, rawMap)
	if err != nil {
		return fmt.Errorf("marshaling settings.json: %w", err)
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s:\n%s", targetPath, output)
		return nil
	}

	return writeClaudeSettingsFile(cmd, targetPath, targetDir, existingData, readErr, output)
}

// ---------------------------------------------------------------------------
// Shared helpers for setup/remove
// ---------------------------------------------------------------------------

// claudeSettingsDir returns the directory for settings.json.
func claudeSettingsDir(project bool) (string, error) {
	if project {
		return filepath.Join(".", ".claude"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, ".claude"), nil
}

// parseClaudeSettingsRaw parses settings.json while preserving unknown fields
// via a raw JSON map. Returns the parsed hooks settings and the raw map for
// round-tripping. Handles nil/empty data as fresh settings.
func parseClaudeSettingsRaw(data []byte) (*claudeSettings, map[string]json.RawMessage, error) {
	rawMap := make(map[string]json.RawMessage)

	if len(data) == 0 {
		return &claudeSettings{Hooks: make(map[string][]claudeMatcherGroup)}, rawMap, nil
	}

	if err := json.Unmarshal(data, &rawMap); err != nil {
		return nil, nil, err
	}

	settings := &claudeSettings{Hooks: make(map[string][]claudeMatcherGroup)}
	if hooksRaw, ok := rawMap["hooks"]; ok {
		if err := json.Unmarshal(hooksRaw, &settings.Hooks); err != nil {
			return nil, nil, fmt.Errorf("parsing hooks section: %w", err)
		}
	}

	return settings, rawMap, nil
}

// marshalClaudeSettings serializes settings back to JSON, merging the hooks
// section into the raw map to preserve unknown fields.
func marshalClaudeSettings(settings *claudeSettings, rawMap map[string]json.RawMessage) ([]byte, error) {
	hooksJSON, err := json.Marshal(settings.Hooks)
	if err != nil {
		return nil, err
	}

	if rawMap == nil {
		rawMap = make(map[string]json.RawMessage)
	}
	rawMap["hooks"] = hooksJSON

	output, err := json.MarshalIndent(rawMap, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(output, '\n'), nil
}

// writeClaudeSettingsFile writes settings.json atomically with backup.
func writeClaudeSettingsFile(cmd *cobra.Command, targetPath, targetDir string, existingData []byte, readErr error, output []byte) error {
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

	// Atomic write: temp file + chmod + rename.
	tmpFile, err := os.CreateTemp(targetDir, "settings-*.json.tmp")
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

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrote pipelock hooks to %s\n", targetPath)
	return nil
}
