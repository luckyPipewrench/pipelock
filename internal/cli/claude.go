package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/spf13/cobra"
)

const (
	decisionAllow = "allow"
	decisionDeny  = "deny"
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
func runClaudeHook(cmd *cobra.Command, configFile string, exitCodeMode bool) error {
	stdout := cmd.OutOrStdout()

	// Panic recovery: always produce valid deny JSON.
	defer func() {
		if r := recover(); r != nil {
			writeClaudeResponse(stdout, claudeCodeFullResponse{
				HookSpecificOutput: claudeCodeHookOutput{
					HookEventName:            "PreToolUse",
					PermissionDecision:       decisionDeny,
					PermissionDecisionReason: "pipelock: internal error",
				},
			})
		}
	}()

	// Read stdin with size cap (reuses maxStdinBytes from cursor.go).
	reader := io.LimitReader(cmd.InOrStdin(), maxStdinBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil || len(data) == 0 {
		return claudeResult(cmd, exitCodeMode, "PreToolUse", decisionDeny, "pipelock: failed to read stdin")
	}

	if len(data) > maxStdinBytes {
		return claudeResult(cmd, exitCodeMode, "PreToolUse", decisionDeny, "pipelock: input too large")
	}

	// Parse the hook payload.
	var payload claudeCodePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return claudeResult(cmd, exitCodeMode, "PreToolUse", decisionDeny, "pipelock: invalid JSON input")
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
