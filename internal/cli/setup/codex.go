// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// Codex MCP wrapping uses the same shape as VS Code: rewrite each server's
// command/args so traffic flows through `pipelock mcp proxy` before reaching
// the original server. Differences from vscode.go: Codex stores config in
// TOML (~/.codex/config.toml), so we shell out to `codex mcp list/add/remove`
// rather than parse the file directly. This avoids a TOML dependency and
// keeps us aligned with whatever schema Codex evolves to.

const (
	codexBinaryDefault  = "codex"
	pipelockBinaryName  = "pipelock"
	codexMCPProxy       = "proxy"
	codexMCP            = "mcp"
	codexArgSeparator   = "--"
	codexFlagConfig     = "--config"
	codexFlagEnv        = "--env"
	codexFlagUpstream   = "--upstream"
	codexTransportStdio = "stdio"

	codexActionWrapStdio       = "wrap-stdio"
	codexActionWrapURL         = "wrap-url"
	codexActionSkipWrapped     = "skip-already-wrapped"
	codexActionSkipUnsupported = "skip-unsupported"
	codexActionUnwrapStdio     = "unwrap-stdio"
	codexActionUnwrapURL       = "unwrap-url"
	codexActionSkipNotWrapped  = "skip-not-wrapped"
)

// codexMCPServer mirrors `codex mcp list --json` output.
type codexMCPServer struct {
	Name              string            `json:"name"`
	Enabled           *bool             `json:"enabled"`
	Transport         codexMCPTransport `json:"transport"`
	StartupTimeoutSec json.RawMessage   `json:"startup_timeout_sec,omitempty"`
	ToolTimeoutSec    json.RawMessage   `json:"tool_timeout_sec,omitempty"`
}

// codexMCPTransport is the per-server transport block. Codex emits both
// stdio (command/args/env) and streamable HTTP (url) shapes under this key
// distinguished by `type`.
type codexMCPTransport struct {
	Type              string            `json:"type"`
	Command           string            `json:"command,omitempty"`
	Args              []string          `json:"args,omitempty"`
	Env               map[string]string `json:"env,omitempty"`
	EnvVars           []string          `json:"env_vars,omitempty"`
	CWD               string            `json:"cwd,omitempty"`
	URL               string            `json:"url,omitempty"`
	BearerTokenEnvVar string            `json:"bearer_token_env_var,omitempty"`
	HTTPHeaders       json.RawMessage   `json:"http_headers,omitempty"`
	EnvHTTPHeaders    json.RawMessage   `json:"env_http_headers,omitempty"`
}

// CodexCmd returns the `pipelock codex` command tree.
func CodexCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "codex",
		Short: "Codex CLI integration",
		Long: `Wrap Codex CLI's MCP servers through pipelock so all tool traffic is scanned.

The install subcommand rewrites each registered MCP server in ~/.codex/config.toml
so its command becomes 'pipelock mcp proxy -- <original command>'. URL-based
streamable HTTP servers are converted to stdio with --upstream.

The remove subcommand restores wrapped servers by reading the original command
out of the wrapped args list. Servers that were not wrapped by pipelock are
left unchanged.

HTTP fetches from Codex itself (LLM API calls, the WebFetch tool) are routed
through pipelock when HTTPS_PROXY is set in the user's shell. Codex inherits
HTTP_PROXY/HTTPS_PROXY/NO_PROXY by default per its shell_environment_policy,
so no codex-side change is needed for those.`,
	}
	cmd.AddCommand(codexInstallCmd(), codexRemoveCmd())
	return cmd
}

func codexInstallCmd() *cobra.Command {
	var (
		dryRun     bool
		configFile string
		codexPath  string
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Wrap Codex MCP servers through pipelock",
		Long: `Iterates servers reported by 'codex mcp list --json' and wraps each one
through pipelock's MCP proxy. Already-wrapped servers are skipped (idempotent).
Streamable HTTP (URL) servers are converted to stdio with --upstream.

Use --dry-run to preview the changes without modifying the Codex config.
Use --config to point pipelock at a specific YAML config when wrapping.
Use --codex-path to override the codex binary location (default: PATH lookup).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCodexInstall(cmd, dryRun, configFile, codexPath)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without modifying Codex config")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "pipelock config path passed through to 'pipelock mcp proxy'")
	cmd.Flags().StringVar(&codexPath, "codex-path", "", "path to the codex binary (default: PATH lookup)")
	return cmd
}

func codexRemoveCmd() *cobra.Command {
	var (
		dryRun    bool
		codexPath string
	)
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Unwrap Codex MCP servers previously wrapped by pipelock",
		Long: `Reverses 'pipelock codex install'. For each server whose command points at
the running pipelock binary, the original command/args are recovered from the
wrapped args list and re-registered. Non-wrapped servers are left unchanged.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCodexRemove(cmd, dryRun, codexPath)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without modifying Codex config")
	cmd.Flags().StringVar(&codexPath, "codex-path", "", "path to the codex binary (default: PATH lookup)")
	return cmd
}

// resolveCodexBinary returns the codex binary path. Honors --codex-path if set,
// otherwise falls back to PATH lookup. Errors clearly if not found.
func resolveCodexBinary(override string) (string, error) {
	if override != "" {
		abs, err := filepath.Abs(override)
		if err != nil {
			return "", fmt.Errorf("resolving --codex-path: %w", err)
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("codex binary at %s: %w", abs, err)
		}
		return abs, nil
	}
	resolved, err := exec.LookPath(codexBinaryDefault)
	if err != nil {
		return "", fmt.Errorf("codex binary not found on PATH (install Codex CLI or pass --codex-path)")
	}
	return resolved, nil
}

// resolvePipelockBinary returns the running pipelock binary path with symlinks
// evaluated. Used so wrapped configs reference a stable absolute path.
func resolvePipelockBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("finding pipelock binary: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolving pipelock binary path: %w", err)
	}
	return resolved, nil
}

// codexMCPList shells out to `codex mcp list --json` and parses the result.
func codexMCPList(ctx context.Context, codexBin string) ([]codexMCPServer, error) {
	out, err := runCodexCommand(ctx, codexBin, "mcp", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("codex mcp list: %w", err)
	}
	return parseCodexMCPList(out)
}

// parseCodexMCPList separates parsing from the shell-out so tests can feed
// canned JSON without mocking exec.
func parseCodexMCPList(data []byte) ([]codexMCPServer, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}
	var servers []codexMCPServer
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("parsing codex mcp list JSON: %w", err)
	}
	return servers, nil
}

// isCodexWrapped reports whether a server's transport is already wrapped by
// pipelock. Detection keys on the args prefix ["mcp", "proxy"] AND a binary
// basename of "pipelock" (with optional suffix like "pipelock-dev"). This
// matches both the current pipelock binary and any prior pipelock binary at
// a different path — important so a rebuild at a new location does not
// double-wrap servers on the next install.
//
// The basename check guards against the unlikely case of a non-pipelock tool
// that also uses `mcp proxy` as its leading args. Operators who want to point
// the wrap at an alternate binary should `pipelock codex remove` first and
// then `pipelock codex install` from the new binary.
func isCodexWrapped(server codexMCPServer, _ string) bool {
	if server.Transport.Type != codexTransportStdio {
		return false
	}
	if !looksLikePipelockBinary(server.Transport.Command) {
		return false
	}
	if len(server.Transport.Args) < 2 {
		return false
	}
	return server.Transport.Args[0] == codexMCP && server.Transport.Args[1] == codexMCPProxy
}

// looksLikePipelockBinary reports whether the command path is plausibly a
// pipelock binary. Matches "pipelock", "pipelock.exe", and dev variants like
// "pipelock-dev". Path is matched on basename so it is location-independent.
func looksLikePipelockBinary(command string) bool {
	if command == "" {
		return false
	}
	base := filepath.Base(command)
	base = strings.TrimSuffix(base, ".exe")
	return base == pipelockBinaryName || strings.HasPrefix(base, pipelockBinaryName+"-")
}

func serverEnabled(server codexMCPServer) bool {
	return server.Enabled == nil || *server.Enabled
}

func rawJSONHasValue(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	switch string(trimmed) {
	case "null", "{}", "[]", `""`:
		return false
	default:
		return true
	}
}

func unsupportedCodexInstallReason(server codexMCPServer) string {
	if !serverEnabled(server) {
		return "server disabled"
	}
	if rawJSONHasValue(server.StartupTimeoutSec) || rawJSONHasValue(server.ToolTimeoutSec) {
		return "custom timeout settings cannot be preserved by codex mcp add"
	}
	if server.Transport.CWD != "" {
		return "cwd cannot be preserved by codex mcp add"
	}
	if len(server.Transport.EnvVars) > 0 {
		return "env_vars passthrough cannot be preserved by codex mcp add"
	}
	if hasUnsafeEnvKey(server.Transport.Env) {
		return "unsafe env key cannot be passed through safely"
	}
	if server.Transport.URL != "" && codexURLTransportHasAuthOrHeaders(server.Transport) {
		return "HTTP auth/header settings cannot be preserved by stdio --upstream wrapper"
	}
	return ""
}

func unsupportedCodexRemoveReason(server codexMCPServer) string {
	if !serverEnabled(server) {
		return "server disabled (codex mcp add re-adds as enabled, which would silently mutate state)"
	}
	if rawJSONHasValue(server.StartupTimeoutSec) || rawJSONHasValue(server.ToolTimeoutSec) {
		return "custom timeout settings cannot be preserved by codex mcp add"
	}
	if server.Transport.CWD != "" {
		return "cwd cannot be preserved by codex mcp add"
	}
	if len(server.Transport.EnvVars) > 0 {
		return "env_vars passthrough cannot be preserved by codex mcp add"
	}
	if hasUnsafeEnvKey(server.Transport.Env) {
		return "unsafe env key cannot be passed through safely"
	}
	return ""
}

func codexURLTransportHasAuthOrHeaders(transport codexMCPTransport) bool {
	return transport.BearerTokenEnvVar != "" ||
		rawJSONHasValue(transport.HTTPHeaders) ||
		rawJSONHasValue(transport.EnvHTTPHeaders)
}

func hasUnsafeEnvKey(env map[string]string) bool {
	for key := range env {
		if key == "" || strings.HasPrefix(key, "-") {
			return true
		}
	}
	return false
}

// wrapCodexArgs builds the args list for a stdio server wrapped through
// pipelock. The result is: ["mcp", "proxy", "--config", CFG?, "--env", K1, ...,
// "--", ORIG_CMD, ORIG_ARG_1, ...]. Pass-through env keys are included as
// `--env KEY` repeats so pipelock's mcp proxy forwards them to the wrapped
// subprocess (matching the `--env` flag pattern used in claude-peers/openclaw
// entries on Josh's machine).
func wrapCodexArgs(origCmd string, origArgs []string, env map[string]string, configFile string) []string {
	args := []string{codexMCP, codexMCPProxy}
	if configFile != "" {
		args = append(args, codexFlagConfig, configFile)
	}
	// Sort env keys so output is deterministic for tests and dry-run diffs.
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, codexFlagEnv, k)
	}
	args = append(args, codexArgSeparator)
	args = append(args, origCmd)
	args = append(args, origArgs...)
	return args
}

// wrapCodexURL builds the args list for an HTTP/SSE server wrapped through
// pipelock. Streamable-HTTP servers convert to stdio with --upstream pointing
// at the original URL.
func wrapCodexURL(url, configFile string) []string {
	args := []string{codexMCP, codexMCPProxy}
	if configFile != "" {
		args = append(args, codexFlagConfig, configFile)
	}
	args = append(args, codexFlagUpstream, url)
	return args
}

// unwrapCodexArgs reverses wrapCodexArgs / wrapCodexURL, returning the
// original command/args (or url, in the streamable-HTTP case) so the server
// can be re-registered with codex mcp add. Returns origURL non-empty for
// URL-shaped wraps, otherwise origCmd+origArgs are populated.
func unwrapCodexArgs(args []string) (origCmd string, origArgs []string, origURL string, err error) {
	if len(args) < 2 || args[0] != codexMCP || args[1] != codexMCPProxy {
		return "", nil, "", errors.New("not a pipelock-wrapped args list")
	}
	rest := args[2:]
	for len(rest) > 0 {
		switch rest[0] {
		case codexFlagConfig, codexFlagEnv:
			if len(rest) < 2 {
				return "", nil, "", fmt.Errorf("malformed wrap: trailing %s", rest[0])
			}
			rest = rest[2:]
		case codexFlagUpstream:
			if len(rest) < 2 {
				return "", nil, "", fmt.Errorf("malformed wrap: trailing %s", codexFlagUpstream)
			}
			return "", nil, rest[1], nil
		case codexArgSeparator:
			rest = rest[1:]
			if len(rest) == 0 {
				return "", nil, "", errors.New("malformed wrap: separator with no command")
			}
			return rest[0], append([]string(nil), rest[1:]...), "", nil
		default:
			return "", nil, "", fmt.Errorf("malformed wrap: unexpected token %q", rest[0])
		}
	}
	return "", nil, "", errors.New("malformed wrap: no command or upstream found")
}

// codexInstallPlan is the precomputed action list for a server (preview-able
// before any shell-out). One per input server.
type codexInstallPlan struct {
	Server   string
	Action   string // codexActionWrapStdio, codexActionWrapURL, codexActionSkipWrapped, codexActionSkipUnsupported
	Reason   string // human-readable detail; empty when not skipped
	NewCmd   string
	NewArgs  []string
	Env      map[string]string
	Original codexMCPTransport // pre-wrap state, used for rollback if `codex mcp add` fails
}

// planCodexInstall computes the wrap plan for each server. Pure function:
// no I/O, no exec.
func planCodexInstall(servers []codexMCPServer, pipelockBin, configFile string) []codexInstallPlan {
	plans := make([]codexInstallPlan, 0, len(servers))
	for _, s := range servers {
		unsupportedReason := unsupportedCodexInstallReason(s)
		switch {
		case isCodexWrapped(s, pipelockBin):
			plans = append(plans, codexInstallPlan{
				Server: s.Name,
				Action: codexActionSkipWrapped,
				Reason: "already routed through pipelock",
			})
		case unsupportedReason != "":
			plans = append(plans, codexInstallPlan{
				Server: s.Name,
				Action: codexActionSkipUnsupported,
				Reason: unsupportedReason,
			})
		case s.Transport.Type == codexTransportStdio && s.Transport.Command != "":
			plans = append(plans, codexInstallPlan{
				Server:   s.Name,
				Action:   codexActionWrapStdio,
				NewCmd:   pipelockBin,
				NewArgs:  wrapCodexArgs(s.Transport.Command, s.Transport.Args, s.Transport.Env, configFile),
				Env:      copyStringMap(s.Transport.Env),
				Original: s.Transport,
			})
		case s.Transport.URL != "":
			plans = append(plans, codexInstallPlan{
				Server:   s.Name,
				Action:   codexActionWrapURL,
				NewCmd:   pipelockBin,
				NewArgs:  wrapCodexURL(s.Transport.URL, configFile),
				Original: s.Transport,
			})
		default:
			plans = append(plans, codexInstallPlan{
				Server: s.Name,
				Action: codexActionSkipUnsupported,
				Reason: fmt.Sprintf("unsupported transport %q", s.Transport.Type),
			})
		}
	}
	return plans
}

// codexRemovePlan describes how to unwrap one server. Pure function output.
type codexRemovePlan struct {
	Server   string
	Action   string // codexActionUnwrapStdio, codexActionUnwrapURL, codexActionSkipNotWrapped
	Reason   string
	NewCmd   string
	NewArgs  []string
	NewURL   string
	Env      map[string]string
	Original codexMCPTransport // pre-unwrap (wrapped) state, used for rollback if `codex mcp add` fails
}

// planCodexRemove computes the unwrap plan for each server. Pure function.
func planCodexRemove(servers []codexMCPServer, pipelockBin string) ([]codexRemovePlan, error) {
	plans := make([]codexRemovePlan, 0, len(servers))
	for _, s := range servers {
		if !isCodexWrapped(s, pipelockBin) {
			plans = append(plans, codexRemovePlan{
				Server: s.Name,
				Action: codexActionSkipNotWrapped,
				Reason: "not wrapped by pipelock",
			})
			continue
		}
		if reason := unsupportedCodexRemoveReason(s); reason != "" {
			return nil, fmt.Errorf("unwrapping %q: %s; edit ~/.codex/config.toml manually", s.Name, reason)
		}
		origCmd, origArgs, origURL, err := unwrapCodexArgs(s.Transport.Args)
		if err != nil {
			return nil, fmt.Errorf("unwrapping %q: %w", s.Name, err)
		}
		switch {
		case origURL != "":
			plans = append(plans, codexRemovePlan{
				Server:   s.Name,
				Action:   codexActionUnwrapURL,
				NewURL:   origURL,
				Original: s.Transport,
			})
		default:
			plans = append(plans, codexRemovePlan{
				Server:   s.Name,
				Action:   codexActionUnwrapStdio,
				NewCmd:   origCmd,
				NewArgs:  origArgs,
				Env:      copyStringMap(s.Transport.Env),
				Original: s.Transport,
			})
		}
	}
	return plans, nil
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// runCodexInstall is the top-level handler for `pipelock codex install`.
func runCodexInstall(cmd *cobra.Command, dryRun bool, configFile, codexPathOverride string) error {
	codexBin, err := resolveCodexBinary(codexPathOverride)
	if err != nil {
		return err
	}
	pipelockBin, err := resolvePipelockBinary()
	if err != nil {
		return err
	}

	servers, err := codexMCPList(cmd.Context(), codexBin)
	if err != nil {
		return err
	}
	plans := planCodexInstall(servers, pipelockBin, configFile)

	wrapped, skipped := 0, 0
	for _, p := range plans {
		switch p.Action {
		case codexActionWrapStdio, codexActionWrapURL:
			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"would wrap %s (%s): codex mcp add %s%s -- %s %s\n",
					p.Server, p.Action, p.Server, formatEnvFlags(p.Env), strconv.Quote(p.NewCmd), joinArgs(p.NewArgs))
				wrapped++
				continue
			}
			if err := codexReplaceServer(cmd.Context(), codexBin, p.Server, p.NewCmd, p.NewArgs, p.Env, p.Original); err != nil {
				return fmt.Errorf("wrapping %q: %w", p.Server, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrapped %s\n", p.Server)
			wrapped++
		case codexActionSkipWrapped, codexActionSkipUnsupported:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "skip %s (%s)\n", p.Server, p.Reason)
			skipped++
		}
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Plan: %d to wrap, %d skipped (dry-run, no changes made)\n", wrapped, skipped)
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrapped %d server(s), skipped %d.\n", wrapped, skipped)
		if wrapped > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Restart Codex sessions to pick up the wrapped MCP servers.")
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Note: Codex's HTTP fetches (LLM calls, WebFetch) follow HTTPS_PROXY from your shell.")
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "      Run pipelock locally and export HTTPS_PROXY=http://127.0.0.1:8888 to scan those.")
		}
	}
	return nil
}

// runCodexRemove is the top-level handler for `pipelock codex remove`.
func runCodexRemove(cmd *cobra.Command, dryRun bool, codexPathOverride string) error {
	codexBin, err := resolveCodexBinary(codexPathOverride)
	if err != nil {
		return err
	}
	pipelockBin, err := resolvePipelockBinary()
	if err != nil {
		return err
	}

	servers, err := codexMCPList(cmd.Context(), codexBin)
	if err != nil {
		return err
	}
	plans, err := planCodexRemove(servers, pipelockBin)
	if err != nil {
		return err
	}

	unwrapped, skipped := 0, 0
	for _, p := range plans {
		switch p.Action {
		case codexActionUnwrapStdio:
			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"would unwrap %s: codex mcp add %s%s -- %s %s\n",
					p.Server, p.Server, formatEnvFlags(p.Env), strconv.Quote(p.NewCmd), joinArgs(p.NewArgs))
				unwrapped++
				continue
			}
			if err := codexReplaceServer(cmd.Context(), codexBin, p.Server, p.NewCmd, p.NewArgs, p.Env, p.Original); err != nil {
				return fmt.Errorf("unwrapping %q: %w", p.Server, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "unwrapped %s\n", p.Server)
			unwrapped++
		case codexActionUnwrapURL:
			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "would unwrap %s: codex mcp add %s --url %s\n", p.Server, p.Server, strconv.Quote(p.NewURL))
				unwrapped++
				continue
			}
			if err := codexReplaceURL(cmd.Context(), codexBin, p.Server, p.NewURL, p.Original); err != nil {
				return fmt.Errorf("unwrapping %q: %w", p.Server, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "unwrapped %s\n", p.Server)
			unwrapped++
		case codexActionSkipNotWrapped:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "skip %s (%s)\n", p.Server, p.Reason)
			skipped++
		}
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Plan: %d to unwrap, %d skipped (dry-run, no changes made)\n", unwrapped, skipped)
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unwrapped %d server(s), skipped %d.\n", unwrapped, skipped)
	}
	return nil
}

// codexReplaceServer is the stdio-server replace primitive: remove + add.
// Codex's `mcp add` rejects duplicates, so we always remove first. The remove
// is best-effort: a "not found" error is treated as success (idempotent).
//
// If the add step fails after the remove succeeded, the server is gone from
// Codex's config. We attempt to roll back by re-adding the original transport
// (captured before the remove call). The error returned distinguishes the
// rollback-succeeded case ("rolled back to original config") from the
// rollback-failed case ("rollback also failed; verify with codex mcp list").
func codexReplaceServer(ctx context.Context, codexBin, name, command string, args []string, env map[string]string, original codexMCPTransport) error {
	if err := codexMCPRemoveBestEffort(ctx, codexBin, name); err != nil {
		return err
	}
	if _, addErr := runCodexCommand(ctx, codexBin, buildCodexAddArgs(name, command, args, env)...); addErr != nil {
		if rbErr := rollbackCodexAdd(ctx, codexBin, name, original); rbErr != nil {
			return fmt.Errorf("codex mcp add %s failed and rollback also failed (server may be missing; verify with `codex mcp list`): %w", name, errors.Join(addErr, rbErr))
		}
		return fmt.Errorf("codex mcp add %s: %w (rolled back to original config)", name, addErr)
	}
	return nil
}

// codexReplaceURL is the URL-server replace primitive: remove + add --url.
// Same rollback semantics as codexReplaceServer.
func codexReplaceURL(ctx context.Context, codexBin, name, url string, original codexMCPTransport) error {
	if err := codexMCPRemoveBestEffort(ctx, codexBin, name); err != nil {
		return err
	}
	if _, addErr := runCodexCommand(ctx, codexBin, "mcp", "add", name, "--url", url); addErr != nil {
		if rbErr := rollbackCodexAdd(ctx, codexBin, name, original); rbErr != nil {
			return fmt.Errorf("codex mcp add %s --url failed and rollback also failed (server may be missing; verify with `codex mcp list`): %w", name, errors.Join(addErr, rbErr))
		}
		return fmt.Errorf("codex mcp add %s --url: %w (rolled back to original config)", name, addErr)
	}
	return nil
}

// buildCodexAddArgs assembles the argv for `codex mcp add NAME [--env K=V]... -- COMMAND ARGS...`.
// Extracted so codexReplaceServer and rollbackCodexAdd share one source of
// truth for the add shape.
func buildCodexAddArgs(name, command string, args []string, env map[string]string) []string {
	addArgs := []string{"mcp", "add"}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		addArgs = append(addArgs, "--env", k+"="+env[k])
	}
	addArgs = append(addArgs, name, "--", command)
	addArgs = append(addArgs, args...)
	return addArgs
}

// rollbackCodexAdd re-registers a server using the captured original transport
// so a failed wrap or unwrap does not leave the user's Codex config with a
// missing server. Returns the rollback error if the re-add itself fails.
func rollbackCodexAdd(ctx context.Context, codexBin, name string, original codexMCPTransport) error {
	if original.Type == codexTransportStdio || (original.Command != "" && original.URL == "") {
		_, err := runCodexCommand(ctx, codexBin, buildCodexAddArgs(name, original.Command, original.Args, original.Env)...)
		return err
	}
	if original.URL != "" {
		_, err := runCodexCommand(ctx, codexBin, "mcp", "add", name, "--url", original.URL)
		return err
	}
	return fmt.Errorf("captured original transport has neither command nor url (type=%q)", original.Type)
}

// codexMCPRemoveBestEffort removes a server, treating "not found" as success.
func codexMCPRemoveBestEffort(ctx context.Context, codexBin, name string) error {
	out, err := runCodexCommand(ctx, codexBin, "mcp", "remove", name)
	if err == nil {
		return nil
	}
	// Codex returns nonzero with a "not found" message when the server is
	// already gone. We don't have a stable error code to key on, so match the
	// substring as a fallback (case-insensitive in case Codex changes message
	// casing). Worst case: a real failure becomes a soft error and the
	// subsequent `mcp add` will fail loudly with the duplicate.
	low := bytes.ToLower(out)
	if bytes.Contains(low, []byte("not found")) || bytes.Contains(low, []byte("does not exist")) {
		return nil
	}
	return fmt.Errorf("codex mcp remove %s: %w", name, err)
}

// runCodexCommand executes `codexBin args...` and returns combined output.
// Used directly so we can inspect stderr in error paths (Codex emits errors
// there). codexBin is the resolved path of an external CLI tool, either from
// exec.LookPath (PATH) or the user-supplied --codex-path; passing a malicious
// path would be the user attacking themselves.
//
//nolint:gosec // G204: canonical CLI subprocess invocation; see comment above.
func runCodexCommand(ctx context.Context, codexBin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, codexBin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return out, nil
}

// formatEnvFlags renders redacted `--env K=<redacted> ...` entries for dry-run
// output. Codex stores env values in its MCP config, and those values are often
// credentials; dry-run output must not copy them into terminal scrollback.
func formatEnvFlags(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for _, k := range keys {
		out += " --env " + k + "=<redacted>"
	}
	return out
}

// joinArgs renders args for human-readable preview output.
func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += strconv.Quote(a)
	}
	return out
}
