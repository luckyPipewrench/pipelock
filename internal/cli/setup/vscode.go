// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// discoverConfigForWrap returns the configFile to pass into the wrapped MCP
// proxy invocation. If the operator already supplied --config, that wins.
// Otherwise we look for the standard pipelock config locations and embed the
// first match in the wrapped argv. Without this auto-discovery the spawned
// subprocess would load config.Defaults() which disables MCPInputScanning,
// MCPToolScanning, MCPToolPolicy, and FlightRecorder, producing an install
// that looks correct while silently scanning nothing.
func discoverConfigForWrap(cmd *cobra.Command, configFile string) string {
	if configFile != "" {
		clean, err := filepath.Abs(filepath.Clean(configFile))
		if err != nil {
			return filepath.Clean(configFile)
		}
		return clean
	}
	if discovered := cliutil.DiscoverConfigPath(); discovered != "" {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Using config %s for the wrapped MCP proxy.\n", discovered)
		return discovered
	}
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
		"warning: no pipelock config found at PIPELOCK_CONFIG, $XDG_CONFIG_HOME/pipelock/pipelock.yaml, ~/.config/pipelock/pipelock.yaml, or /etc/pipelock/pipelock.yaml. The wrapped MCP proxy will run with built-in defaults; MCP input scanning, tool scanning, tool policy, and the flight recorder are disabled in the defaults. Pass --config explicitly or place a config at one of the standard locations to enable scanning.")
	return ""
}

// vscodeMCPConfig represents the VS Code .vscode/mcp.json file structure.
// Top-level key is "servers" (not "mcpServers" like Cursor).
// Inputs and other unknown fields are preserved via rawFields.
type vscodeMCPConfig struct {
	Inputs  json.RawMessage                   `json:"inputs,omitempty"`
	Servers map[string]map[string]interface{} `json:"servers"`
}

// sidecarOp captures a deferred header-sidecar mutation produced by wrap or
// unwrap. The wrap helpers are pure: they decide what the wrapped argv and
// the metadata should contain, and they describe (but do not execute) the
// header-sidecar write or delete that backs them. Callers accumulate these
// ops during their wrap / unwrap loops. Install applies write ops immediately
// before the canonical config rename and rolls them back if that rename fails;
// remove applies delete ops only after the restored config is committed.
// dry-run skips the apply step entirely.
type sidecarOp struct {
	// kind is "write" when install needs the sidecar created, or "delete"
	// when remove needs it cleaned up.
	kind string
	// path is the deterministic sidecar file location.
	path string
	// body is the file content, only populated when kind == "write".
	body []byte
}

const (
	sidecarOpWrite  = "write"
	sidecarOpDelete = "delete"
)

// applySidecarOps performs the writes and deletes described by ops. On a
// write failure it deletes any sidecars that were successfully written
// earlier in the same call so callers never observe a partially-applied
// plan. Delete ops are best-effort (absent paths return nil from
// removeHeaderSidecar) so they cannot trigger the rollback path.
func applySidecarOps(ops []sidecarOp) error {
	written := make([]string, 0, len(ops))
	for _, op := range ops {
		switch op.kind {
		case sidecarOpWrite:
			if err := commitHeaderSidecar(op.path, op.body); err != nil {
				for _, p := range written {
					removeHeaderSidecar(p)
				}
				return err
			}
			written = append(written, op.path)
		case sidecarOpDelete:
			removeHeaderSidecar(op.path)
		}
	}
	return nil
}

// rollbackSidecarWrites deletes every sidecar referenced by a "write" op in
// ops. Used when a later step (the canonical config atomic write) fails
// after applySidecarOps has already landed sidecars on disk.
func rollbackSidecarWrites(ops []sidecarOp) {
	for _, op := range ops {
		if op.kind == sidecarOpWrite {
			removeHeaderSidecar(op.path)
		}
	}
}

// pipelockMeta stores original server config for unwrapping on remove.
//
// ArgsPresent distinguishes "source had an args field" from "source omitted
// args entirely" so unwrap can restore `"args": []` byte-exact for sources
// that declared it. Without it, an unwrap of a server seeded with empty args
// would drop the field.
//
// HeaderSidecarPath, when set, points at the operator-private 0o600 file
// the install wrote with the server's headers. The wrapped argv references
// it via --header-file so credential values never appear in process argv
// (visible via /proc/<pid>/cmdline). Remove deletes the sidecar.
//
// omitempty preserves backward compatibility with rosters wrapped before
// these fields existed.
type pipelockMeta struct {
	OriginalType      string            `json:"original_type"`
	TypeOmitted       bool              `json:"type_omitted,omitempty"`
	OriginalCommand   string            `json:"original_command,omitempty"`
	OriginalArgs      []string          `json:"original_args,omitempty"`
	ArgsPresent       bool              `json:"args_present,omitempty"`
	OriginalURL       string            `json:"original_url,omitempty"`
	OriginalHeaders   map[string]string `json:"original_headers,omitempty"`
	HeaderSidecarPath string            `json:"header_sidecar_path,omitempty"`
}

func VscodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vscode",
		Short: "VS Code integration",
		Long: `Commands for integrating pipelock with VS Code's MCP server support.

Unlike Cursor and Claude Code which use hooks, VS Code integration wraps
MCP servers through pipelock's MCP proxy. All tool calls, responses, and
descriptions are scanned bidirectionally.

The install subcommand rewrites .vscode/mcp.json to route MCP servers
through pipelock. The remove subcommand restores the original config.`,
	}

	cmd.AddCommand(
		vscodeInstallCmd(),
		vscodeRemoveCmd(),
	)

	return cmd
}

func vscodeInstallCmd() *cobra.Command {
	var (
		global     bool
		project    bool
		dryRun     bool
		configFile string
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Wrap VS Code MCP servers through pipelock",
		Long: `Rewrites .vscode/mcp.json to route all MCP servers through pipelock's
MCP proxy. Stdio servers get their command wrapped. HTTP/SSE servers are
converted to stdio with --upstream.

By default writes to .vscode/mcp.json in the current directory (project-level).
Use --global to write to the VS Code user-level mcp.json.

If mcp.json already exists, servers are wrapped in place. Already-wrapped
servers are skipped (idempotent). A .bak backup is created before modification.
Non-server fields (inputs, sandbox) are preserved.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVscodeInstall(cmd, global, project, dryRun, configFile)
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "install to VS Code user-level mcp.json")
	cmd.Flags().BoolVar(&project, "project", false, "install to .vscode/mcp.json in current directory (default)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "path to pipelock config file for --config passthrough")

	return cmd
}

func vscodeRemoveCmd() *cobra.Command {
	var (
		global  bool
		project bool
		dryRun  bool
	)

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove pipelock wrapping from VS Code MCP servers",
		Long: `Restores .vscode/mcp.json by unwrapping servers that were wrapped by
pipelock install. Original server configurations are restored from the
_pipelock metadata field. Non-wrapped servers are left unchanged.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVscodeRemove(cmd, global, project, dryRun)
		},
	}

	cmd.Flags().BoolVar(&global, "global", false, "remove from VS Code user-level mcp.json")
	cmd.Flags().BoolVar(&project, "project", false, "remove from .vscode/mcp.json in current directory (default)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be written without modifying files")

	return cmd
}

// vscodeConfigPath returns the target mcp.json path based on flags.
func vscodeConfigPath(global bool) (string, error) {
	if global {
		return vscodeUserConfigPath()
	}
	return filepath.Join(".", ".vscode", "mcp.json"), nil
}

// vscodeUserConfigPath returns the VS Code user-level mcp.json path.
func vscodeUserConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json"), nil
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, "Code", "User", "mcp.json"), nil
	default: // linux, freebsd, etc.
		configDir := os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			configDir = filepath.Join(home, ".config")
		}
		return filepath.Join(configDir, "Code", "User", "mcp.json"), nil
	}
}

func runVscodeInstall(cmd *cobra.Command, global, project, dryRun bool, configFile string) error {
	if global && project {
		return fmt.Errorf("--global and --project are mutually exclusive")
	}

	// Default to project when no scope flag is set.
	targetPath, err := vscodeConfigPath(global)
	if err != nil {
		return err
	}

	// Auto-discover the operator's pipelock.yaml when --config was not passed.
	// Without this, the spawned MCP proxy loads config.Defaults() with MCP
	// scanning and the flight recorder disabled — the wrap would look correct
	// while silently providing no scanning. See discoverConfigForWrap below.
	configFile = discoverConfigForWrap(cmd, configFile)

	// Find pipelock binary path.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding pipelock binary: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolving pipelock binary path: %w", err)
	}

	// Load existing mcp.json if present.
	existingData, readErr := os.ReadFile(filepath.Clean(targetPath))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("reading existing %s: %w", targetPath, readErr)
	}

	mcpCfg := &vscodeMCPConfig{
		Servers: make(map[string]map[string]interface{}),
	}
	if readErr == nil && len(existingData) > 0 {
		if err := json.Unmarshal(existingData, mcpCfg); err != nil {
			return fmt.Errorf("parsing %s: %w", targetPath, err)
		}
		if mcpCfg.Servers == nil {
			mcpCfg.Servers = make(map[string]map[string]interface{})
		}
	}

	// Wrap each server through pipelock.
	wrapped := 0
	skipped := 0
	var sidecarOps []sidecarOp
	for name, server := range mcpCfg.Servers {
		if isVscodeWrapped(server) {
			skipped++
			continue
		}

		newServer, meta, plan, err := wrapVscodeServer(server, exe, configFile, targetPath, name)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping server %q: %v\n", name, err)
			continue
		}

		// Store metadata for unwrapping.
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshaling metadata for %q: %w", name, err)
		}
		var metaMap interface{}
		if err := json.Unmarshal(metaJSON, &metaMap); err != nil {
			return fmt.Errorf("unmarshaling metadata for %q: %w", name, err)
		}
		newServer["_pipelock"] = metaMap

		mcpCfg.Servers[name] = newServer
		if plan != nil {
			sidecarOps = append(sidecarOps, *plan)
		}
		wrapped++
	}

	// Marshal result, preserving unknown top-level fields.
	output, err := marshalVscodeConfig(existingData, mcpCfg)
	if err != nil {
		return fmt.Errorf("marshaling mcp.json: %w", err)
	}

	if dryRun {
		// Dry-run is read-only end-to-end: do not write the canonical config
		// AND do not write any sidecar file. The wrapped argv in the dry-run
		// preview already references the deterministic sidecar path so the
		// operator can see what would land where.
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s (%d wrapped, %d already wrapped):\n%s", targetPath, wrapped, skipped, output)
		return nil
	}

	// Create directory if needed.
	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("creating directory %s: %w", targetDir, err)
	}

	// Backup existing file.
	if readErr == nil {
		if err := os.WriteFile(targetPath+".bak", existingData, 0o600); err != nil {
			return fmt.Errorf("creating backup: %w", err)
		}
	}

	// Sidecars are written FIRST so a sidecar failure leaves the operator's
	// config untouched. applySidecarOps internally rolls back any partial
	// writes if one of the writes fails partway through the plan.
	if err := applySidecarOps(sidecarOps); err != nil {
		return fmt.Errorf("writing header sidecar: %w", err)
	}

	// Atomic write of the canonical config. If this fails, the sidecars we
	// just wrote would orphan to a config file that has no reference to
	// them, so we clean them up before returning the error.
	if err := vscodeAtomicWrite(targetPath, output, targetDir); err != nil {
		rollbackSidecarWrites(sidecarOps)
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrapped %d server(s) in %s (%d already wrapped)\n", wrapped, targetPath, skipped)
	if wrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart VS Code to activate pipelock scanning.\n")
	}
	return nil
}

func runVscodeRemove(cmd *cobra.Command, global, project, dryRun bool) error {
	if global && project {
		return fmt.Errorf("--global and --project are mutually exclusive")
	}

	targetPath, err := vscodeConfigPath(global)
	if err != nil {
		return err
	}

	existingData, err := os.ReadFile(filepath.Clean(targetPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No mcp.json found at %s\n", targetPath)
			return nil
		}
		return fmt.Errorf("reading %s: %w", targetPath, err)
	}

	mcpCfg := &vscodeMCPConfig{
		Servers: make(map[string]map[string]interface{}),
	}
	if err := json.Unmarshal(existingData, mcpCfg); err != nil {
		return fmt.Errorf("parsing %s: %w", targetPath, err)
	}

	unwrapped := 0
	var sidecarOps []sidecarOp
	for name, server := range mcpCfg.Servers {
		if !isVscodeWrapped(server) {
			continue
		}

		restored, plan, err := unwrapVscodeServer(server)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not unwrap %q: %v\n", name, err)
			continue
		}

		mcpCfg.Servers[name] = restored
		if plan != nil {
			sidecarOps = append(sidecarOps, *plan)
		}
		unwrapped++
	}

	output, err := marshalVscodeConfig(existingData, mcpCfg)
	if err != nil {
		return fmt.Errorf("marshaling mcp.json: %w", err)
	}

	if dryRun {
		// Dry-run is read-only: do not write the restored config AND do not
		// touch the sidecars referenced by the still-wrapped on-disk config.
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would write to %s (%d unwrapped):\n%s", targetPath, unwrapped, output)
		return nil
	}

	// Backup.
	if err := os.WriteFile(targetPath+".bak", existingData, 0o600); err != nil {
		return fmt.Errorf("creating backup: %w", err)
	}

	targetDir := filepath.Dir(targetPath)
	if err := vscodeAtomicWrite(targetPath, output, targetDir); err != nil {
		return err
	}

	// Sidecars are deleted only after the restored config is committed to
	// disk. A failure before this point leaves the wrapped config in place
	// with its sidecars still readable, so the operator can retry.
	_ = applySidecarOps(sidecarOps)

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unwrapped %d server(s) in %s\n", unwrapped, targetPath)
	if unwrapped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restart VS Code to apply changes.\n")
	}
	return nil
}

const (
	// vsTypeStdio is the VS Code MCP server type for subprocess-based servers.
	vsTypeStdio       = "stdio"
	mcpFlagHeader     = "--header"
	mcpFlagHeaderFile = "--header-file"
)

// isVscodeHTTPType returns true for server types that use URL-based upstream
// (anything that is not stdio).
func isVscodeHTTPType(t string) bool { return t != vsTypeStdio && t != "" }

// isVscodeWrapped returns true if a server entry has pipelock metadata.
func isVscodeWrapped(server map[string]interface{}) bool {
	_, ok := server["_pipelock"]
	return ok
}

// wrapVscodeServer wraps a single VS Code MCP server through pipelock mcp proxy.
// wrapVscodeServer wraps a single MCP server entry through pipelock mcp proxy.
// targetConfigPath + serverName are used to derive the per-server 0o600 header
// sidecar file when the entry carries an HTTP `headers` block; the wrapped
// argv references it via --header-file so credential header values never
// appear in /proc/<pid>/cmdline.
//
// The function is pure with respect to the file system: it computes the
// sidecar path and body but does not write them. Callers receive a sidecarOp
// (or nil) and decide when to apply it: install applies writes immediately
// before the canonical config rename and rolls them back on rename failure;
// remove applies deletes only after the restored config is committed; dry-run
// skips the apply step entirely.
func wrapVscodeServer(server map[string]interface{}, exe, configFile, targetConfigPath, serverName string) (map[string]interface{}, *pipelockMeta, *sidecarOp, error) {
	serverType, _ := server["type"].(string)
	typeOmitted := serverType == ""
	if typeOmitted {
		serverType = vsTypeStdio // VS Code defaults to stdio when type is omitted.
	}

	// VS Code mcp.json separates command and args, so use the raw path.
	// Unlike Cursor hooks (shell command string), no shell quoting needed.
	result := make(map[string]interface{})

	// Copy all fields except command/args/url/headers/type (we replace those).
	for k, v := range server {
		switch k {
		case "command", "args", "url", "headers", "type":
			// Replaced below.
		default:
			result[k] = v
		}
	}

	meta := &pipelockMeta{OriginalType: serverType, TypeOmitted: typeOmitted}

	// Collect --env flags for environment variable passthrough.
	// pipelock mcp proxy strips the parent env and only passes safeEnvKeys
	// plus explicit --env additions. Without these flags, the child MCP
	// server won't receive the env vars VS Code sets.
	envFlags := buildEnvFlags(server)

	if serverType == vsTypeStdio {
		originalCmd, _ := server["command"].(string)
		if originalCmd == "" {
			return nil, nil, nil, fmt.Errorf("stdio server missing command")
		}
		_, meta.ArgsPresent = server["args"]
		originalArgs := interfaceSliceToStrings(server["args"])

		meta.OriginalCommand = originalCmd
		meta.OriginalArgs = originalArgs

		args := []string{"mcp", "proxy"}
		if configFile != "" {
			args = append(args, "--config", configFile)
		}
		args = append(args, envFlags...)
		args = append(args, "--")
		args = append(args, originalCmd)
		args = append(args, originalArgs...)

		result["type"] = vsTypeStdio
		result["command"] = exe
		result["args"] = args
	} else if isVscodeHTTPType(serverType) {
		originalURL, _ := server["url"].(string)
		if originalURL == "" {
			return nil, nil, nil, fmt.Errorf("%s server missing url", serverType)
		}

		meta.OriginalURL = originalURL
		headerLines, err := extractHeaderLines(server)
		if err != nil {
			return nil, nil, nil, err
		}
		if headers, ok := server["headers"].(map[string]interface{}); ok {
			meta.OriginalHeaders = make(map[string]string, len(headers))
			for k, v := range headers {
				value, ok := v.(string)
				if !ok {
					return nil, nil, nil, fmt.Errorf("header %q has non-string value of type %T; only string header values are supported", k, v)
				}
				meta.OriginalHeaders[k] = value
			}
		}
		var (
			sidecarFlags []string
			plan         *sidecarOp
		)
		if len(headerLines) > 0 {
			path, err := headerSidecarPath(targetConfigPath, serverName)
			if err != nil {
				return nil, nil, nil, err
			}
			body := []byte(strings.Join(headerLines, "\n") + "\n")
			plan = &sidecarOp{kind: sidecarOpWrite, path: path, body: body}
			meta.HeaderSidecarPath = path
			sidecarFlags = []string{mcpFlagHeaderFile, path}
		}

		args := []string{"mcp", "proxy"}
		if configFile != "" {
			args = append(args, "--config", configFile)
		}
		args = append(args, envFlags...)
		args = append(args, sidecarFlags...)
		args = append(args, "--upstream", originalURL)

		result["type"] = vsTypeStdio
		result["command"] = exe
		result["args"] = args
		return result, meta, plan, nil
	} else {
		return nil, nil, nil, fmt.Errorf("unsupported server type %q", serverType)
	}

	return result, meta, nil, nil
}

// unwrapVscodeServer restores a server from its pipelock metadata. The
// returned sidecarOp (when non-nil) describes a sidecar delete that the
// caller MUST execute only after successfully writing the restored config to
// disk; otherwise a marshal / atomic-write failure later in the remove path
// would leave the still-wrapped config on disk while the credential carrier
// it references is gone.
func unwrapVscodeServer(server map[string]interface{}) (map[string]interface{}, *sidecarOp, error) {
	metaRaw, ok := server["_pipelock"]
	if !ok {
		return server, nil, nil
	}

	// Marshal and unmarshal to get a typed struct.
	metaJSON, err := json.Marshal(metaRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("reading _pipelock metadata: %w", err)
	}
	var meta pipelockMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, nil, fmt.Errorf("parsing _pipelock metadata: %w", err)
	}

	var plan *sidecarOp
	if meta.HeaderSidecarPath != "" {
		path, err := validatedHeaderSidecarDeletePath(meta.HeaderSidecarPath)
		if err != nil {
			return nil, nil, err
		}
		plan = &sidecarOp{kind: sidecarOpDelete, path: path}
	}

	result := make(map[string]interface{})

	// Copy fields that aren't replaced by restore.
	for k, v := range server {
		switch k {
		case "command", "args", "url", "headers", "type", "_pipelock":
			// Replaced/removed below.
		default:
			result[k] = v
		}
	}

	// Validate required metadata before restoring.
	switch meta.OriginalType {
	case vsTypeStdio:
		if meta.OriginalCommand == "" {
			return nil, nil, fmt.Errorf("invalid _pipelock metadata: missing original_command")
		}
	case "":
		return nil, nil, fmt.Errorf("invalid _pipelock metadata: missing original_type")
	default:
		if meta.OriginalURL == "" {
			return nil, nil, fmt.Errorf("invalid _pipelock metadata: missing original_url for %s server", meta.OriginalType)
		}
	}

	// Only set type if the original config had it explicitly.
	if !meta.TypeOmitted {
		result["type"] = meta.OriginalType
	}

	switch meta.OriginalType {
	case vsTypeStdio:
		result["command"] = meta.OriginalCommand
		// Restore args if the source had the field (new metadata) or if the
		// stored args are non-empty (legacy metadata that lacked ArgsPresent).
		// A source that had `"args": []` round-trips byte-exact via ArgsPresent.
		switch {
		case meta.ArgsPresent:
			if meta.OriginalArgs != nil {
				result["args"] = meta.OriginalArgs
			} else {
				result["args"] = []string{}
			}
		case len(meta.OriginalArgs) > 0:
			result["args"] = meta.OriginalArgs
		}
	default:
		result["url"] = meta.OriginalURL
		if len(meta.OriginalHeaders) > 0 {
			headers := make(map[string]interface{}, len(meta.OriginalHeaders))
			for k, v := range meta.OriginalHeaders {
				headers[k] = v
			}
			result["headers"] = headers
		}
	}

	return result, plan, nil
}

// buildEnvFlags extracts env var keys from a server's "env" block and returns
// --env KEY flags for each. VS Code resolves ${input:*} and ${env:*} variables
// before setting them on the process, so we only need the key names. pipelock
// mcp proxy will read the values from its own environment (which VS Code set).
func buildEnvFlags(server map[string]interface{}) []string {
	envMap, ok := server["env"].(map[string]interface{})
	if !ok || len(envMap) == 0 {
		return nil
	}
	flags := make([]string, 0, len(envMap)*2)
	for key := range envMap {
		flags = append(flags, "--env", key)
	}
	return flags
}

// extractHeaderLines reads, validates, and returns the operator's HTTP header
// declarations as "Key: Value" lines ready for a sidecar file. The runtime
// parser repeats these checks at startup; doing them here means a bad header
// fails install rather than surfacing only after the agent starts. Returns
// nil when the server has no headers block.
func extractHeaderLines(server map[string]interface{}) ([]string, error) {
	headers, ok := server["headers"].(map[string]interface{})
	if !ok || len(headers) == 0 {
		return nil, nil
	}

	lines := make([]string, 0, len(headers))
	for key, raw := range headers {
		value, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("header %q has non-string value of type %T; only string header values are supported", key, raw)
		}
		key = strings.Trim(key, " \t")
		value = strings.Trim(value, " \t")
		if err := validateSetupHeader(key, value); err != nil {
			return nil, err
		}
		lines = append(lines, key+": "+value)
	}
	// Deterministic ordering so the sidecar file is stable across reinstalls
	// even when Go's map iteration order shifts.
	sort.Strings(lines)
	return lines, nil
}

// headerSidecarDir returns the operator-private directory where the install
// command writes header sidecar files. Operator-private (0o700) so other
// local users cannot read credential headers, even with /proc visibility.
func headerSidecarDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, ".config", "pipelock", "wrap-headers"), nil
}

// headerSidecarPath returns the absolute path of the sidecar file for the
// given (target IDE config, server name) pair. The hash of the absolute
// config path keeps sidecars from different IDE installations from colliding
// on a shared server name (e.g. two Cline configs both declaring "remote").
// The hash of the raw server name keeps names that sanitize to the same path
// component (e.g. "prod/api" and "prod_api") from sharing one sidecar.
func headerSidecarPath(targetConfigPath, serverName string) (string, error) {
	dir, err := headerSidecarDir()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(filepath.Clean(targetConfigPath))
	if err != nil {
		return "", fmt.Errorf("resolving config path for sidecar: %w", err)
	}
	configSum := sha256.Sum256([]byte(abs))
	configPrefix := hex.EncodeToString(configSum[:])[:16]
	serverSum := sha256.Sum256([]byte(serverName))
	serverPrefix := hex.EncodeToString(serverSum[:])[:16]
	safeName := sanitizeSidecarComponent(serverName)
	if len(safeName) > 80 {
		safeName = safeName[:80]
	}
	return filepath.Join(dir, configPrefix+"-"+serverPrefix+"-"+safeName+".headers"), nil
}

func validatedHeaderSidecarDeletePath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("invalid _pipelock metadata: header sidecar path must be absolute")
	}
	if !strings.HasSuffix(filepath.Base(path), ".headers") {
		return "", fmt.Errorf("invalid _pipelock metadata: header sidecar path must end in .headers")
	}
	dir, err := headerSidecarDir()
	if err != nil {
		return "", err
	}
	cleanDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", fmt.Errorf("resolving header sidecar dir: %w", err)
	}
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolving header sidecar path: %w", err)
	}
	if !pathWithinDir(cleanDir, cleanPath) {
		return "", fmt.Errorf("invalid _pipelock metadata: header sidecar path escapes %s", cleanDir)
	}

	resolvedDir := cleanDir
	if realDir, err := filepath.EvalSymlinks(cleanDir); err == nil {
		resolvedDir = realDir
	}
	if realPath, err := filepath.EvalSymlinks(cleanPath); err == nil {
		if !pathWithinDir(resolvedDir, realPath) {
			return "", fmt.Errorf("invalid _pipelock metadata: header sidecar path resolves outside %s", resolvedDir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("resolving header sidecar path symlinks: %w", err)
	}

	return cleanPath, nil
}

func pathWithinDir(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil || rel == "." || rel == "" {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// sanitizeSidecarComponent strips characters that have meaning in path
// segments so an attacker-named MCP server cannot redirect the sidecar
// elsewhere. Replace anything outside [A-Za-z0-9._-] with '_'.
func sanitizeSidecarComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// commitHeaderSidecar atomically writes a sidecar body to path at 0o600
// under a 0o700 parent. This is the side-effecting half of the sidecar
// lifecycle; the deciding half is done by the wrap helpers, which produce
// a sidecarOp plan. Install applies writes before the canonical config rename
// and rolls them back if that rename fails; remove applies deletes only after
// the restored config is committed.
func commitHeaderSidecar(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating sidecar dir %s: %w", dir, err)
	}
	// Re-tighten the parent in case it pre-existed with a looser mode.
	// gosec G302 fires on the 0o700 directory mode because it treats the rule
	// as file-only; directories need the execute bit to be enterable.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // 0o700 is correct for a private directory
		return fmt.Errorf("locking down sidecar dir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".headers-*.tmp")
	if err != nil {
		return fmt.Errorf("creating sidecar temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing sidecar temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing sidecar temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("setting sidecar permissions: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming sidecar into place: %w", err)
	}
	return nil
}

// removeHeaderSidecar deletes the sidecar file. Best-effort; absent paths
// or already-deleted files are not surfaced as errors.
func removeHeaderSidecar(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(filepath.Clean(path))
}

func validateSetupHeader(key, value string) error {
	if key == "" {
		return fmt.Errorf("header key is empty")
	}
	if !validSetupHeaderName(key) {
		return fmt.Errorf("header %q has invalid characters", key)
	}
	switch strings.ToLower(key) {
	case "content-type", "accept", "mcp-session-id", "content-length", "transfer-encoding", "host":
		return fmt.Errorf("header %q is managed by the MCP HTTP transport and cannot be passed through", key)
	}
	if !validSetupHeaderValue(value) {
		return fmt.Errorf("header %q has invalid value characters", key)
	}
	return nil
}

func validSetupHeaderName(key string) bool {
	// HTTP header names are ASCII tokens (RFC 7230 §3.2.6); iterate by byte
	// so any non-ASCII byte is rejected by isSetupHTTPTokenChar.
	for i := 0; i < len(key); i++ {
		if !isSetupHTTPTokenChar(key[i]) {
			return false
		}
	}
	return true
}

func isSetupHTTPTokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func validSetupHeaderValue(value string) bool {
	for _, r := range value {
		if r == '\t' || r == ' ' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
		if r > 127 && unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// interfaceSliceToStrings converts []interface{} (from JSON unmarshal) to []string.
func interfaceSliceToStrings(v interface{}) []string {
	slice, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// marshalVscodeConfig marshals the mcp config while preserving unknown
// top-level fields from the original file data.
func marshalVscodeConfig(originalData []byte, cfg *vscodeMCPConfig) ([]byte, error) {
	// If we have original data, preserve unknown top-level fields.
	if len(originalData) > 0 {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(originalData, &raw); err == nil {
			// Update servers.
			serversJSON, err := json.Marshal(cfg.Servers)
			if err != nil {
				return nil, err
			}
			raw["servers"] = serversJSON

			// Update inputs if present in our config.
			if cfg.Inputs != nil {
				raw["inputs"] = cfg.Inputs
			}

			output, err := json.MarshalIndent(raw, "", "  ")
			if err != nil {
				return nil, err
			}
			return append(output, '\n'), nil
		}
	}

	// No original data or parse failed: marshal from scratch.
	output, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(output, '\n'), nil
}

// vscodeAtomicWrite writes data to targetPath via temp file + rename.
func vscodeAtomicWrite(targetPath string, data []byte, tmpDir string) error {
	tmpFile, err := os.CreateTemp(tmpDir, "mcp-*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
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
		return fmt.Errorf("renaming to %s: %w", targetPath, err)
	}

	return nil
}
