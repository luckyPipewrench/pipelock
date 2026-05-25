// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Coverage classifications reported by verify.
const (
	coverageFull    = "full"    // plugin present + proxy env injected
	coveragePartial = "partial" // plugin present XOR env injected
	coverageNone    = "none"    // neither
)

// verifyReport is the machine-readable result of `pipelock hermes verify`.
type verifyReport struct {
	PluginPresent   bool     `json:"plugin_present"`
	PluginRoot      string   `json:"plugin_root"`
	ConfigSidecar   string   `json:"config_sidecar,omitempty"`
	PipelockConfig  string   `json:"pipelock_config,omitempty"`
	ConfigReadable  *bool    `json:"pipelock_config_readable,omitempty"`
	ConfigWarning   string   `json:"pipelock_config_warning,omitempty"`
	PipelockBinary  string   `json:"pipelock_binary,omitempty"`
	HookExecutable  bool     `json:"hook_executable"`
	TerminalBackend string   `json:"terminal_backend"`
	ProxyEnvPresent []string `json:"proxy_env_present"`
	ProxyEnvMissing []string `json:"proxy_env_missing"`
	NoProxyWarning  string   `json:"no_proxy_warning,omitempty"`
	MCPServerCount  int      `json:"mcp_server_count"`
	Coverage        string   `json:"coverage"`
}

// lookPipelock resolves the pipelock binary the plugin would invoke. Overridable
// via PIPELOCK_BIN; mirrors the Python plugin's resolution so verify reports the
// same binary the hook will actually use. A package var so tests can stub it.
var lookPipelock = func() (string, bool) {
	if override := os.Getenv("PIPELOCK_BIN"); override != "" {
		if info, err := os.Stat(override); err == nil && !info.IsDir() {
			return override, info.Mode().Perm()&0o111 != 0
		}
		return override, false
	}
	path, err := exec.LookPath("pipelock")
	if err != nil {
		return "", false
	}
	info, statErr := os.Stat(path)
	return path, statErr == nil && info.Mode().Perm()&0o111 != 0
}

func verifyCmd() *cobra.Command {
	opts := &installOptions{Mode: ModeFull}
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Report pipelock's Hermes integration coverage",
		Long: `Inspect ~/.hermes and report whether the pipelock plugin is installed,
whether the hook binary is resolvable, which proxy env names are present in
the terminal backend passthrough, and the resulting coverage classification.

Coverage is reported honestly: "full" means the plugin is installed and the
proxy env names are present, NOT that terminal network egress is enforced.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.resolvePaths(); err != nil {
				return err
			}
			report := buildVerifyReport(opts)
			if jsonOut {
				return emitVerifyJSON(cmd, report)
			}
			emitVerifyText(cmd, report)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the report as JSON")
	cmd.Flags().StringVar(&opts.PluginRoot, "plugin-root", "",
		"override the plugin install directory (default ~/.hermes/plugins/pipelock)")
	cmd.Flags().StringVar(&opts.HermesConfig, "hermes-config", "",
		"override the Hermes config path (default ~/.hermes/config.yaml)")

	return cmd
}

// buildVerifyReport gathers integration state without mutating anything.
func buildVerifyReport(opts *installOptions) verifyReport {
	r := verifyReport{
		PluginRoot:      opts.PluginRoot,
		PluginPresent:   pluginInstalled(opts.PluginRoot),
		TerminalBackend: "local",
	}

	sidecarOK := inspectConfigSidecar(&r)

	bin, executable := lookPipelock()
	r.PipelockBinary = bin
	r.HookExecutable = executable

	// Config inspection is best-effort: a missing/unparseable config still
	// yields a meaningful "no env injected" report rather than an error.
	envInjected := false
	if cfg, err := loadHermesConfig(opts.HermesConfig); err == nil {
		r.TerminalBackend = cfg.backend()
		present := cfg.terminalEnvPresent()
		r.ProxyEnvPresent = present
		r.ProxyEnvMissing = missingProxyEnv(present)
		envInjected = len(present) == len(proxyEnvNames)
		r.MCPServerCount = mcpServerCount(cfg)
	} else {
		r.ProxyEnvMissing = append([]string(nil), proxyEnvNames...)
	}

	if np := noProxyValue(); isBroadNoProxy(np) {
		r.NoProxyWarning = fmt.Sprintf("NO_PROXY=%q is broad and may bypass pipelock for matching destinations", np)
	}

	pluginReady := r.PluginPresent && r.HookExecutable && sidecarOK
	r.Coverage = classifyCoverage(pluginReady, envInjected)
	return r
}

// classifyCoverage maps ready-plugin/env presence to a coverage label.
func classifyCoverage(pluginReady, envInjected bool) string {
	switch {
	case pluginReady && envInjected:
		return coverageFull
	case pluginReady || envInjected:
		return coveragePartial
	default:
		return coverageNone
	}
}

// inspectConfigSidecar validates the optional plugin sidecar. The sidecar is
// the exact config path the Python plugin passes to `pipelock hermes hook`; if
// it is stale or relative, the hook can fail closed at runtime while a shallow
// install check still looks complete.
func inspectConfigSidecar(r *verifyReport) bool {
	sidecar := filepath.Join(r.PluginRoot, configSidecarName)
	//nolint:gosec // verify intentionally inspects the operator-selected Hermes plugin sidecar.
	data, err := os.ReadFile(sidecar)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true
		}
		readable := false
		r.ConfigSidecar = sidecar
		r.ConfigReadable = &readable
		r.ConfigWarning = fmt.Sprintf("config sidecar is unreadable: %v", err)
		return false
	}
	r.ConfigSidecar = sidecar
	configPath := strings.TrimSpace(string(data))
	if configPath == "" {
		r.ConfigWarning = "config sidecar is empty; hook will fall back to its default config"
		return true
	}
	r.PipelockConfig = configPath
	readable := false
	r.ConfigReadable = &readable
	if !filepath.IsAbs(configPath) {
		r.ConfigWarning = "config sidecar uses a relative path; hook may resolve it from Hermes' process directory"
		return false
	}
	info, statErr := os.Stat(configPath)
	if statErr != nil {
		r.ConfigWarning = fmt.Sprintf("configured pipelock config is not readable: %v", statErr)
		return false
	}
	if info.IsDir() {
		r.ConfigWarning = "configured pipelock config is a directory, not a file"
		return false
	}
	readable = true
	r.ConfigReadable = &readable
	return true
}

func missingProxyEnv(present []string) []string {
	have := make(map[string]bool, len(present))
	for _, p := range present {
		have[p] = true
	}
	var missing []string
	for _, name := range proxyEnvNames {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

// isBroadNoProxy reports whether a NO_PROXY value is broad enough to bypass the
// proxy for a wide range of destinations.
func isBroadNoProxy(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		p := strings.TrimSpace(part)
		if p == "*" || p == "." || strings.HasPrefix(p, ".") {
			return true
		}
	}
	return false
}

func mcpServerCount(c *hermesConfig) int {
	servers, ok := c.root[mcpServersKey].(map[string]interface{})
	if !ok {
		return 0
	}
	return len(servers)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func emitVerifyJSON(cmd *cobra.Command, r verifyReport) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func emitVerifyText(cmd *cobra.Command, r verifyReport) {
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Plugin installed: %v (%s)\n", r.PluginPresent, r.PluginRoot)
	if r.ConfigSidecar != "" {
		_, _ = fmt.Fprintf(out, "Config sidecar:   %s\n", r.ConfigSidecar)
	}
	if r.PipelockConfig != "" {
		readable := false
		if r.ConfigReadable != nil {
			readable = *r.ConfigReadable
		}
		_, _ = fmt.Fprintf(out, "Pipelock config:  %s (readable=%v)\n", r.PipelockConfig, readable)
	}
	if r.PipelockBinary != "" {
		_, _ = fmt.Fprintf(out, "Hook binary:      %s (executable=%v)\n", r.PipelockBinary, r.HookExecutable)
	} else {
		_, _ = fmt.Fprintln(out, "Hook binary:      not found on PATH (set PIPELOCK_BIN)")
	}
	_, _ = fmt.Fprintf(out, "Terminal backend: %s\n", r.TerminalBackend)
	_, _ = fmt.Fprintf(out, "Proxy env names:  %d/%d present\n", len(r.ProxyEnvPresent), len(proxyEnvNames))
	if len(r.ProxyEnvMissing) > 0 {
		_, _ = fmt.Fprintf(out, "  missing: %s\n", strings.Join(r.ProxyEnvMissing, ", "))
	}
	if r.MCPServerCount > 0 {
		_, _ = fmt.Fprintf(out, "MCP servers:      %d declared\n", r.MCPServerCount)
	}
	if r.NoProxyWarning != "" {
		_, _ = fmt.Fprintf(out, "WARNING: %s\n", r.NoProxyWarning)
	}
	if r.ConfigWarning != "" {
		_, _ = fmt.Fprintf(out, "WARNING: %s\n", r.ConfigWarning)
	}
	_, _ = fmt.Fprintf(out, "Coverage:         %s\n", r.Coverage)
}
