// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

type statusReport struct {
	ConfigFile string                 `json:"config_file"`
	Version    string                 `json:"version"`
	Mode       string                 `json:"mode"`
	Enforce    bool                   `json:"enforce"`
	Listeners  []statusListener       `json:"listeners"`
	Scanners   []statusScanner        `json:"scanners"`
	License    statusLicense          `json:"license"`
	KillSwitch statusKillSwitchReport `json:"kill_switch"`
}

type statusListener struct {
	Name    string `json:"name"`
	Listen  string `json:"listen,omitempty"`
	Enabled bool   `json:"enabled"`
	Detail  string `json:"detail,omitempty"`
}

type statusScanner struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Action  string `json:"action,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type statusLicense struct {
	State  string `json:"state"`
	ID     string `json:"id,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type statusKillSwitchReport struct {
	Active  bool            `json:"active"`
	Sources map[string]bool `json:"sources"`
	Detail  string          `json:"detail,omitempty"`
}

func statusCmd() *cobra.Command {
	var configFile string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print read-only effective Pipelock state",
		Long: `Print a read-only summary of the effective local configuration: mode,
listeners, scanner switches, license state, and kill-switch sources. This
command loads config and stats any configured kill-switch sentinel file, but it
does not mutate runtime state or contact the proxy.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, cfgLabel, err := explainLoadConfig(configFile)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			report := buildStatusReport(cfg, cfgLabel)
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return fmt.Errorf("encode status report JSON: %w", err)
				}
				return nil
			}
			printStatusReport(cmd.OutOrStdout(), report)
			return nil
		},
	}
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path (default: built-in defaults)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output report as JSON")
	return cmd
}

func buildStatusReport(cfg *config.Config, cfgLabel string) statusReport {
	ks := killswitch.New(cfg)
	sources := ks.Sources()
	return statusReport{
		ConfigFile: cfgLabel,
		Version:    cliutil.Version,
		Mode:       cfg.Mode,
		Enforce:    cfg.EnforceEnabled(),
		Listeners:  statusListeners(cfg),
		Scanners:   statusScanners(cfg),
		License:    statusLicenseState(cfg, time.Now()),
		KillSwitch: statusKillSwitchReport{
			Active:  anyKillSwitchSource(sources),
			Sources: sources,
			Detail:  killSwitchDetail(cfg),
		},
	}
}

func statusListeners(cfg *config.Config) []statusListener {
	listeners := []statusListener{
		{Name: "fetch_proxy", Listen: cfg.FetchProxy.Listen, Enabled: cfg.FetchProxy.Listen != ""},
		{Name: "forward_proxy", Listen: cfg.FetchProxy.Listen, Enabled: cfg.ForwardProxy.Enabled},
		{Name: "websocket_proxy", Listen: cfg.FetchProxy.Listen, Enabled: cfg.WebSocketProxy.Enabled},
		{Name: "metrics", Listen: cfg.MetricsListen, Enabled: cfg.MetricsListen != ""},
		{Name: "kill_switch_api", Listen: cfg.KillSwitch.APIListen, Enabled: cfg.KillSwitch.APIListen != ""},
		{Name: "scan_api", Listen: cfg.ScanAPI.Listen, Enabled: cfg.ScanAPI.Listen != ""},
	}
	listeners = append(listeners, statusListener{
		Name:    "reverse_proxy",
		Listen:  cfg.ReverseProxy.Listen,
		Enabled: cfg.ReverseProxy.Enabled,
		Detail:  cfg.ReverseProxy.Profile,
	})
	return listeners
}

func statusScanners(cfg *config.Config) []statusScanner {
	enabledSeed := cfg.SeedPhraseDetection.Enabled == nil || *cfg.SeedPhraseDetection.Enabled
	scanners := []statusScanner{
		{Name: "url_scanning", Enabled: true, Action: modeAction(cfg), Detail: "scheme, CRLF, path traversal, allowlist/blocklist, SSRF, DLP, entropy, rate, budget"},
		{Name: "dlp", Enabled: true, Action: modeAction(cfg), Detail: fmt.Sprintf("%d patterns; scan_env=%t", len(cfg.DLP.Patterns), cfg.DLP.ScanEnv)},
		{Name: "core_dlp", Enabled: true, Action: config.ActionBlock, Detail: "immutable floor"},
		{Name: "ssrf", Enabled: cfg.Internal != nil, Action: modeAction(cfg)},
		{Name: "core_ssrf", Enabled: true, Action: config.ActionBlock, Detail: "immutable literal-IP floor"},
		{Name: "response_scanning", Enabled: cfg.ResponseScanning.Enabled, Action: cfg.ResponseScanning.Action},
		{Name: "request_body_scanning", Enabled: cfg.RequestBodyScanning.Enabled, Action: cfg.RequestBodyScanning.Action},
		{Name: "mcp_input_scanning", Enabled: cfg.MCPInputScanning.Enabled, Action: cfg.MCPInputScanning.Action},
		{Name: "mcp_tool_scanning", Enabled: cfg.MCPToolScanning.Enabled, Action: cfg.MCPToolScanning.Action},
		{Name: "mcp_tool_policy", Enabled: cfg.MCPToolPolicy.Enabled, Action: cfg.MCPToolPolicy.Action},
		{Name: "mcp_session_binding", Enabled: cfg.MCPSessionBinding.Enabled, Action: cfg.MCPSessionBinding.UnknownToolAction},
		{Name: "mcp_binary_integrity", Enabled: cfg.MCPBinaryIntegrity.Enabled, Action: cfg.MCPBinaryIntegrity.Action},
		{Name: "mcp_tool_provenance", Enabled: cfg.MCPToolProvenance.Enabled, Action: cfg.MCPToolProvenance.Action},
		{Name: "a2a_scanning", Enabled: cfg.A2AScanning.Enabled, Action: cfg.A2AScanning.Action},
		{Name: "address_protection", Enabled: cfg.AddressProtection.Enabled, Action: cfg.AddressProtection.Action},
		{Name: "browser_shield", Enabled: cfg.BrowserShield.Enabled, Action: cfg.BrowserShield.OversizeAction},
		{Name: "media_policy", Enabled: cfg.MediaPolicy.IsEnabled(), Action: config.ActionBlock},
		{Name: "seed_phrase_detection", Enabled: enabledSeed, Action: modeAction(cfg)},
		{Name: "file_sentry", Enabled: cfg.FileSentry.Enabled, Action: cfg.FileSentry.Action},
		{Name: "git_protection", Enabled: cfg.GitProtection.Enabled, Action: config.ActionBlock},
	}
	return scanners
}

func modeAction(cfg *config.Config) string {
	if !cfg.EnforceEnabled() || cfg.Mode == config.ModeAudit {
		return config.ActionWarn
	}
	return config.ActionBlock
}

func statusLicenseState(cfg *config.Config, now time.Time) statusLicense {
	switch {
	case cfg.LicenseKey == "":
		return statusLicense{State: "not_configured", Detail: "no enterprise license configured"}
	case cfg.LicenseRevoked:
		return statusLicense{State: "revoked", ID: cfg.LicenseID, Detail: cfg.LicenseRevocationReason}
	case cfg.LicenseExpiresAt > 0 && now.Unix() > cfg.LicenseExpiresAt:
		return statusLicense{State: "expired", ID: cfg.LicenseID, Detail: time.Unix(cfg.LicenseExpiresAt, 0).UTC().Format(time.DateOnly)}
	case cfg.LicenseAgentsFeature:
		return statusLicense{State: "active", ID: cfg.LicenseID, Detail: "agents feature enabled"}
	case cfg.LicenseID != "":
		return statusLicense{State: "configured", ID: cfg.LicenseID, Detail: "license token loaded"}
	default:
		return statusLicense{State: "configured", Detail: "license token configured; verification status unavailable in this build"}
	}
}

func anyKillSwitchSource(sources map[string]bool) bool {
	for _, active := range sources {
		if active {
			return true
		}
	}
	return false
}

func killSwitchDetail(cfg *config.Config) string {
	parts := []string{
		fmt.Sprintf("sentinel_file=%t", cfg.KillSwitch.SentinelFile != ""),
		fmt.Sprintf("api_listen=%t", cfg.KillSwitch.APIListen != ""),
		fmt.Sprintf("allowlist_ips=%d", len(cfg.KillSwitch.AllowlistIPs)),
	}
	return strings.Join(parts, ", ")
}

func printStatusReport(w io.Writer, report statusReport) {
	_, _ = fmt.Fprintln(w, "Pipelock Status")
	_, _ = fmt.Fprintln(w, "===============")
	_, _ = fmt.Fprintf(w, "Config:  %s\n", terminalDisplay(report.ConfigFile))
	_, _ = fmt.Fprintf(w, "Mode:    %s\n", terminalDisplay(report.Mode))
	_, _ = fmt.Fprintf(w, "Enforce: %t\n", report.Enforce)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Listeners:")
	for _, l := range report.Listeners {
		_, _ = fmt.Fprintf(w, "  %-18s %-8s %s", terminalDisplay(l.Name), onOff(l.Enabled), terminalDisplay(l.Listen))
		if l.Detail != "" {
			_, _ = fmt.Fprintf(w, " (%s)", terminalDisplay(l.Detail))
		}
		_, _ = fmt.Fprintln(w)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Scanners:")
	for _, s := range report.Scanners {
		_, _ = fmt.Fprintf(w, "  %-22s %-8s", terminalDisplay(s.Name), onOff(s.Enabled))
		if s.Action != "" {
			_, _ = fmt.Fprintf(w, " action=%s", terminalDisplay(s.Action))
		}
		if s.Detail != "" {
			_, _ = fmt.Fprintf(w, " (%s)", terminalDisplay(s.Detail))
		}
		_, _ = fmt.Fprintln(w)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "License: %s", terminalDisplay(report.License.State))
	if report.License.ID != "" {
		_, _ = fmt.Fprintf(w, " (%s)", terminalDisplay(report.License.ID))
	}
	if report.License.Detail != "" {
		_, _ = fmt.Fprintf(w, " - %s", terminalDisplay(report.License.Detail))
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "Kill switch: active=%t", report.KillSwitch.Active)
	if report.KillSwitch.Detail != "" {
		_, _ = fmt.Fprintf(w, " (%s)", terminalDisplay(report.KillSwitch.Detail))
	}
	_, _ = fmt.Fprintln(w)
	for _, name := range sortedSourceNames(report.KillSwitch.Sources) {
		_, _ = fmt.Fprintf(w, "  %-18s %t\n", terminalDisplay(name), report.KillSwitch.Sources[name])
	}
}

func sortedSourceNames(sources map[string]bool) []string {
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func onOff(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}
