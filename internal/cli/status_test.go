// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func runStatusCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := statusCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestStatusCmd_JSONEffectiveState(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "kill")
	if err := os.WriteFile(sentinel, []byte("on\n"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	cfgPath := writeConfig(t, strings.Join([]string{
		"mode: strict",
		"api_allowlist:",
		"  - api.vendor.example",
		"fetch_proxy:",
		"  listen: 127.0.0.1:7777",
		"forward_proxy:",
		"  enabled: true",
		"websocket_proxy:",
		"  enabled: true",
		"response_scanning:",
		"  enabled: true",
		"  action: block",
		"mcp_input_scanning:",
		"  enabled: true",
		"  action: block",
		"kill_switch:",
		"  sentinel_file: " + sentinel,
	}, "\n"))

	out, err := runStatusCmd(t, "--config", cfgPath, "--json")
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, out)
	}
	var report statusReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode status JSON: %v\n%s", err, out)
	}
	if report.Mode != config.ModeStrict {
		t.Fatalf("mode = %q, want strict", report.Mode)
	}
	if !report.KillSwitch.Active || !report.KillSwitch.Sources["sentinel"] {
		t.Fatalf("kill switch sources = %+v, active=%t", report.KillSwitch.Sources, report.KillSwitch.Active)
	}
	if got := statusScannerByName(report.Scanners, "mcp_input_scanning"); !got.Enabled || got.Action != config.ActionBlock {
		t.Fatalf("mcp_input_scanning = %+v", got)
	}
	if got := statusListenerByName(report.Listeners, "forward_proxy"); !got.Enabled || got.Listen != "127.0.0.1:7777" {
		t.Fatalf("forward_proxy listener = %+v", got)
	}
}

func TestStatusCmd_TextIncludesLicenseAndSources(t *testing.T) {
	out, err := runStatusCmd(t)
	if err != nil {
		t.Fatalf("status failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"Pipelock Status",
		"License: not_configured",
		"Kill switch:",
		"config",
		"api",
		"signal",
		"sentinel",
		"conductor_remote",
		"conductor_stale",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestStatusCmd_InvalidConfigReturnsExitConfig(t *testing.T) {
	missingConfig := filepath.Join(t.TempDir(), "missing.yaml")
	out, err := runStatusCmd(t, "--config", missingConfig)
	if err == nil {
		t.Fatalf("expected error for missing config, got output:\n%s", out)
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
		t.Fatalf("exit code = %d, want %d: %v", got, cliutil.ExitConfig, err)
	}
	if !strings.Contains(err.Error(), "load config") && !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("error = %v, want config load failure", err)
	}
}

func TestStatusReportDoesNotExposeConfiguredTokens(t *testing.T) {
	cfg := config.Defaults()
	apiToken := "ghp_" + strings.Repeat("B", 36)
	bearerToken := "ghp_" + strings.Repeat("C", 36)
	licenseToken := "ghp_" + strings.Repeat("D", 36)
	cfg.KillSwitch.APIToken = apiToken
	cfg.KillSwitch.APIListen = "127.0.0.1:9090"
	cfg.KillSwitch.AllowlistIPs = []string{"192.0.2.10/32"}
	cfg.ScanAPI.Auth.BearerTokens = []string{bearerToken}
	cfg.LicenseKey = licenseToken
	cfg.LicenseID = "lic-public-id"

	report := buildStatusReport(cfg, "test-config.yaml")
	jsonBytes, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal status report: %v", err)
	}
	var text bytes.Buffer
	printStatusReport(&text, report)
	all := string(jsonBytes) + text.String()
	for _, secret := range []string{apiToken, bearerToken, licenseToken, "192.0.2.10"} {
		if strings.Contains(all, secret) {
			t.Fatalf("status output leaked configured secret/detail %q:\n%s", secret, all)
		}
	}
}

func TestStatusLicenseStateBoundaries(t *testing.T) {
	now := time.Unix(200, 0)
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{name: "not_configured", cfg: &config.Config{}, want: "not_configured"},
		{name: "revoked", cfg: &config.Config{LicenseKey: "tok", LicenseID: "lic-1", LicenseRevoked: true}, want: "revoked"},
		{name: "expired", cfg: &config.Config{LicenseKey: "tok", LicenseID: "lic-1", LicenseExpiresAt: 100}, want: "expired"},
		{name: "active_agents", cfg: &config.Config{LicenseKey: "tok", LicenseID: "lic-1", LicenseAgentsFeature: true}, want: "active"},
		{name: "configured", cfg: &config.Config{LicenseKey: "tok", LicenseID: "lic-1"}, want: "configured"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statusLicenseState(tt.cfg, now).State; got != tt.want {
				t.Fatalf("state = %q, want %q", got, tt.want)
			}
		})
	}
}

func statusScannerByName(scanners []statusScanner, name string) statusScanner {
	for _, scanner := range scanners {
		if scanner.Name == name {
			return scanner
		}
	}
	return statusScanner{}
}

func statusListenerByName(listeners []statusListener, name string) statusListener {
	for _, listener := range listeners {
		if listener.Name == name {
			return listener
		}
	}
	return statusListener{}
}
