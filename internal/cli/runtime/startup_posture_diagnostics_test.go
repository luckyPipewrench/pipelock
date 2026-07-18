// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestStartupEnabledCheckCountTracksEveryOptionalControl(t *testing.T) {
	t.Parallel()

	disabled := false
	base := &config.Config{
		Mode:                config.ModeBalanced,
		SeedPhraseDetection: config.SeedPhraseDetection{Enabled: &disabled},
	}
	baseCount := startupEnabledCheckCount(base)
	if baseCount != 7 {
		t.Fatalf("disabled control count = %d, want immutable floor of 7", baseCount)
	}

	tests := []struct {
		name   string
		enable func(*config.Config)
	}{
		{name: "URL length", enable: func(c *config.Config) { c.FetchProxy.Monitoring.MaxURLLength = 1 }},
		{name: "strict allowlist", enable: func(c *config.Config) {
			c.Mode = config.ModeStrict
			c.APIAllowlist = []string{"api.vendor.example"}
		}},
		{name: "domain blocklist", enable: func(c *config.Config) {
			c.FetchProxy.Monitoring.Blocklist = []string{"blocked.vendor.example"}
		}},
		{name: "configured DLP", enable: func(c *config.Config) { c.DLP.Patterns = []config.DLPPattern{{Name: "credential"}} }},
		{name: "path entropy", enable: func(c *config.Config) { c.FetchProxy.Monitoring.EntropyThreshold = 1 }},
		{name: "subdomain entropy", enable: func(c *config.Config) { c.FetchProxy.Monitoring.SubdomainEntropyThreshold = 1 }},
		{name: "DNS SSRF", enable: func(c *config.Config) { c.Internal = []string{"10.0.0.0/8"} }},
		{name: "request rate", enable: func(c *config.Config) { c.FetchProxy.Monitoring.MaxReqPerMinute = 1 }},
		{name: "data budget", enable: func(c *config.Config) { c.FetchProxy.Monitoring.MaxDataPerMinute = 1 }},
		{name: "seed phrase", enable: func(c *config.Config) {
			enabled := true
			c.SeedPhraseDetection.Enabled = &enabled
		}},
		{name: "request body", enable: func(c *config.Config) { c.RequestBodyScanning.Enabled = true }},
		{name: "response", enable: func(c *config.Config) { c.ResponseScanning.Enabled = true }},
		{name: "SSE response", enable: func(c *config.Config) { c.ResponseScanning.SSEStreaming.Enabled = true }},
		{name: "MCP input", enable: func(c *config.Config) { c.MCPInputScanning.Enabled = true }},
		{name: "MCP tool scan", enable: func(c *config.Config) { c.MCPToolScanning.Enabled = true }},
		{name: "MCP tool policy", enable: func(c *config.Config) { c.MCPToolPolicy.Enabled = true }},
		{name: "MCP session binding", enable: func(c *config.Config) { c.MCPSessionBinding.Enabled = true }},
		{name: "tool chain", enable: func(c *config.Config) { c.ToolChainDetection.Enabled = true }},
		{name: "cross request", enable: func(c *config.Config) { c.CrossRequestDetection.Enabled = true }},
		{name: "address protection", enable: func(c *config.Config) { c.AddressProtection.Enabled = true }},
		{name: "browser shield", enable: func(c *config.Config) { c.BrowserShield.Enabled = true }},
		{name: "A2A", enable: func(c *config.Config) { c.A2AScanning.Enabled = true }},
		{name: "file sentry", enable: func(c *config.Config) { c.FileSentry.Enabled = true }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := base.Clone()
			tt.enable(cfg)
			if got := startupEnabledCheckCount(cfg); got != baseCount+1 {
				t.Fatalf("startupEnabledCheckCount = %d, want %d after enabling %s", got, baseCount+1, tt.name)
			}
		})
	}
}

func TestStartupListenersReportEveryActiveSurface(t *testing.T) {
	t.Parallel()

	s, _ := newTestServer(t, func(opts *ServerOpts) {
		opts.Listen = serverTestEphemeralListen
		opts.ListenChanged = true
		opts.MCPListen = "127.0.0.1:18889"
		opts.MCPUpstream = "http://127.0.0.1:18890"
	})
	s.apiOnSeparatePort = true

	cfg := s.cfg.Clone()
	cfg.MetricsListen = "127.0.0.1:19090"
	cfg.ForwardProxy.Enabled = true
	cfg.WebSocketProxy.Enabled = true
	cfg.ScanAPI.Listen = "127.0.0.1:19091"
	cfg.KillSwitch.APIToken = "diagnostic-test-token"
	cfg.KillSwitch.APIListen = "127.0.0.1:19092"
	cfg.ReverseProxy.Enabled = true
	cfg.ReverseProxy.Listen = "127.0.0.1:19093"
	resolved, _ := cfg.ResolveRuntime(config.RuntimeResolveOpts{Mode: config.RuntimeForwardWithMCPListener})

	got := strings.Join(s.startupListeners(resolved, "127.0.0.1:19089"), ",")
	for _, want := range []string{
		"fetch=127.0.0.1:19089",
		"stats=127.0.0.1:19090",
		"forward=enabled",
		"ws=127.0.0.1:19089",
		"scan_api=127.0.0.1:19091",
		"kill_api=127.0.0.1:19092",
		"mcp=127.0.0.1:18889",
		"reverse=127.0.0.1:19093",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("startup listeners %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "diagnostic-test-token") {
		t.Fatalf("startup listeners leaked API token: %q", got)
	}
}
