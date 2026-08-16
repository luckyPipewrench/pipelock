// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestStatusLicenseStateRoutes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.LicenseKey = ""
	got := statusLicenseState(cfg, now)
	if got.State != "not_configured" {
		t.Fatalf("empty license = %+v, want not_configured", got)
	}

	cfg.LicenseKey = "lic-" + "test"
	cfg.LicenseRevoked = true
	cfg.LicenseID = "lic-1"
	cfg.LicenseRevocationReason = "operator revoked"
	got = statusLicenseState(cfg, now)
	if got.State != "revoked" || got.Detail != "operator revoked" {
		t.Fatalf("revoked = %+v", got)
	}

	cfg.LicenseRevoked = false
	cfg.LicenseExpiresAt = now.Add(-time.Hour).Unix()
	got = statusLicenseState(cfg, now)
	if got.State != "expired" {
		t.Fatalf("expired = %+v", got)
	}

	cfg.LicenseExpiresAt = now.Add(time.Hour).Unix()
	cfg.LicenseAgentsFeature = true
	got = statusLicenseState(cfg, now)
	if got.State != "active" || got.ID != "lic-1" {
		t.Fatalf("active = %+v", got)
	}

	cfg.LicenseAgentsFeature = false
	got = statusLicenseState(cfg, now)
	if got.State != "configured" || got.ID != "lic-1" || got.Detail != "license token loaded" {
		t.Fatalf("id-only configured = %+v", got)
	}

	cfg.LicenseID = ""
	got = statusLicenseState(cfg, now)
	if got.State != "configured" || got.ID != "" || !strings.Contains(got.Detail, "verification status unavailable") {
		t.Fatalf("key-only configured = %+v", got)
	}
}

func TestModeActionAuditWarns(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Mode = config.ModeAudit
	if got := modeAction(cfg); got != config.ActionWarn {
		t.Fatalf("audit mode = %q, want warn", got)
	}

	cfg.Mode = config.ModeBalanced
	if got := modeAction(cfg); got != config.ActionBlock {
		t.Fatalf("balanced enforce = %q, want block", got)
	}
}

func TestAnyKillSwitchSource(t *testing.T) {
	t.Parallel()

	if anyKillSwitchSource(nil) || anyKillSwitchSource(map[string]bool{"config": false}) {
		t.Fatal("inactive sources reported active")
	}
	if !anyKillSwitchSource(map[string]bool{"config": false, "api": true}) {
		t.Fatal("active source was ignored")
	}
}

func TestOnOff(t *testing.T) {
	t.Parallel()

	if onOff(true) != "enabled" || onOff(false) != "disabled" {
		t.Fatal("onOff mapping changed")
	}
}

func TestStatusListenersAndScannersFlags(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Listen = "127.0.0.1:0"
	cfg.ForwardProxy.Enabled = false
	cfg.WebSocketProxy.Enabled = true
	cfg.MetricsListen = ""
	cfg.KillSwitch.APIListen = ""
	cfg.ScanAPI.Listen = "127.0.0.1:1"
	cfg.ReverseProxy.Enabled = true
	cfg.ReverseProxy.Listen = "127.0.0.1:2"
	cfg.ReverseProxy.Profile = "sidecar"
	cfg.ResponseScanning.Enabled = false
	cfg.GitProtection.Enabled = true

	listeners := map[string]statusListener{}
	for _, l := range statusListeners(cfg) {
		listeners[l.Name] = l
	}
	if !listeners["fetch_proxy"].Enabled || listeners["forward_proxy"].Enabled {
		t.Fatalf("proxy listeners = %+v", listeners)
	}
	if !listeners["websocket_proxy"].Enabled || listeners["metrics"].Enabled || listeners["kill_switch_api"].Enabled {
		t.Fatalf("optional listeners = %+v", listeners)
	}
	if !listeners["scan_api"].Enabled || !listeners["reverse_proxy"].Enabled {
		t.Fatalf("api listeners = %+v", listeners)
	}
	if listeners["reverse_proxy"].Detail != "sidecar" {
		t.Fatalf("reverse proxy detail = %q", listeners["reverse_proxy"].Detail)
	}

	scanners := map[string]statusScanner{}
	for _, s := range statusScanners(cfg) {
		scanners[s.Name] = s
	}
	if scanners["ssrf"].Enabled {
		t.Fatal("nil Internal still reported configured SSRF as enabled")
	}
	if !scanners["core_ssrf"].Enabled || scanners["core_ssrf"].Action != config.ActionBlock {
		t.Fatalf("core SSRF = %+v", scanners["core_ssrf"])
	}
	if scanners["response_scanning"].Enabled {
		t.Fatal("disabled response scanning reported enabled")
	}
	if !scanners["git_protection"].Enabled || scanners["git_protection"].Action != config.ActionBlock {
		t.Fatalf("git protection = %+v", scanners["git_protection"])
	}
}
