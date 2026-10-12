// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
)

func TestServerDestinationGrantsReloadPreservesAndRevokes(t *testing.T) {
	s, _ := newTestServer(t, nil)
	grant := config.DestinationGrant{Protocol: "tcp", Host: "preview.vendor.example", Port: 8443}
	for _, tc := range []struct {
		name    string
		grants  []config.DestinationGrant
		allowed bool
	}{
		{"add", []config.DestinationGrant{grant}, true},
		{"unrelated preserves", []config.DestinationGrant{grant}, true},
		{"revoke", nil, false},
		{"unrelated stays revoked", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := s.proxy.CurrentConfig().Clone()
			next.DestinationGrants = tc.grants
			next.ExplainBlocks = new(!s.proxy.CurrentConfig().ExplainBlocksEnabled())
			if err := s.Reload(next); err != nil {
				t.Fatal(err)
			}
			sc := s.proxy.ScannerPtr().Load()
			if got := sc.IsDestinationGranted(destination.NetworkTCP, grant.Host, grant.Port); got != tc.allowed {
				t.Fatalf("serving scanner grants=%t, want %t", got, tc.allowed)
			}
		})
	}
	previous := s.proxy.CurrentConfig()
	invalid := previous.Clone()
	invalid.DestinationGrants = []config.DestinationGrant{{Protocol: "tcp", Host: "169.254.169.254", Port: 80}}
	if err := s.Reload(invalid); err == nil {
		t.Fatal("invalid reload accepted")
	}
	if s.proxy.CurrentConfig() != previous {
		t.Fatal("invalid reload replaced live policy")
	}
}

func TestDestinationGrantsReloadTrustExpansionContracts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		mode     string
		receipts bool
		rejected bool
	}{
		{"balanced", config.ModeBalanced, false, false},
		{"strict", config.ModeStrict, false, true},
		{"required receipts", config.ModeBalanced, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := config.Defaults()
			old.Mode, old.FlightRecorder.RequireReceipts = tc.mode, tc.receipts
			next := old.Clone()
			next.DestinationGrants = []config.DestinationGrant{{Protocol: "tcp", Host: "preview.vendor.example", Port: 8443}}
			warnings := config.ValidateReload(old, next)
			if reason := reloadDowngradeRejectReason(old, next, warnings); (reason != "") != tc.rejected {
				t.Fatalf("reject reason=%q, rejected=%t", reason, tc.rejected)
			}
			if fields := trustExpansionReloadFields(warnings); len(fields) != 1 || fields[0] != "destination_grants" {
				t.Fatalf("trust expansion fields=%v", fields)
			}
			if tc.rejected && !strings.Contains(rejectedDowngradeReloadDetail(old, next, warnings), "destination_grants") {
				t.Fatal("rejection does not name destination_grants")
			}
			if reason := reloadDowngradeRejectReason(next, old, config.ValidateReload(next, old)); reason != "" {
				t.Fatalf("grant removal rejected: %s", reason)
			}
		})
	}
}

func TestServerDestinationGrantsRejectedReloadAudited(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.New("json", "file", logPath, false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	s := &Server{logger: logger, opts: ServerOpts{ConfigFile: "policy.yaml"}}
	invalid := config.Defaults()
	invalid.DestinationGrants = []config.DestinationGrant{{Protocol: "tcp", Host: "169.254.169.254", Port: 80}}
	if err := s.Reload(invalid); err == nil {
		t.Fatal("invalid reload accepted")
	}
	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{configReloadAuditMethod, "destination_grants", "policy.yaml", "rejected: invalid config reload"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("audit log missing %q: %s", want, data)
		}
	}
}
