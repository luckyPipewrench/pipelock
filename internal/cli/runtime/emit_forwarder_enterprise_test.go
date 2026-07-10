//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestBuildEmitSinksCreatesDormantEnterpriseForwarder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"203.0.113.10"}}
	cfg.Emit.Forwarder = config.ForwarderConfig{
		URL: "https://api.vendor.example/events", DestinationAllowlist: []string{"api.vendor.example"},
		SpoolFile: dir + "/spool", CursorFile: dir + "/cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks: %v", err)
	}
	if len(sinks) != 1 {
		t.Fatalf("len(sinks) = %d, want 1", len(sinks))
	}
	activateEmitSinks(sinks)
	if err := sinks[0].Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestBuildEmitSinksForwarderKeepsSSRFFloorWhenMainScannerDisablesIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"127.0.0.1"}}
	cfg.Emit.Forwarder = config.ForwarderConfig{
		URL: "https://api.vendor.example/events", DestinationAllowlist: []string{"api.vendor.example"},
		SpoolFile: dir + "/spool", CursorFile: dir + "/cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	_, err := BuildEmitSinks(cfg)
	if err == nil || !strings.Contains(err.Error(), "internal IP") {
		t.Fatalf("BuildEmitSinks error = %v, want internal-IP denial", err)
	}
}
