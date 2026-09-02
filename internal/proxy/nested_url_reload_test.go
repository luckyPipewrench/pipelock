// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// nestedURLReloadConfig is a config whose only interesting property is whether
// nested query destinations are evaluated. SSRF stays literal-only so the test
// needs no resolver, and the metadata address is not IP-allowlisted.
func nestedURLReloadConfig(t *testing.T, enabled *bool) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = nil
	cfg.APIAllowlist = nil
	cfg.DLP.Patterns = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
	cfg.FetchProxy.Monitoring.MaxURLLength = 4096
	cfg.FetchProxy.Monitoring.ScanNestedURLs = enabled
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}
	return cfg
}

// nestedURLReloadProxy builds a proxy whose active scanner starts from cfg.
func nestedURLReloadProxy(t *testing.T, cfg *config.Config) *Proxy {
	t.Helper()
	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

// scanThroughLiveScanner scans a nested metadata URL through whatever scanner
// the proxy is CURRENTLY serving from. Reading p.scannerPtr rather than a
// locally built scanner is the whole point: a reload that swaps config without
// swapping the scanner would pass a test that built its own.
func scanThroughLiveScanner(t *testing.T, p *Proxy) scanner.Result {
	t.Helper()
	sc := p.scannerPtr.Load()
	if sc == nil {
		t.Fatal("proxy has no active scanner")
	}
	raw := "https://mirror.fixture.example.com/pkg?target=" +
		url.QueryEscape("http://169.254.169.254/latest/meta-data/")
	return sc.Scan(context.Background(), raw)
}

// reloadInto swaps the proxy onto a config with the given setting, through the
// production Reload path, and returns the verdict the live scanner then gives.
func reloadInto(t *testing.T, p *Proxy, enabled *bool) scanner.Result {
	t.Helper()
	cfg := nestedURLReloadConfig(t, enabled)
	if !p.Reload(cfg, scanner.MustNew(cfg)) {
		t.Fatal("Reload reported failure")
	}
	return scanThroughLiveScanner(t, p)
}

// TestProxy_ReloadScanNestedURLs_MovesEnforcementBothWays drives
// fetch_proxy.monitoring.scan_nested_urls through the RUNNING reload path and
// asserts the serving scanner reflects each change.
//
// A security boolean needs reload-with-change in both directions plus
// reload-without-change: an operator who disables a control to get past an
// incident and then removes the override must not keep the relaxed posture
// until the process restarts. Constructing a fresh Config per assertion cannot
// see that failure, because it never asks what the running proxy is serving.
func TestProxy_ReloadScanNestedURLs_MovesEnforcementBothWays(t *testing.T) {
	t.Parallel()

	enabled, disabled := true, false

	// Default (omitted) evaluates nested destinations.
	p := nestedURLReloadProxy(t, nestedURLReloadConfig(t, nil))
	if got := scanThroughLiveScanner(t, p); got.Allowed {
		t.Fatal("omitted scan_nested_urls did not evaluate the nested destination")
	}

	// Disable through reload: the running scanner must stop evaluating.
	if got := reloadInto(t, p, &disabled); !got.Allowed {
		t.Fatalf("reload to false still blocked: scanner=%s reason=%q", got.Scanner, got.Reason)
	}

	// Reload with NO change: the relaxed posture must persist, not oscillate.
	if got := reloadInto(t, p, &disabled); !got.Allowed {
		t.Fatalf("unchanged reload flipped enforcement back on: reason=%q", got.Reason)
	}

	// Removing the override must restore the secure default. Reloading to
	// explicit true would still pass if nil kept the previous false value.
	if got := reloadInto(t, p, nil); got.Allowed {
		t.Fatal("removing scan_nested_urls override left nested scanning disabled")
	}

	// Re-enable through reload: enforcement must return without a restart.
	got := reloadInto(t, p, &enabled)
	if got.Allowed {
		t.Fatal("reload back to true left the relaxed scanner installed")
	}
	// The destination is a metadata address, so any of the three SSRF labels is
	// a correct attribution. Pinning two of them would fail on a legitimate
	// verdict rather than on a regression.
	switch got.Scanner {
	case scanner.ScannerSSRF, scanner.ScannerSSRFMetadata, scanner.ScannerCoreSSRF:
	default:
		t.Fatalf("re-enabled block came from %q, want an SSRF scanner", got.Scanner)
	}
}
