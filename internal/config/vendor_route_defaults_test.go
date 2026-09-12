// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestVendorRouteDefaults pins BOTH directions of the shipped document-sharing
// route exclusions. The allow cases prove an operator sent an ordinary Google
// Docs, Sheets, Slides, Forms or Drive link is not blocked on a fresh install.
// The block cases are the ones that matter more: each shipped entry binds ONE
// host to ONE literal path prefix, so a different route on the same host, the
// same route shape on another host, and a lookalike host that merely carries
// the vendor host as a leading label must all still be blocked. Removing any
// entry makes its allow case fail with the real entropy reason, so neither
// direction is vacuous.
func TestVendorRouteDefaults(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	const id = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"
	const formID = "1FAIpQLSf1xQ2mGh7kVJd0pWqYxNzR3TbLcMnOpQrStUvWxYz012345"

	cases := []struct {
		name      string
		url       string
		wantAllow bool
	}{
		{"docs document", "https://docs.google.com/document/d/" + id + "/edit", true},
		{"docs spreadsheet", "https://docs.google.com/spreadsheets/d/" + id + "/edit", true},
		{"docs presentation", "https://docs.google.com/presentation/d/" + id + "/edit", true},
		{"docs form", "https://docs.google.com/forms/d/e/" + formID + "/viewform", true},
		{"drive file", "https://drive.google.com/file/d/" + id + "/view", true},

		// Must STILL block: same host, route not on the list.
		{"same host other route", "https://docs.google.com/random/" + id, false},
		// Must STILL block: listed route shape on an unlisted host.
		{"route on evil host", "https://evil.test/document/d/" + id, false},
		// Must STILL block: lookalike host with the vendor host as a prefix label.
		{"lookalike host", "https://docs.google.com.evil.test/document/d/" + id, false},
		// Must STILL block: listed prefix but the blob is elsewhere in the path.
		{"prefix then unrelated blob segment", "https://docs.google.com/random/d/" + id, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := sc.Scan(context.Background(), tc.url)
			if res.Allowed != tc.wantAllow {
				t.Fatalf("allowed=%v want %v (reason=%q scanner=%q)", res.Allowed, tc.wantAllow, res.Reason, res.Scanner)
			}
		})
	}
}

// TestVendorRouteDefaultsReachAYAMLBackedConfig covers the state every real
// operator occupies and the original tests missed: a config LOADED FROM YAML.
//
// Load() decodes into an empty config and then calls ApplyDefaults, so a value
// present only in Defaults() reaches the no-config CLI path and no deployment.
// The first version of this change had exactly that shape: the five routes were
// in Defaults(), the defaults hash moved, and a configured operator still got
// the block. Asserting through Load is what makes the default real.
func TestVendorRouteDefaultsReachAYAMLBackedConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	// A minimal config that says nothing about path_entropy_exclusions.
	if err := os.WriteFile(path, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Compare CONTENT, not just the count. A count-only check passes for a
	// wrong set of the same length, which would report the enforcement path as
	// working while a deployment inherited routes nobody shipped.
	want := config.Defaults().FetchProxy.Monitoring.PathEntropyExclusions
	got := cfg.FetchProxy.Monitoring.PathEntropyExclusions
	if len(got) != len(want) {
		t.Fatalf("a YAML-backed config inherited %d shipped routes, want %d; the default never reaches a real deployment: %+v",
			len(got), len(want), got)
	}
	for i := range want {
		if got[i].Host != want[i].Host || got[i].PathPrefix != want[i].PathPrefix {
			t.Fatalf("inherited route %d = %s%s, want %s%s", i, got[i].Host, got[i].PathPrefix, want[i].Host, want[i].PathPrefix)
		}
	}

	// An explicitly empty list is a deliberate opt-out and must be preserved,
	// not silently refilled with the shipped set.
	optOut := filepath.Join(dir, "optout.yaml")
	body := "mode: balanced\nfetch_proxy:\n  monitoring:\n    path_entropy_exclusions: []\n"
	if err := os.WriteFile(optOut, []byte(body), 0o600); err != nil {
		t.Fatalf("write opt-out config: %v", err)
	}
	cfg2, err := config.Load(optOut)
	if err != nil {
		t.Fatalf("config.Load(opt-out): %v", err)
	}
	if n := len(cfg2.FetchProxy.Monitoring.PathEntropyExclusions); n != 0 {
		t.Fatalf("an explicit empty list was refilled with %d shipped routes; the operator's opt-out was overridden", n)
	}
}
