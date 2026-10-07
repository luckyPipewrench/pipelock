// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestScanURLCoreFloor pins the standalone core floor check: it finds a core
// credential that the full scan never reached because an earlier stage refused
// the URL, keeps the SigV4 presigned-URL carve-out, and passes benign URLs.
func TestScanURLCoreFloor(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	key := "AKIA" + "IOSFODNN7EXAMPLE"

	blocked := "https://blocked.example/x?token=" + key
	if full := sc.Scan(context.Background(), blocked); full.Allowed || IsCoreCriticalResult(full) {
		t.Fatalf("control: the blocklist must stop the full scan before the core floor, got %+v", full)
	}
	cases := []struct {
		name, url string
		allowed   bool
	}{
		{"core behind blocklist", blocked, false},
		{"core in path", "https://api.vendor.example/" + key, false},
		{"unparseable", "https://api.vendor.example/%zz?token=" + key, false},
		{"presigned URL", buildSigV4URL(t, fakeAKIAExample, "3600", ""), true},
		{"benign", "https://blocked.example/x?q=hello", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sc.ScanURLCoreFloor(tc.url)
			if got.Allowed != tc.allowed {
				t.Fatalf("Allowed = %v, want %v: %+v", got.Allowed, tc.allowed, got)
			}
			if !tc.allowed && got.Scanner != ScannerCoreDLP {
				t.Fatalf("Scanner = %q, want %q", got.Scanner, ScannerCoreDLP)
			}
		})
	}
}
