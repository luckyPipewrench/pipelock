// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestScan_EmptyLabelHostnameFailsClosed pins the verdict for a request
// hostname carrying an empty DNS label.
//
// The defect this replaces was a SPLIT verdict, not a missing one. The scan
// entry point hands the RAW hostname to the blocklist while handing the
// once-trimmed destination host to the allowlist, so "host.example.."
// evaded a blocklist entry for "host.example" and simultaneously SATISFIED a
// strict allowlist entry for it. Only the dialer's own failed lookup of the
// two-dot name kept the request off the network.
func TestScan_EmptyLabelHostnameFailsClosed(t *testing.T) {
	t.Run("blocklisted host cannot be evaded by an extra dot", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.vendor.example"}
		sc, err := New(cfg)
		if err != nil {
			t.Fatalf("scanner.New: %v", err)
		}

		// Control: the ordinary and single-root-dot spellings block on the
		// blocklist, which is what proves the list is live.
		for _, u := range []string{
			"https://blocked.vendor.example/x",
			"https://blocked.vendor.example./x",
		} {
			got := sc.Scan(context.Background(), u)
			if got.Allowed || got.Scanner != ScannerBlocklist {
				t.Fatalf("control %s: allowed=%v scanner=%s, want blocklist block", u, got.Allowed, got.Scanner)
			}
		}

		for _, u := range []string{
			"https://blocked.vendor.example../x",
			"https://blocked.vendor.example.../x",
			"https://BLOCKED.vendor.example../x",
		} {
			got := sc.Scan(context.Background(), u)
			if got.Allowed {
				t.Fatalf("%s was allowed; an empty-label spelling must not evade the blocklist", u)
			}
			if got.Scanner != ScannerParser || !strings.Contains(got.Reason, "invalid destination") {
				t.Fatalf("%s: scanner=%s reason=%q, want a parser invalid-destination block", u, got.Scanner, got.Reason)
			}
		}
	})

	t.Run("strict allowlist is not satisfied by an extra dot", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.Mode = config.ModeStrict
		cfg.APIAllowlist = []string{"api.vendor.example"}
		sc, err := New(cfg)
		if err != nil {
			t.Fatalf("scanner.New: %v", err)
		}

		// Control: the exact allowlisted host is permitted, so a refusal
		// below is the empty label and not a dead allowlist.
		if got := sc.Scan(context.Background(), "https://api.vendor.example/x"); !got.Allowed {
			t.Fatalf("control: allowlisted host blocked by %s: %s", got.Scanner, got.Reason)
		}

		got := sc.Scan(context.Background(), "https://api.vendor.example../x")
		if got.Allowed {
			t.Fatal("an empty-label host satisfied the strict allowlist")
		}
		if got.Scanner != ScannerParser {
			t.Fatalf("scanner=%s reason=%q, want a parser block", got.Scanner, got.Reason)
		}
	})
}
