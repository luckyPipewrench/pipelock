// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestReloadDowngradeRejectReason_BlocklistRemoval drives the real refusal
// decision. Emptying the blocklist on reload is refused where the running
// config forbids downgrades and applied, with its warning, where it does not.
func TestReloadDowngradeRejectReason_BlocklistRemoval(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		configure  func(*config.Config)
		wantReason string
	}{
		{"required receipts refuses", func(c *config.Config) { c.FlightRecorder.RequireReceipts = true }, "flight_recorder.require_receipts"},
		{"strict refuses", func(c *config.Config) { c.Mode = config.ModeStrict }, "strict mode"},
		{"plain balanced applies", func(*config.Config) {}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			old := config.Defaults()
			tc.configure(old)
			if len(old.FetchProxy.Monitoring.Blocklist) == 0 {
				t.Fatal("defaults ship no blocklist; nothing to remove")
			}
			updated := old.Clone()
			updated.FetchProxy.Monitoring.Blocklist = []string{}
			warnings := config.ValidateReload(old, updated)
			reason := reloadDowngradeRejectReason(old, updated, warnings)
			if tc.wantReason == "" {
				if reason != "" {
					t.Fatalf("balanced reload refused: %q", reason)
				}
				return
			}
			if !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("reject reason = %q, want it to contain %q", reason, tc.wantReason)
			}
		})
	}
}
