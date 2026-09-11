// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func readA2ACardFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "a2a", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return body
}

// TestScanAgentCard_DriftDiscriminationFixtures measures the false-positive
// surface of Agent Card drift discrimination against realistic cards. A benign
// descriptive update is adopted and stays clean; an endpoint/structural change
// or a descriptive change that introduces a cue class blocks and names what
// changed. ScanAgentCards is disabled so the drift path alone is exercised - the
// field walker would independently block the injection/egress cards and mask
// which layer made the call.
func TestScanAgentCard_DriftDiscriminationFixtures(t *testing.T) {
	tests := []struct {
		name        string
		after       string
		wantClean   bool
		wantAdopted bool   // benign textual change adopted as new baseline
		wantReason  string // substring of the block reason (blocking cases only)
	}{
		{name: "benign description refine", after: "benign-desc-refine.json", wantClean: true, wantAdopted: true},
		{name: "benign skill description refine", after: "benign-skill-desc-refine.json", wantClean: true, wantAdopted: true},
		{name: "benign version bump", after: "benign-version-bump.json", wantClean: true, wantAdopted: false},
		{name: "block url swap", after: "block-url-swap.json", wantReason: "endpoint or structural change"},
		{name: "block auth scheme change", after: "block-auth-change.json", wantReason: "endpoint or structural change"},
		{name: "block new skill", after: "block-new-skill.json", wantReason: "endpoint or structural change"},
		{name: "block description injection cue", after: "block-desc-injection.json", wantReason: "agent-directive"},
		{name: "block skill egress cue", after: "block-skill-egress.json", wantReason: "egress-url"},
	}

	base := readA2ACardFixture(t, "base.json")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := enabledA2ACfg()
			cfg.ScanAgentCards = false // isolate the drift discriminator
			cfg.DetectCardDrift = true
			cfg.Action = config.ActionBlock
			baseline := NewCardBaseline(10)
			key := CardCacheKeyFromRequest("https://agent.vendor.example/.well-known/agent-card.json", "")

			seed := ScanAgentCard(context.Background(), base, testA2AScanner(t), baseline, key, cfg)
			if !seed.Clean || !seed.FirstSeen {
				t.Fatalf("seed baseline = clean:%v firstSeen:%v, want clean first-seen", seed.Clean, seed.FirstSeen)
			}

			after := readA2ACardFixture(t, tt.after)
			got := ScanAgentCard(context.Background(), after, testA2AScanner(t), baseline, key, cfg)

			if tt.wantClean {
				if !got.Clean {
					t.Fatalf("benign update blocked: reason=%q action=%q", got.Reason, got.Action)
				}
				if got.DriftAdopted != tt.wantAdopted {
					t.Fatalf("DriftAdopted = %v, want %v (reason=%q)", got.DriftAdopted, tt.wantAdopted, got.Reason)
				}
				// An adopted change records drift for observability; a no-op change
				// (version-only) records nothing.
				if got.DriftDetected != tt.wantAdopted {
					t.Fatalf("DriftDetected = %v, want %v", got.DriftDetected, tt.wantAdopted)
				}
				return
			}

			if got.Clean {
				t.Fatalf("update stayed clean, want block: %+v", got)
			}
			if got.Action != config.ActionBlock {
				t.Fatalf("block action = %q, want %q", got.Action, config.ActionBlock)
			}
			if got.DriftAdopted {
				t.Fatalf("a blocked change must not be adopted: %+v", got)
			}
			if !strings.Contains(got.Reason, tt.wantReason) {
				t.Fatalf("block reason = %q, want substring %q", got.Reason, tt.wantReason)
			}
			if !strings.Contains(got.Reason, "drift introduced") {
				t.Fatalf("block reason = %q, want it to name introduced drift", got.Reason)
			}
		})
	}
}
