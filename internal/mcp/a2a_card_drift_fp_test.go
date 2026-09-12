// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func readA2ACardFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Clean(filepath.Join("testdata", "a2a", name)))
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

func TestScanAgentCard_DriftDiscriminationAcceptsOrdinaryDescriptionURLs(t *testing.T) {
	updates := []string{
		"Searches the documentation corpus. See https://docs.vendor.example/guide for examples.",
		"Searches the documentation corpus. Read https://support.vendor.example/faq before opening a ticket.",
		"Searches the documentation corpus. The API reference is https://api.vendor.example/reference.",
	}
	base := readA2ACardFixture(t, "base.json")
	key := CardCacheKeyFromRequest("https://agent.vendor.example/.well-known/agent-card.json", "")
	for _, update := range updates {
		t.Run(update, func(t *testing.T) {
			cfg := enabledA2ACfg()
			cfg.ScanAgentCards = false
			cfg.DetectCardDrift = true
			cfg.Action = config.ActionBlock
			baseline := NewCardBaseline(2)
			if got := ScanAgentCard(context.Background(), base, testA2AScanner(t), baseline, key, cfg); !got.Clean || !got.FirstSeen {
				t.Fatalf("seed baseline = %+v, want clean first-seen", got)
			}
			updated := strings.Replace(string(base), "Searches the documentation corpus.", update, 1)
			got := ScanAgentCard(context.Background(), []byte(updated), testA2AScanner(t), baseline, key, cfg)
			if !got.Clean || !got.DriftAdopted {
				t.Fatalf("ordinary documentation URL update = %+v, want clean adopted drift", got)
			}
		})
	}
}

func TestCardStructuralDigest_DuplicateSkillIDsIgnoreOrder(t *testing.T) {
	first := A2AAgentCard{Skills: []A2ASkill{
		{ID: "", Name: "Search", Description: "Searches the documentation.", InputSchema: json.RawMessage(`{"type":"string"}`)},
		{ID: "", Name: "Summarize", Description: "Summarizes the selected text.", InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}}}`)},
	}}
	second := A2AAgentCard{Skills: []A2ASkill{first.Skills[1], first.Skills[0]}}
	if got, want := cardStructuralDigest(second), cardStructuralDigest(first); got != want {
		t.Fatalf("same empty-ID skills in a different order changed structural digest: got %s want %s", got, want)
	}
}

func TestCardStructuralDigest_DescriptiveUnicodeNormalizationIsAdopted(t *testing.T) {
	first := A2AAgentCard{
		Name:        "Café Search",
		Description: "Searches the café documentation.",
		URL:         "https://agent.vendor.example/a2a",
		Skills:      []A2ASkill{{ID: "search", Name: "Café search", Description: "Searches café articles."}},
	}
	second := first
	second.Name = "Cafe\u0301 Search"
	second.Description = "Searches the cafe\u0301 documentation."
	second.Skills = append([]A2ASkill(nil), first.Skills...)
	second.Skills[0].Name = "Cafe\u0301 search"
	second.Skills[0].Description = "Searches cafe\u0301 articles."
	if got, want := cardStructuralDigest(second), cardStructuralDigest(first); got != want {
		t.Fatalf("descriptive Unicode normalization changed structural digest: got %s want %s", got, want)
	}

	baseline := NewCardBaseline(2)
	key := CardCacheKeyFromRequest("https://agent.vendor.example/.well-known/agent-card.json", "")
	if out := baseline.Check(key, cardStructuralDigest(first), cardDescriptiveDigest(first), cardDescriptiveText(first), nil); !out.firstSeen {
		t.Fatalf("seed outcome = %+v, want first-seen", out)
	}
	if out := baseline.Check(key, cardStructuralDigest(second), cardDescriptiveDigest(second), cardDescriptiveText(second), nil); !out.adopted || out.block {
		t.Fatalf("Unicode normalization update = %+v, want adopted non-blocking drift", out)
	}
}

func TestCardBaseline_ConcurrentDescriptiveAdoption(t *testing.T) {
	card := A2AAgentCard{
		Name:        "Vendor Agent",
		Description: "Searches vendor documentation.",
		URL:         "https://agent.vendor.example/a2a",
		Skills:      []A2ASkill{{ID: "search", Name: "Search", Description: "Searches the documentation corpus."}},
	}
	baseline := NewCardBaseline(2)
	key := CardCacheKeyFromRequest("https://agent.vendor.example/.well-known/agent-card.json", "Bearer tenant-one")
	structural := cardStructuralDigest(card)
	if out := baseline.Check(key, structural, cardDescriptiveDigest(card), cardDescriptiveText(card), nil); !out.firstSeen {
		t.Fatalf("seed outcome = %+v, want first-seen", out)
	}

	descriptions := []string{
		"Searches vendor documentation and returns relevant passages.",
		"Searches vendor documentation with source links.",
		"Searches vendor documentation and includes headings.",
		"Searches vendor documentation for the selected product.",
	}
	errs := make(chan cardDriftOutcome, len(descriptions))
	var wg sync.WaitGroup
	for _, description := range descriptions {
		wg.Go(func() {
			updated := card
			updated.Description = description
			out := baseline.Check(key, structural, cardDescriptiveDigest(updated), cardDescriptiveText(updated), nil)
			// Every description here is distinct from the seed, so each call
			// MUST report a change and adopt it. Accepting a zero outcome as
			// well would let a regression that silently drops every update
			// pass this test.
			if !out.changed || !out.adopted || out.block || out.structuralChange || out.capacityExceeded {
				errs <- out
			}
		})
	}
	wg.Wait()
	close(errs)
	for out := range errs {
		t.Fatalf("benign concurrent adoption = %+v, want changed+adopted without blocking", out)
	}
}
