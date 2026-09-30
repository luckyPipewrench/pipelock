// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// With redaction configured the body is scanned twice, once before redaction
// and once after. A finding the operator disabled is dropped by both passes,
// but it is one finding and must be recorded once, or the dropped-match metric
// and the dlp_warn evidence overcount it.
func TestScanRequestBody_DroppedFindingRecordedOnceAcrossRedactionPasses(t *testing.T) {
	t.Parallel()

	const name = "Acme Disabled Key"
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: name, Regex: `acmedis-[a-z]{24}`, Severity: "high"})
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatalf("scanner: %v", err)
	}
	t.Cleanup(sc.Close)

	body := `{"note":"acmedis-` + strings.Repeat("q", 24) + `"}`
	run := func(body string, matcher *redact.Matcher, suppressed bool) (int, []string) {
		var got []string
		disabled := []string{name}
		var suppress []config.SuppressEntry
		if suppressed {
			disabled = nil
			suppress = []config.SuppressEntry{{Rule: name, Path: "*"}}
		}
		_, result := scanRequestBody(context.Background(), BodyScanRequest{
			Body:            strings.NewReader(body),
			ContentType:     contentTypeJSON,
			Target:          "https://api.vendor.example/upload",
			MaxBytes:        len(body) * 2,
			Scanner:         sc,
			RedactMatcher:   matcher,
			DisablePatterns: disabled,
			Suppress:        suppress,
			OnDroppedDLP: func(m scanner.TextDLPMatch, reason string) {
				got = append(got, m.PatternName+"/"+reason)
			},
		})
		if !result.Clean {
			t.Fatalf("dropped body finding changed verdict: %+v", result)
		}
		return len(got), got
	}

	// Positive control: without redaction there is one pass and one record,
	// so the drop callback is reachable for this finding.
	if n, got := run(body, nil, false); n != 1 {
		t.Fatalf("single pass recorded %d drops, want 1: %v", n, got)
	}
	if n, got := run(body, redact.NewDefaultMatcher(), false); n != 1 {
		t.Fatalf("redaction passes recorded %d drops for one finding, want 1: %v", n, got)
	}
	// Each field starts its match at byte zero; offsets cannot identify values.
	twoFields := `{"first":"acmedis-` + strings.Repeat("q", 24) + `","second":"acmedis-` + strings.Repeat("r", 24) + `"}`
	for _, suppressed := range []bool{false, true} {
		for _, matcher := range []*redact.Matcher{nil, redact.NewDefaultMatcher()} {
			if n, got := run(body, matcher, suppressed); n != 1 {
				t.Fatalf("suppressed=%v single finding recorded %d drops, want 1: %v", suppressed, n, got)
			}

			if n, got := run(twoFields, matcher, suppressed); n != 2 {
				t.Fatalf("different fields recorded %d drops, want 2: %v", n, got)
			}
		}
	}
}

// Ordinary and provider-opaque scans share request drop accounting.
func TestBodyDLPDropsAcrossTextSets(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	const name = "Acme Disabled Key"
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: name, Regex: `acmedis-[a-z]{24}`, Severity: "high"})
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	first := "acmedis-" + strings.Repeat("q", 24)
	second := "acmedis-" + strings.Repeat("r", 24)
	var drops int
	callback := onceBodyDLPDrops(func(scanner.TextDLPMatch, string) { drops++ })
	disabled := bodyDLPDisabledSet([]string{name})
	scanBodyTextsForDLPWithAudience(context.Background(), sc, []string{first}, "", nil, disabled, false, callback, "", nil)
	scanProviderOpaqueTextsForDLPWithAudience(context.Background(), sc, []string{first, second}, "", nil, disabled, false, callback, "", nil)
	if drops != 2 {
		t.Fatalf("text sets recorded %d drops, want 2", drops)
	}
}
