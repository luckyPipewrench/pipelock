// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// awsJoinedTail is a synthetic 16-character key tail, split so no literal key
// sits in the source (gosec G101 and the self-scan).
var awsJoinedTail = "IOSFODNN" + "7EXAMPLE"

func awsJoinedSpaced(s string, n int) string {
	var parts []string
	for len(s) > n {
		parts = append(parts, s[:n])
		s = s[n:]
	}
	return strings.Join(append(parts, s), " ")
}

// TestAWSAccessID_JoinedEnglishIsClean covers the false-positive class where
// the whitespace-joined view fuses English words into a key-shaped run, on the
// configurable pattern layer, the immutable core floor, and the inbound entry.
func TestAWSAccessID_JoinedEnglishIsClean(t *testing.T) {
	t.Parallel()
	s := MustNew(testConfig())
	ctx := context.Background()

	texts := []string{
		"hide_canvas: Add random noise to canvas operations to prevent fingerprinting",
		"Add random noise to canvas operations to prevent fingerprinting across Asian regional markets",
		"Add random noise to canvas operations to prevent fingerprinting Asia Pacific region deployment operations",
		"We call CANVAS OPERATIONS TO PREVENT FINGERPRINTING here",
		"Asia Pacific region deployment operations",
		"Southeast Asia region planning notes by random OCR context",
		"Use Aida operations for the data team every quarter",
		"the technician vacuumed out the water",
		"Manage AGPA-free planning: organize agpas operations for teams",
		"Reload the Alaska routes operations plan for the winter season",
		"Send an ansible playbook: Ansible plays run tasks across all hosts",
		"Prefer Aroa Ropes outdoor operations catalog entries this season",
		"a3t is a lowercase word start: a3trial versions expire quickly for users",
	}
	for _, text := range texts {
		if r := s.ScanTextForDLP(ctx, text); !r.Clean {
			t.Errorf("ScanTextForDLP flagged English %q: %+v", text, r.Matches)
		}
		if r := s.ScanTextForDLPInbound(ctx, text); !r.Clean {
			t.Errorf("ScanTextForDLPInbound flagged English %q: %+v", text, r.Matches)
		}
		if m := s.scanCoreDLP(text); len(m) != 0 {
			t.Errorf("core floor flagged English %q: %+v", text, m)
		}
		if m := coreWhitespaceMatches(s, text); len(m) != 0 {
			t.Errorf("core whitespace view flagged English %q: %+v", text, m)
		}
	}
}

// coreWhitespaceMatches drives the core whitespace view the way scanCoreDLP does.
func coreWhitespaceMatches(s *Scanner, text string) []TextDLPMatch {
	cleaned := normalize.ForDLP(text)
	compacted, offsets := compactTextDLPWhitespaceWithOffsets(cleaned)
	if compacted == cleaned {
		return nil
	}
	return s.matchCoreDLPWhitespaceView(compacted, cleaned, offsets)
}

func TestAWSAccessID_JoinedRealKeysStillBlock(t *testing.T) {
	t.Parallel()
	s := MustNew(testConfig())
	ctx := context.Background()

	prefixes := []string{"AKIA", "A3T", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA"}
	for _, prefix := range prefixes {
		key := prefix + awsJoinedTail
		cases := map[string]string{
			"contiguous":         key,
			"single spaces":      strings.Join(strings.Split(key, ""), " "),
			"groups of four":     awsJoinedSpaced(key, 4),
			"prefix apart":       prefix + " " + awsJoinedTail,
			"newline split":      prefix + "\n" + awsJoinedTail,
			"zero width split":   prefix + "\u200b" + awsJoinedTail[:8] + "\u200d" + awsJoinedTail[8:],
			"quoted spaced":      `"` + awsJoinedSpaced(key, 5) + `"`,
			"assignment spaced":  "aws_access_key_id=" + awsJoinedSpaced(key, 5),
			"leading decoy":      "canvas operations to prevent fingerprinting " + awsJoinedSpaced(key, 5),
			"decoy other case":   "x" + awsJoinedSpaced(key, 5),
			"digit before":       "7" + awsJoinedSpaced(key, 5),
			"trailing prose":     awsJoinedSpaced(key, 5) + " and then more words follow",
			"decoy prefix inner": "canvas " + awsJoinedSpaced(key, 5),
		}
		for name, text := range cases {
			if r := s.ScanTextForDLP(ctx, text); r.Clean {
				t.Errorf("%s/%s: real key not detected: %q", prefix, name, text)
			}
			if m := s.scanCoreDLP(text); len(m) == 0 {
				t.Errorf("%s/%s: core floor missed real key: %q", prefix, name, text)
			}
		}
	}

	// Lowercased keys: contiguous and spaced are detected for the credential
	// prefixes (unchanged behavior).
	for _, prefix := range []string{"AKIA", "ASIA"} {
		key := strings.ToLower(prefix + awsJoinedTail)
		for name, text := range map[string]string{
			"contiguous": key,
			"spaced":     awsJoinedSpaced(key, 4),
			"assignment": "key=" + awsJoinedSpaced(key, 4),
		} {
			if r := s.ScanTextForDLP(ctx, text); r.Clean {
				t.Errorf("lowercase %s/%s not detected: %q", prefix, name, text)
			}
		}
	}
}

// TestAWSAccessID_JoinedKnownNarrowing pins the one accepted narrowing: a
// lowercase or uppercase key that is split by whitespace AND glued to a
// preceding letter of the same case is treated as a word, like "canvas".
func TestAWSAccessID_JoinedKnownNarrowing(t *testing.T) {
	t.Parallel()
	s := MustNew(testConfig())
	text := "x" + awsJoinedSpaced(strings.ToLower("AKIA"+awsJoinedTail), 4)
	if r := s.ScanTextForDLP(context.Background(), text); !r.Clean {
		t.Fatalf("documented narrowing changed; update the docs and report: %+v", r.Matches)
	}
}

// TestAWSAccessID_JoinedKnownResidual pins the class this rule cannot remove
// without dropping real-key evasions: an all-uppercase or all-lowercase run of
// words that STARTS at a word beginning with AKIA or ASIA (or, uppercase only,
// another prefix) and is at least 20 letters long. Such a run is byte-for-byte
// what a whitespace-split key of that case looks like.
func TestAWSAccessID_JoinedKnownResidual(t *testing.T) {
	t.Parallel()
	s := MustNew(testConfig())
	for _, text := range []string{
		"ASIA PACIFIC REGION DEPLOYMENT",
		"asia pacific region deployment",
	} {
		if r := s.ScanTextForDLP(context.Background(), text); r.Clean {
			t.Errorf("residual class changed for %q; update docs and report", text)
		}
	}
}

func TestValidateAWSAccessIDJoined(t *testing.T) {
	t.Parallel()
	key := "AKIA" + awsJoinedTail
	identity := func(n int) []int {
		o := make([]int, n)
		for i := range o {
			o[i] = i
		}
		return o
	}
	if !validateAWSAccessIDJoined(key, -1, 5, key, identity(len(key))) {
		t.Error("invalid range must stay fail-closed")
	}
	if !validateAWSAccessIDJoined(key, 0, len(key), key, identity(2)) {
		t.Error("short offsets must stay fail-closed")
	}
	if !validateAWSAccessIDJoined(key, 0, len(key), key, identity(len(key))) {
		t.Error("contiguous key must validate")
	}
	if validateAWSAccessIDJoined("AKIA!"+awsJoinedTail, 0, 21, "AKIA!"+awsJoinedTail, identity(21)) {
		t.Error("non-alphanumeric window must not validate")
	}
	if validateAWSAccessIDJoined("ANVAsoperationstopreventfingerprinting", 0, 38, "cANVAs operations to prevent fingerprinting", identity(38)) {
		t.Error("mixed-case window must not validate")
	}
	if builtinDLPJoinedValidatorForRegex(`unrelated`) != nil {
		t.Error("only the AWS regex carries a joined validator")
	}
	if !awsJoinedStartAllowed("abc", 99, 'A') || !awsJoinedStartAllowed("abc", 0, 'A') {
		t.Error("out-of-range and zero offsets are allowed")
	}
	if !config.IsCoreDLPPatternName(patternNameAWSAccessID) {
		t.Error("AWS Access ID must remain in the core floor")
	}
}

// TestJoinedViewNonAWSPatternUnchanged proves patterns without a joined
// validator behave as before in the whitespace view.
func TestJoinedViewNonAWSPatternUnchanged(t *testing.T) {
	t.Parallel()
	s := MustNew(testConfig())
	key := testAnthropicPrefix + strings.Repeat("A", 20)
	if r := s.ScanTextForDLP(context.Background(), awsJoinedSpaced(key, 5)); r.Clean {
		t.Fatal("spaced non-AWS key must still be detected in the joined view")
	}
}
