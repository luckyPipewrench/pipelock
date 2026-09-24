// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"
)

// awsTestKeyBody is sixteen access-key characters assembled at runtime so no
// credential-shaped literal sits in source.
func awsTestKeyBody() string {
	return strings.Join([]string{"QR2S", "TUVW", "XYZ2", "3456"}, "")
}

// joinedProse builds the whitespace-collapsed form of a sentence at runtime,
// so the diff self-scan (which has no validator) does not flag the fixture.
func joinedProse(words ...string) string {
	return strings.Join(words, "")
}

func hasAWSAccessIDMatch(result TextDLPResult) bool {
	for _, match := range result.Matches {
		if match.PatternName == patternNameAWSAccessID {
			return true
		}
	}
	return false
}

// Ordinary prose that the whitespace-collapsed view joins into a lowercase run
// behind an IAM resource prefix is not an access key on any surface.
func TestScanTextForDLP_AWSResourcePrefixProseIsNotAccessKey(t *testing.T) {
	t.Parallel()

	s := MustNew(testConfig())
	ctx := context.Background()

	for _, tt := range []struct {
		name string
		text string
	}{
		{
			// "technician vacuumed" collapses to "...anvacuumed...", an ANVA run.
			name: "ANVA across a word boundary",
			text: "The technician then vacuumed out the water from the fixture and flushed it again.",
		},
		{
			name: "AROA across a word boundary",
			text: "Here is a roadmap for the entire quarter ahead of us.",
		},
		{
			name: "AIDA at a word start",
			text: "Aida performed the overture tonight again for the crowd.",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if result := s.ScanTextForDLP(ctx, tt.text); hasAWSAccessIDMatch(result) {
				t.Fatalf("outbound prose matched AWS Access ID: %+v", result.Matches)
			}
			if result := s.ScanTextForDLPInbound(ctx, tt.text); hasAWSAccessIDMatch(result) {
				t.Fatalf("inbound prose matched AWS Access ID: %+v", result.Matches)
			}
		})
	}
}

// Every disguise of a real access key still matches: the case-folding and the
// whitespace view exist to catch exactly these, and a real key always carries
// an AKIA or ASIA prefix.
func TestScanTextForDLP_AWSAccessKeyDisguisesStillMatch(t *testing.T) {
	t.Parallel()

	s := MustNew(testConfig())
	ctx := context.Background()
	body := awsTestKeyBody()
	lower := strings.ToLower(body)
	spacedLower := strings.Join([]string{"akia", lower[0:4], lower[4:8], lower[8:12], lower[12:16]}, " ")

	for _, tt := range []struct {
		name string
		text string
	}{
		{name: "uppercase contiguous AKIA", text: "value " + "AKIA" + body + " end"},
		{name: "lowercase contiguous AKIA", text: "value " + "akia" + lower + " end"},
		{name: "lowercase spaced AKIA", text: "value " + spacedLower + " end"},
		{name: "lowercase spaced ASIA", text: "value " + strings.Replace(spacedLower, "akia", "asia", 1) + " end"},
		{
			// A resource-prefix prose run in front of the key must not hide it.
			name: "decoy resource-prefix prose before lowercase spaced key",
			text: "the technician vacuumed out " + spacedLower,
		},
		{
			// Uppercase resource identifiers keep today's behavior.
			name: "uppercase contiguous AIDA identifier",
			text: "value " + "AIDA" + body + " end",
		},
		{
			name: "uppercase spaced AIDA identifier",
			text: "value " + strings.Join([]string{"AIDA", body[0:4], body[4:8], body[8:12], body[12:16]}, " ") + " end",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if result := s.ScanTextForDLP(ctx, tt.text); !hasAWSAccessIDMatch(result) {
				t.Fatalf("expected AWS Access ID match, got %+v", result.Matches)
			}
		})
	}
}

func TestValidateAWSAccessIDCandidate(t *testing.T) {
	t.Parallel()

	body := awsTestKeyBody()
	for _, tt := range []struct {
		name      string
		candidate string
		want      bool
	}{
		{name: "uppercase AKIA", candidate: "AKIA" + body, want: true},
		{name: "uppercase resource prefix", candidate: "ANVA" + body, want: true},
		{name: "lowercase AKIA", candidate: "akia" + strings.ToLower(body), want: true},
		{name: "mixed case ASIA", candidate: "Asia" + strings.ToLower(body), want: true},
		{name: "lowercase resource prefix prose", candidate: joinedProse("an", "vacuumed", "out", "the", "water"), want: false},
		{name: "mixed case resource prefix prose", candidate: joinedProse("Aida", "performed", "the", "overture"), want: false},
		{name: "credential run embedded after prose", candidate: "anvacuumed" + "akia" + strings.ToLower(body), want: true},
		{name: "genuine uppercase id embedded after prose", candidate: "anvacuumed" + "AIDA" + body, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := validateAWSAccessIDCandidate(tt.candidate); got != tt.want {
				t.Fatalf("validateAWSAccessIDCandidate(%q) = %v, want %v", tt.candidate, got, tt.want)
			}
		})
	}
}

func TestBuiltinDLPValidatorForRegex(t *testing.T) {
	t.Parallel()

	if builtinDLPValidatorForRegex("AKIA[A-Z0-9]{16}") != nil {
		t.Fatal("a regex other than the built-in AWS Access ID regex must carry no built-in validator")
	}
	fn := builtinDLPValidatorForRegex(strictAWSAccessIDRe.String())
	if fn == nil || fn(joinedProse("an", "vacuumed", "out", "the", "water")) {
		t.Fatal("the built-in AWS Access ID regex must carry the resource-prefix prose validator")
	}
}
