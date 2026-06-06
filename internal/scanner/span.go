// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

// View labels name the exact scanner view that byte offsets index. Labels use
// a transform-stack scheme: "<stage>" or "<stage>:<provenance>". Consumers must
// slice the named view, not the raw input that produced it.
const (
	ViewForMatching     = "for_matching"
	ViewInvisibleSpaced = "for_matching:invisible_spaced"
	ViewLeetspeak       = "leetspeak:for_matching"
	ViewVowelFold       = "vowel_fold:for_matching"
	ViewBase64Decoded   = "for_matching:base64_decoded"
	ViewHexDecoded      = "for_matching:hex_decoded"
	ViewDLPNormalized   = "dlp_normalized"
)

// MatchSpan is retained scanner evidence metadata for a pattern match.
// It carries coordinates and provenance only; it never carries matched bytes.
type MatchSpan struct {
	ByteStart     int
	ByteEnd       int
	ViewLabel     string
	RuleID        string
	Bundle        string
	BundleVersion string
}

func newMatchSpan(start, end int, viewLabel, ruleID, bundle, bundleVersion string) MatchSpan {
	if start < 0 || end < start || viewLabel == "" || ruleID == "" {
		return MatchSpan{}
	}
	return MatchSpan{
		ByteStart:     start,
		ByteEnd:       end,
		ViewLabel:     viewLabel,
		RuleID:        ruleID,
		Bundle:        bundle,
		BundleVersion: bundleVersion,
	}
}

// Valid reports whether the span has coordinates, a view label, and rule ID.
func (s MatchSpan) Valid() bool {
	return s.ByteStart >= 0 && s.ByteEnd >= s.ByteStart && s.ViewLabel != "" && s.RuleID != ""
}

func dlpEncodedViewLabel(encoding string) string {
	return dlpViewLabel(encoding)
}

func dlpViewLabel(provenance string) string {
	return spanViewLabel(ViewDLPNormalized, provenance)
}

func lowerViewLabel(base string) string {
	return spanViewLabel("lowercase", base)
}

func canonicalLowerViewLabel(base string) string {
	return spanViewLabel("canonicalized", lowerViewLabel(base))
}

func vowelFoldViewLabel(base string) string {
	return spanViewLabel("vowel_fold", base)
}

func spanViewLabel(stage string, provenance ...string) string {
	label := stage
	for _, p := range provenance {
		if p == "" {
			continue
		}
		label += ":" + p
	}
	return label
}

func copySpans(spans []MatchSpan) []MatchSpan {
	if len(spans) == 0 {
		return nil
	}
	out := make([]MatchSpan, len(spans))
	copy(out, spans)
	return out
}

func (p *compiledPattern) matchSpan(text string) (start, end int, ok bool) {
	if p.validate == nil {
		loc := p.re.FindStringIndex(text)
		if loc == nil {
			return 0, 0, false
		}
		return loc[0], loc[1], true
	}
	for _, loc := range p.re.FindAllStringIndex(text, -1) {
		if p.validate(text[loc[0]:loc[1]]) {
			return loc[0], loc[1], true
		}
	}
	return 0, 0, false
}
