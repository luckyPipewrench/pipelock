// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"strings"
	"testing"
)

func TestHTMLEntityDecodeV5Scalars(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ input, want string }{
		{"plain", "plain"},
		{"&nGt;&nLt;&NotEqualTilde;", "\u226b\u20d2\u226a\u20d2\u2242\u0338"},
		{"&fjlig;&ThickSpace;&caps;&race;&acE;&bne;", "fj\u205f\u200a\u2229\ufe00\u223d\u0331\u223e\u0333=\u20e5"},
		{"&amp &lt &notit; &notin; &amp=tail", "& < \u00acit; \u2209 &=tail"},
		{"&amp;&nGt;&amp;NotEqualTilde;", "&\u226b\u20d2\u2242\u0338"},
		{"&CounterClockwiseContourIntegral;", "\u2233"},
		{"&frac12;&frac12x", "\u00bd\u00bdx"},
		{"&" + strings.Repeat("a", 40) + ";", "&" + strings.Repeat("a", 40) + ";"},
		{"&; &! &é &", "&; &! &é &"},
		{"&#4294967361;", "\ufffd"},
		{"&#x100000041;", "\ufffd"},
		{"&#4294967424;", "\ufffd"},
		{"&#x110000;", "\ufffd"},
		{"&#0;&#xD800;&#xDFFF;", "\ufffd\ufffd\ufffd"},
		{"&#x1;&#xB;&#x7F;&#xFFFE;&#xFDD0;&#x10FFFE;&#x10FFFF;", "\x01\x0b\x7f\ufffe\ufdd0\U0010fffe\U0010ffff"},
		{"&#128;&#x81;&#x9F;", "\u20ac\u0081\u0178"},
		{"&#X41tail &#65tail", "Atail Atail"},
		{"&#; &#x; &#xG; &unknown;", "&#; &#x; &#xG; &unknown;"},
		{"&amp;#x1;&euro;&#xFFFE;", "\x01\u20ac\ufffe"},
		{"&#38;#x1;", "\x01"},
		{"&#" + strings.Repeat("9", 5000) + ";", "\ufffd"},
		{"&#x" + strings.Repeat("F", 5000) + ";", "\ufffd"},
	} {
		t.Run(tc.input[:min(len(tc.input), 80)], func(t *testing.T) {
			recipe := Recipe{TransformProfileDigest: EvidenceProvenanceProfileV5Digest, Operations: []Operation{{Kind: OperationHTMLEntityDecode}}}
			got, err := recipe.Apply(tc.input)
			if err != nil || got != tc.want {
				t.Fatalf("decoded = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestHTMLEntityDecodeHistoricalProfiles(t *testing.T) {
	t.Parallel()
	for _, digest := range []string{EvidenceProvenanceProfileV1Digest, EvidenceProvenanceProfileV2Digest, EvidenceProvenanceProfileV3Digest, EvidenceProvenanceProfileV4Digest} {
		recipe := Recipe{TransformProfileDigest: digest, Operations: []Operation{{Kind: OperationHTMLEntityDecode}}}
		got, err := recipe.Apply("&#4294967361;&#x1;&#xFFFE;")
		if err != nil || got != "A\x01\ufffe" {
			t.Fatalf("%s: decoded = %q, %v", digest, got, err)
		}
	}
}
