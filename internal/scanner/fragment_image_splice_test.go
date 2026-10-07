// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func imageSpliceScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func imageSpliceFragments(parts ...string) []fragment {
	out := make([]fragment, 0, len(parts))
	for _, p := range parts {
		out = append(out, fragment{data: []byte(p)})
	}
	return out
}

func hasAWSKey(matches []DLPMatch) bool {
	const name = "AWS Access ID"
	for _, m := range matches {
		if m.PatternName == name {
			return true
		}
	}
	return false
}

func TestFragmentImageSplice(t *testing.T) {
	sc := imageSpliceScanner(t)
	key := "AKI" + "A" + "ABCDEFGHIJKLMNOP"
	image := dataURLForPNGBytes(t, randomPNG(t, 21))
	if !strings.HasPrefix(exciseImagesRetainingDecodedForDLP(key[:4]+image+key[4:]), key) {
		t.Fatal("fixture: excision does not join the key")
	}
	at := len(image) / 2

	t.Run("key split around an image across requests is reported", func(t *testing.T) {
		got := scanOneFragmentContinuityMemo(context.Background(), sc, imageSpliceFragments(key[:4]+image[:at], image[at:]+key[4:]), nil, "splice")
		if !hasAWSKey(got) {
			t.Fatalf("split key not reported: %+v", got)
		}
	})

	t.Run("key whole inside one request is not a cross-request match", func(t *testing.T) {
		got := scanOneFragmentContinuityMemo(context.Background(), sc, imageSpliceFragments(image[:at], image[at:]+" "+key), nil, "whole")
		if hasAWSKey(got) {
			t.Fatalf("single-request key reported as cross-request: %+v", got)
		}
	})

	t.Run("a whole decoy copy does not hide a split copy", func(t *testing.T) {
		got := scanOneFragmentContinuityMemo(context.Background(), sc, imageSpliceFragments(key+" ", key[:4]+image[:at], image[at:]+key[4:]), nil, "decoy")
		if !hasAWSKey(got) {
			t.Fatalf("split key hidden by a whole decoy copy: %+v", got)
		}
	})

	t.Run("blanking one rule does not hide another rule's split", func(t *testing.T) {
		ssn := "123" + "-45-" + "6789"
		got := scanOneFragmentContinuityMemo(context.Background(), sc, imageSpliceFragments(key+" "+ssn+" ", key[:4]+image[:at], image[at:]+key[4:]+" "+ssn[:6], ssn[6:]+" end"), nil, "rules")
		if !hasAWSKey(got) {
			t.Fatalf("split key lost when another rule is present: %+v", got)
		}
		splitSSN := false
		for _, m := range got {
			if m.PatternName == "Social Security Number" {
				splitSSN = true
			}
		}
		if !splitSSN {
			t.Fatalf("split SSN lost while the key rule was processed: %+v", got)
		}
	})

	t.Run("a fragment that holds a whole image still reports a split key", func(t *testing.T) {
		got := scanOneFragmentContinuityMemo(context.Background(), sc, imageSpliceFragments(image+" "+key+" "+key[:4]+image[:at], image[at:]+key[4:]), nil, "own-image")
		if !hasAWSKey(got) {
			t.Fatalf("split key hidden by a fragment containing its own image: %+v", got)
		}
	})

	t.Run("many whole copies hit the rescan cap and still report", func(t *testing.T) {
		whole := strings.Repeat(key+" ", maxImageSpliceRescans+2)
		got := scanOneFragmentContinuityMemo(context.Background(), sc, imageSpliceFragments(whole+image[:at], image[at:]), nil, "cap")
		if !hasAWSKey(got) {
			t.Fatalf("rescan cap did not fail closed: %+v", got)
		}
	})

	t.Run("a whole copy running into a split copy is reported", func(t *testing.T) {
		frags := imageSpliceFragments(key+key[:10]+image[:at], image[at:]+key[10:])
		frags[0].sourceRequestID = []byte("req-1")
		frags[1].sourceRequestID = []byte("req-2")
		got := scanOneFragmentContinuityMemo(context.Background(), sc, frags, nil, "adjacent")
		if !hasAWSKey(got) {
			t.Fatalf("split copy adjoining a whole copy dropped: %+v", got)
		}
		var ids []string
		for _, m := range got {
			if m.PatternName == "AWS Access ID" {
				for _, c := range m.Contributors {
					ids = append(ids, string(c))
				}
			}
		}
		if strings.Join(ids, ",") != "req-1,req-2" {
			t.Fatalf("contributors = %v, want both requests", ids)
		}
	})

	t.Run("image without a secret stays clean", func(t *testing.T) {
		if got := scanOneFragmentContinuityMemo(context.Background(), sc, imageSpliceFragments(image[:at], image[at:]), nil, "clean"); len(got) != 0 {
			t.Fatalf("clean image produced matches: %+v", got)
		}
	})
}

// The scanner swaps the public documentation credentials for placeholders of
// a different length before recording positions. A split secret behind them
// must still be reported, with and without an image in the window.
func TestFragmentDocExampleRedactionShift(t *testing.T) {
	sc := imageSpliceScanner(t)
	ctx := context.Background()
	marker := "example credential "
	docKey := rot13ASCII("NXVNVBFSBQAA7RKNZCYR")
	docSecret := rot13ASCII("jWnyeKHgaSRZV/X7ZQRAT/oCkEsvPLRKNZCYRXRL")
	key := "AKI" + "A" + "ABCDEFGHIJKLMNOP"
	ssn := "123" + "-45-" + "6789"
	image := dataURLForPNGBytes(t, randomPNG(t, 21))
	cases := []struct {
		name, lead, secret, rule string
		cut                      int
	}{
		{"key behind lengthened placeholder", marker + docKey + " ", key, "AWS Access ID", 4},
		{"key at the length difference", marker + docKey + " ", key, "AWS Access ID", 5},
		{"ssn behind lengthened placeholder", marker + docKey + " ", ssn, "Social Security Number", 4},
		{"key behind shortened placeholder", marker + docSecret + " ", key, "AWS Access ID", 10},
	}
	for _, tc := range cases {
		for _, withImage := range []bool{false, true} {
			p1 := tc.lead + tc.secret[:tc.cut]
			p2 := tc.secret[tc.cut:] + " done."
			if withImage {
				p2 += image
			}
			got := scanOneFragmentContinuityMemo(ctx, sc, imageSpliceFragments(p1, p2), nil, tc.name)
			found := false
			for _, m := range got {
				if m.PatternName == tc.rule {
					found = true
				}
			}
			if !found {
				t.Errorf("%s (image=%v): split %s dropped: %+v", tc.name, withImage, tc.rule, got)
			}
		}
	}
}
