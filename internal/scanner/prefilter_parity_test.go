// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestDLPPreFilterCompiledPrefixParity(t *testing.T) {
	sc := MustNew(testConfig())
	t.Cleanup(sc.Close)
	for _, patterns := range [][]*compiledPattern{sc.dlpPatterns, sc.core.dlpPatterns, nil} {
		pf := newDLPPreFilter(patterns)
		prefixes := make(map[string][]int)
		var alwaysRun []int
		for i, pattern := range patterns {
			anchors := extractRequiredLiteralAnchors(pattern.re.String())
			if len(anchors) == 0 {
				alwaysRun = append(alwaysRun, i)
			}
			for _, anchor := range anchors {
				lower := strings.ToLower(anchor)
				prefixes[lower] = append(prefixes[lower], i)
			}
		}
		inputs := []string{"", "ordinary first body", "different second body", "\xff\x00", "ÜNİCODE"}
		var joined strings.Builder
		for prefix := range prefixes {
			inputs = append(inputs, "before "+prefix+" after", strings.ToUpper(prefix), prefix+prefix)
			joined.WriteString(prefix)
			joined.WriteByte(' ')
		}
		inputs = append(inputs, joined.String(), "ordinary first body")
		for _, input := range inputs {
			var want []int
			lower := strings.ToLower(input)
			for prefix, indices := range prefixes {
				if strings.Contains(lower, prefix) {
					want = append(want, indices...)
				}
			}
			want = append(want, alwaysRun...)
			sort.Ints(want)
			if len(want) > 0 {
				unique := want[:1]
				for _, index := range want[1:] {
					if index != unique[len(unique)-1] {
						unique = append(unique, index)
					}
				}
				want = unique
			}
			if got := pf.patternsToCheck(input); !reflect.DeepEqual(got, want) {
				t.Fatalf("candidate order differs for %q: got %v, want %v", input, got, want)
			}
		}
	}
}
