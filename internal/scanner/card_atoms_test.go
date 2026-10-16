// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
)

func TestRequestBodyCardAtomsKeepNumericBoundaries(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	groups := []string{"4000", "5000", "6000", "7003"}
	for _, tt := range []struct {
		name, sep string
		number    bool
		clean     bool
	}{
		{"number atoms", ".", true, false},
		{"string atoms", ".", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			atoms := make([]extract.DLPAtom, len(groups))
			for i, group := range groups {
				atoms[i] = extract.DLPAtom{Text: group, Card: group, Number: tt.number}
			}
			result := s.ScanRequestBodyTextPartsWithCardAtoms(t.Context(), atoms, tt.sep)
			if result.Clean != tt.clean {
				t.Fatalf("clean=%v want=%v matches=%+v", result.Clean, tt.clean, result.Matches)
			}
		})
	}
}
