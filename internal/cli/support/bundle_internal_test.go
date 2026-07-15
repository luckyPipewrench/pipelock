// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRedactLogLinesFailsClosedWhenScannerCannotStart(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:  "invalid",
		Regex: "[",
	})

	got := redactLogLines(cfg, []string{"first diagnostic", "second diagnostic"})
	want := []string{"[redacted: scanner unavailable]", "[redacted: scanner unavailable]"}
	if !slices.Equal(got, want) {
		t.Fatalf("redactLogLines() = %q, want %q", got, want)
	}
}
