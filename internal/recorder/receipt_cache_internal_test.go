// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestReceiptDetectorCacheBinding caches only the detector whose scanner
// generation is fixed for the recorder's lifetime. An arbitrary callback may
// change its answer, so New never caches it.
func TestReceiptDetectorCacheBinding(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "cache fixture", Regex: "receipt-secret-fixture", Severity: config.SeverityHigh})
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	bound, err := NewWithScanner(Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := bound.Close(); err != nil {
			t.Error(err)
		}
	}()
	if bound.contentCache == nil {
		t.Fatal("scanner-bound recorder has no receipt content cache")
	}
	det := bound.ReceiptDetector()
	for range 2 {
		if res := det(t.Context(), "ordinary receipt"); !res.Clean {
			t.Fatalf("clean control blocked: %+v", res)
		}
		if res := det(t.Context(), "receipt-secret-fixture"); res.Clean || len(res.Matches) != 1 {
			t.Fatalf("cached detector missed generation rule: %+v", res)
		}
	}
	if n := bound.contentCache.Len(); n != 1 {
		t.Fatalf("cache remembers %d texts, want only the clean one", n)
	}

	plain, err := New(Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc.ScanTextForDLP, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := plain.Close(); err != nil {
			t.Error(err)
		}
	}()
	if plain.contentCache != nil {
		t.Fatal("arbitrary callback was cached")
	}
	off, err := NewWithScanner(Config{Enabled: true, Dir: t.TempDir()}, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := off.Close(); err != nil {
			t.Error(err)
		}
	}()
	if off.contentCache != nil || off.ReceiptDetector() != nil {
		t.Fatal("recorder without redaction built a receipt detector")
	}
}
