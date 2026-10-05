// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestImmutableReceiptRedactorAvailability(t *testing.T) {
	var absent *recorder.Recorder
	if rf, known := absent.ImmutableReceiptRedactor(); rf != nil || known {
		t.Fatal("nil recorder advertised a generation")
	}
	rec, err := recorder.NewWithScanner(recorder.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rf, known := rec.ImmutableReceiptRedactor(); rf != nil || !known {
		t.Fatal("disabled redaction required a detector")
	}
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	if _, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true, SignCheckpoints: true}, sc, nil); err == nil {
		t.Fatal("invalid recorder signing configuration accepted")
	}
}

func TestImmutableReceiptRedactorLifetime(t *testing.T) {
	if rec, err := recorder.NewWithScanner(recorder.Config{Redact: true}, nil, nil); err == nil || rec != nil {
		t.Fatal("redaction accepted without a scanner")
	}
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "generation fixture", Regex: "receipt-secret-fixture", Severity: config.SeverityHigh})
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	plain, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc.ScanTextForDLP, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rf, known := plain.ImmutableReceiptRedactor(); rf != nil || known {
		t.Fatal("arbitrary callback advertised immutable lifetime")
	}
	bound, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := bound.Close(); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		if err := plain.Close(); err != nil {
			t.Error(err)
		}
	}()
	rf, known := bound.ImmutableReceiptRedactor()
	if rf == nil || !known {
		t.Fatal("bound scanner did not expose redactor")
	}
	if result := rf(t.Context(), "receipt-secret-fixture"); result.Clean || len(result.Matches) != 1 {
		t.Fatalf("bound redactor missed generation rule: %+v", result)
	}
	if result := rf(t.Context(), "ordinary receipt"); !result.Clean {
		t.Fatalf("clean control blocked: %+v", result)
	}
}
