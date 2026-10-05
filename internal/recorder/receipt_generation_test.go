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
