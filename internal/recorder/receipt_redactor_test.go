// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestReceiptRedactor(t *testing.T) {
	t.Parallel()

	dlp := func(_ context.Context, _ string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: true}
	}

	t.Run("nil recorder returns nil", func(t *testing.T) {
		t.Parallel()
		var r *Recorder
		if r.ReceiptRedactor() != nil {
			t.Error("nil recorder should return nil redactor")
		}
	})

	t.Run("redaction off returns nil", func(t *testing.T) {
		t.Parallel()
		rec, err := New(Config{Enabled: true, Dir: t.TempDir(), Redact: false}, dlp, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer func() { _ = rec.Close() }()
		if rec.ReceiptRedactor() != nil {
			t.Error("redaction off should return nil redactor")
		}
	})

	t.Run("redaction on returns the function", func(t *testing.T) {
		t.Parallel()
		rec, err := New(Config{Enabled: true, Dir: t.TempDir(), Redact: true}, dlp, nil)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer func() { _ = rec.Close() }()
		fn := rec.ReceiptRedactor()
		if fn == nil {
			t.Fatal("redaction on should return a non-nil redactor")
		}
		// The returned function must be the recorder's own DLP function.
		if !fn(context.Background(), "anything").Clean {
			t.Error("returned redactor did not behave like the wired DLP fn")
		}
	})
}
