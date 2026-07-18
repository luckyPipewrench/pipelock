// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type explainFailReader struct {
	data []byte
	err  error
}

func (r *explainFailReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

func TestExplainRejectsAmbiguousAndMalformedSurfaceInputs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "multiple positional targets", args: []string{"https://one.example", "https://two.example"}, want: "at most one"},
		{name: "empty tool name", args: []string{"--tool", " ", "--input", `{}`}, want: "--tool cannot be empty"},
		{name: "empty file name", args: []string{"--file", " "}, want: "--file cannot be empty"},
		{name: "missing file", args: []string{"--file", filepath.Join(t.TempDir(), "missing")}, want: "read --file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runExplainCmd(t, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "large.txt")
	data := bytes.Repeat([]byte{'x'}, explainFileReadLimitBytes+1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runExplainCmd(t, "--file", path)
	if err == nil || !strings.Contains(err.Error(), "exceeds explain read cap") {
		t.Fatalf("oversized file error = %v", err)
	}
}

func TestExplainActionAndSummaryBoundaries(t *testing.T) {
	_, _, err := explainActionForMode("unexpected", "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "unknown explain mode") {
		t.Fatalf("unknown mode error = %v", err)
	}

	short := "plain command"
	if got := explainLimitSummary(short); got != short {
		t.Fatalf("short summary = %q", got)
	}
	long := strings.Repeat("x", explainSummaryMaxBytes+20)
	got := explainLimitSummary(long)
	if len(got) != explainSummaryMaxBytes+3 || !strings.HasSuffix(got, "...") {
		t.Fatalf("bounded summary length/suffix = %d/%q", len(got), got[len(got)-3:])
	}
}

func TestExplainEvidenceFallbacksFailClosed(t *testing.T) {
	first := decide.Evidence{Scanner: "first", Pattern: "pattern-only", Action: config.ActionWarn}
	if got := explainPrimaryEvidence(decide.Decision{Evidence: []decide.Evidence{first}}); got != first {
		t.Fatalf("first evidence fallback = %+v", got)
	}
	structural := explainPrimaryEvidence(decide.Decision{UserMessage: "invalid action"})
	if structural.Scanner != scanner.DecideStructuralLabel || structural.Action != config.ActionBlock {
		t.Fatalf("empty evidence fallback = %+v", structural)
	}

	tests := []struct {
		name     string
		evidence decide.Evidence
		decision decide.Decision
		want     string
	}{
		{name: "detail", evidence: decide.Evidence{Detail: "specific detail", Pattern: "pattern"}, want: "specific detail"},
		{name: "pattern", evidence: decide.Evidence{Pattern: "pattern"}, want: "pattern"},
		{name: "message", decision: decide.Decision{UserMessage: "safe fallback"}, want: "safe fallback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := explainEvidenceReason(tt.evidence, tt.decision); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}

	mapped := explainRemediationForEvidence(decide.Evidence{
		Scanner: scanner.ScannerCoreDLP,
		Detail:  "core DLP match",
	})
	if mapped == nil || !mapped.Immutable {
		t.Fatalf("core DLP remediation = %+v", mapped)
	}
	fallback := explainRemediationForEvidence(decide.Evidence{Scanner: "unknown", Pattern: "opaque"})
	if fallback == nil || !strings.Contains(fallback.Knob, "No specific remediation") {
		t.Fatalf("unknown remediation = %+v", fallback)
	}
}

func TestExplainViewDerivationBoundaries(t *testing.T) {
	for _, tt := range []struct {
		label string
		want  string
	}{
		{label: "normalized_query", want: explainViewURLQuery},
		{label: "canonical_subdomain", want: explainViewHost},
		{label: "decoded_path", want: explainViewPath},
		{label: "raw_url", want: explainViewURL},
		{label: "other", want: ""},
	} {
		t.Run(tt.label, func(t *testing.T) {
			got := explainTargetViewFromSpans([]scanner.MatchSpan{{ViewLabel: tt.label}})
			if got != tt.want {
				t.Fatalf("view = %q, want %q", got, tt.want)
			}
		})
	}

	for _, tt := range []struct {
		raw  string
		want string
	}{
		{raw: "https://host.example/", want: explainViewHost},
		{raw: "mailto:user@example.com", want: explainViewURL},
		{raw: "https://host.example/path", want: explainViewPath},
		{raw: "https://host.example/?key=value", want: explainViewURLQuery},
		{raw: "https://host.example/%zz", want: ""},
	} {
		if got := explainURLComponentView(tt.raw); got != tt.want {
			t.Errorf("explainURLComponentView(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestExplainEventReaderAndFieldFailureBoundaries(t *testing.T) {
	sentinel := errors.New("read failed")
	lookup, err := scanExplainEvent(&explainFailReader{err: sentinel}, "request")
	if err == nil || !strings.Contains(err.Error(), "scan audit log") || lookup.found {
		t.Fatalf("scan result = %+v, err = %v", lookup, err)
	}

	reader := bufio.NewReaderSize(&explainFailReader{
		data: bytes.Repeat([]byte{'x'}, 32),
		err:  sentinel,
	}, 16)
	_, tooLong, err := readExplainEventAuditLine(reader, 8)
	if !tooLong || err == nil || !strings.Contains(err.Error(), "scan audit log") {
		t.Fatalf("tooLong = %v, err = %v", tooLong, err)
	}

	reader = bufio.NewReaderSize(&explainFailReader{
		data: []byte("fragment"),
		err:  sentinel,
	}, 16)
	err = discardExplainEventAuditLineRemainder(reader)
	if err == nil || !strings.Contains(err.Error(), "scan audit log") {
		t.Fatalf("discard error = %v", err)
	}

	raw := map[string]any{
		"missing": nil,
		"integer": float64(42),
		"decimal": 3.5,
		"boolean": true,
		"object":  map[string]any{"x": 1},
	}
	for field, want := range map[string]string{
		"missing": "", "integer": "42", "decimal": "3.5", "boolean": "true", "object": "",
	} {
		if got := eventFieldString(raw, field); got != want {
			t.Errorf("eventFieldString(%q) = %q, want %q", field, got, want)
		}
	}
}

func TestExplainEventTargetViewsAndTerminalSafety(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{name: "empty", raw: map[string]any{}, want: ""},
		{name: "tool", raw: map[string]any{"tool": "shell"}, want: explainSurfaceTool},
		{name: "resource", raw: map[string]any{"resource": "tenant/item"}, want: "resource"},
		{name: "session", raw: map[string]any{"session": "session-1"}, want: "session"},
		{name: "path", raw: map[string]any{"target": "dir/file"}, want: explainViewPath},
		{name: "host", raw: map[string]any{"target": "host.example"}, want: explainViewHost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := firstEventField(tt.raw, "target", "tool", "resource", "session")
			if got := explainEventTargetView("", "", target, tt.raw); got != tt.want {
				t.Fatalf("target view = %q, want %q", got, tt.want)
			}
		})
	}

	if got := terminalDisplay("line\nbreak"); !strings.Contains(got, `\n`) || strings.Contains(got, "\n") {
		t.Fatalf("terminalDisplay emitted unsafe control bytes: %q", got)
	}
	if got := terminalDisplay("plain"); got != "plain" {
		t.Fatalf("plain terminal display = %q", got)
	}
}

func TestExplainJSONWriterFailureIsReported(t *testing.T) {
	cmd := explainCmd()
	cmd.SetArgs([]string{"--json", "https://example.com"})
	cmd.SetOut(explainErrorWriter{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "encode explain report JSON") {
		t.Fatalf("writer error = %v", err)
	}
}

type explainErrorWriter struct{}

func (explainErrorWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestExplainLoadSurfaceConfigRejectsInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("mode: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := explainLoadSurfaceConfig(path)
	if err == nil || !strings.Contains(err.Error(), "config load error") {
		t.Fatalf("load error = %v", err)
	}
}

func TestValidateExplainArgsInputFlagRequiresTool(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("input", "", "")
	cmd.Flags().String(explainSurfaceCommand, "", "")
	cmd.Flags().String(explainSurfaceTool, "", "")
	cmd.Flags().String(explainSurfaceFile, "", "")
	if err := cmd.Flags().Set("input", `{}`); err != nil {
		t.Fatal(err)
	}
	err := validateExplainArgs(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--input can only") {
		t.Fatalf("validation error = %v", err)
	}
}
