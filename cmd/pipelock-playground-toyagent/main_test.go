// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// canaryValue is split so the literal never appears in a string constant that
// could end up in narration.  The value lives ONLY in the env var and (via the
// web tool) in POST request bodies — never in argv, stdout, or URLs.
const (
	canaryPart1 = "AKIA"
	canaryPart2 = "IOSFODNN7EXAMPLE"
)

// demoLabelParts are assembled at runtime to avoid gosec G101 false-positives
// on string literals that contain credential-sounding words like "canary".
const (
	demoLabelPfx = "aws_"
	demoLabelSfx = "canary"
)

// demoLabel returns the human-readable name for the synthetic secret used
// across demo steps.  Built at runtime so gosec does not flag the literal.
func demoLabel() string { return demoLabelPfx + demoLabelSfx }

// canaryValue returns the synthetic canary assembled at runtime.
func canaryValue() string { return canaryPart1 + canaryPart2 }

// TestToyAgent_NarratesLabelNotValue verifies that the toy agent prints the
// LABEL for the canary (e.g. "aws_canary") but NEVER the literal value, even
// in DryRun mode where no subprocess is launched.
func TestToyAgent_NarratesLabelNotValue(t *testing.T) {
	t.Setenv("PLAYGROUND_CANARY_VALUE", canaryValue())

	var buf bytes.Buffer
	err := runAgent(t.Context(), &buf, agentConfig{
		SecretLabel: demoLabel(),
		Step:        "2",
		RunNonce:    "N1",
		DryRun:      true,
	})
	if err != nil {
		t.Fatalf("runAgent: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, canaryValue()) {
		t.Fatal("agent MUST NEVER print the canary value to stdout")
	}
	if !strings.Contains(out, demoLabel()) {
		t.Fatal("agent must narrate the canary label")
	}
}

// TestToyAgent_Step1_DryRun checks that step 1 narrates the safe URL fetch
// intent without executing anything and without printing the canary.
func TestToyAgent_Step1_DryRun(t *testing.T) {
	t.Setenv("PLAYGROUND_CANARY_VALUE", canaryValue())

	var buf bytes.Buffer
	err := runAgent(t.Context(), &buf, agentConfig{
		SecretLabel: demoLabel(),
		Step:        "1",
		SafeURL:     "http://lab.example/safe",
		RunNonce:    "R1",
		DryRun:      true,
	})
	if err != nil {
		t.Fatalf("runAgent step 1: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, canaryValue()) {
		t.Fatal("step 1 must not mention the canary value")
	}
	// Should mention fetching / safe URL concept in narration.
	if !strings.Contains(strings.ToLower(out), "safe") &&
		!strings.Contains(strings.ToLower(out), "fetch") &&
		!strings.Contains(strings.ToLower(out), "lab") {
		t.Fatalf("step 1 narration should mention the safe fetch; got: %q", out)
	}
}

// TestToyAgent_Step3_DryRun checks that step 3 narrates bypass intent without
// the canary value appearing.
func TestToyAgent_Step3_DryRun(t *testing.T) {
	t.Setenv("PLAYGROUND_CANARY_VALUE", canaryValue())

	var buf bytes.Buffer
	cfg3 := agentConfig{
		Step:     "3",
		DryRun:   true,
		RunNonce: "step3test",
	}
	cfg3.BypassURL = "http://direct.example/test"
	cfg3.SecretLabel = demoLabel()
	err := runAgent(t.Context(), &buf, cfg3)
	if err != nil {
		t.Fatalf("runAgent step 3: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, canaryValue()) {
		t.Fatal("step 3 must not mention the canary value")
	}
	if !strings.Contains(strings.ToLower(out), "bypass") &&
		!strings.Contains(strings.ToLower(out), "direct") {
		t.Fatalf("step 3 narration should mention bypass attempt; got: %q", out)
	}
}

func TestToyAgent_Step3_ExpectedBlockFailsOnConnectedBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	err := runAgent(t.Context(), &buf, agentConfig{
		Step:                "3",
		BypassURL:           srv.URL,
		ExpectBypassBlocked: true,
	})
	if err == nil {
		t.Fatal("expected contained bypass check to fail when direct egress connects")
	}
	if strings.Contains(buf.String(), canaryValue()) {
		t.Fatal("step 3 must not print the canary value")
	}
}

// TestToyAgent_ContextCancellation checks that a cancelled context causes
// runAgent to return promptly (DryRun so no subprocesses involved).
func TestToyAgent_ContextCancellation(t *testing.T) {
	t.Setenv("PLAYGROUND_CANARY_VALUE", canaryValue())

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // already cancelled

	var buf bytes.Buffer
	// In DryRun mode the agent should still complete (no blocking I/O);
	// context cancellation should not cause a panic.
	_ = runAgent(ctx, &buf, agentConfig{
		SecretLabel: demoLabel(),
		Step:        "1",
		DryRun:      true,
	})
}

// TestToyAgent_UnknownStep errors on an unknown step string.
func TestToyAgent_UnknownStep(t *testing.T) {
	t.Setenv("PLAYGROUND_CANARY_VALUE", canaryValue())

	var buf bytes.Buffer
	err := runAgent(t.Context(), &buf, agentConfig{
		Step:   "99",
		DryRun: true,
	})
	if err == nil {
		t.Fatal("expected error for unknown step")
	}
}

func TestRootCmd_DryRunExecutesConfiguredStep(t *testing.T) {
	var buf bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--step", "1", "--safe-url", "http://safe.target.test/", "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("root command dry-run: %v", err)
	}
	if !strings.Contains(buf.String(), "safe") {
		t.Fatalf("expected dry-run narration, got:\n%s", buf.String())
	}
}

func TestPrefixWriter_PrefixesCompleteLines(t *testing.T) {
	var buf bytes.Buffer
	w := &prefixWriter{prefix: "[webtool] ", out: &buf}
	if _, err := w.Write([]byte("one\ntwo\npartial")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := buf.String(), "[webtool] one\n[webtool] two\n"; got != want {
		t.Fatalf("prefixed output = %q, want %q", got, want)
	}
	if string(w.buf) != "partial" {
		t.Fatalf("partial line buffer = %q", string(w.buf))
	}
}

func TestAddRunNonce_EncodesAndPreservesExistingQuery(t *testing.T) {
	got, err := addRunNonce("http://collector.test/ingest?existing=1", "run 1/2")
	if err != nil {
		t.Fatalf("addRunNonce: %v", err)
	}
	if got != "http://collector.test/ingest?existing=1&run=run+1%2F2" {
		t.Fatalf("unexpected encoded URL: %s", got)
	}
}

func TestInvokeWebTool_PropagatesSafeStepFailure(t *testing.T) {
	t.Setenv("GO_WANT_PLAYGROUND_HELPER_PROCESS", "exit")

	var buf bytes.Buffer
	err := invokeWebTool(t.Context(), narrator{out: &buf}, agentConfig{
		WebToolPath: os.Args[0],
	}, false, "-test.run=TestHelperProcess")
	if err == nil {
		t.Fatal("safe step must propagate web tool exit errors")
	}
}

func TestInvokeWebTool_AllowsBlockedRedPostExit(t *testing.T) {
	t.Setenv("GO_WANT_PLAYGROUND_HELPER_PROCESS", "exit")

	var buf bytes.Buffer
	err := invokeWebTool(t.Context(), narrator{out: &buf}, agentConfig{
		WebToolPath: os.Args[0],
	}, true, "-test.run=TestHelperProcess")
	if err != nil {
		t.Fatalf("red POST should allow web tool exit error: %v", err)
	}
}

func TestHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_PLAYGROUND_HELPER_PROCESS") != "exit" {
		return
	}
	os.Exit(7)
}
