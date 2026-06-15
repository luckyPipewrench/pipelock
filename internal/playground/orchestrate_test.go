// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

const testScenarioID = "secret-exfil-url-blocked"

func TestRunDemo_Uncontained_VerifiesAndRendersTimeline(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestrate test builds binaries and boots a real proxy")
	}

	var buf bytes.Buffer
	rep, err := playground.RunDemo(t.Context(), &buf, playground.DemoOpts{
		Contained:  false,
		ScenarioID: testScenarioID,
		RunDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("uncontained run must verify: %+v", rep)
	}
	out := buf.String()
	// The rendered timeline shows the evidence classes + a blocked decision + the verifier command.
	for _, want := range []string{"pipelock_decision", "collector_witness", "BLOCKED", "verify"} {
		if !strings.Contains(out, want) {
			t.Fatalf("timeline missing %q in output:\n%s", want, out)
		}
	}
}

func TestReset_ThreeTimesClean(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestrate test builds binaries and boots a real proxy")
	}

	base := t.TempDir()
	for i := 0; i < 3; i++ {
		rd := filepath.Join(base, fmt.Sprintf("run-%d", i))
		if err := playground.Reset(rd); err != nil {
			t.Fatalf("reset %d: %v", i, err)
		}
		rep, err := playground.RunDemo(t.Context(), io.Discard, playground.DemoOpts{
			Contained:  false,
			ScenarioID: testScenarioID,
			RunDir:     rd,
		})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if !rep.OK {
			t.Fatalf("run %d must be clean+verify: %+v", i, rep)
		}
	}
}

func TestReset_RefusesEvidenceDirReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("orchestrate test builds binaries and boots a real proxy")
	}

	// Do a real run, producing artifacts in the run dir.
	rd := t.TempDir()
	_, err := playground.RunDemo(t.Context(), io.Discard, playground.DemoOpts{
		Contained:  false,
		ScenarioID: testScenarioID,
		RunDir:     rd,
	})
	if err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Reset cleans it so a second run works without stale state.
	if err := playground.Reset(rd); err != nil {
		t.Fatalf("reset: %v", err)
	}

	// Second run on the same dir must succeed (no stale evidence bleed).
	rep, err := playground.RunDemo(t.Context(), io.Discard, playground.DemoOpts{
		Contained:  false,
		ScenarioID: testScenarioID,
		RunDir:     rd,
	})
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("second run must verify: %+v", rep)
	}
}

func TestRunDemo_ContainedMode_FailsLoudlyWithoutHook(t *testing.T) {
	t.Parallel()

	// Ensure no containment hook is wired (default state).
	playground.SetContainmentHook(nil)

	var buf bytes.Buffer
	_, err := playground.RunDemo(t.Context(), &buf, playground.DemoOpts{
		Contained:  true,
		ScenarioID: testScenarioID,
		RunDir:     t.TempDir(),
	})
	if err == nil {
		t.Fatal("contained mode without hook must fail, got nil error")
	}
	if !strings.Contains(err.Error(), "containment") {
		t.Fatalf("error must mention containment, got: %v", err)
	}
}

func TestPreflight_ContainedWithoutHook(t *testing.T) {
	t.Parallel()

	playground.SetContainmentHook(nil)

	err := playground.Preflight(playground.DemoOpts{
		Contained:  true,
		ScenarioID: testScenarioID,
		RunNonce:   "test-nonce",
		RunDir:     t.TempDir(),
	})
	if err == nil {
		t.Fatal("preflight with contained=true and no hook must fail")
	}
	if !strings.Contains(err.Error(), "containment") {
		t.Fatalf("error must mention containment, got: %v", err)
	}
}

func TestPreflight_UncontainedSucceeds(t *testing.T) {
	t.Parallel()

	err := playground.Preflight(playground.DemoOpts{
		Contained:  false,
		ScenarioID: testScenarioID,
		RunNonce:   "test-nonce",
		RunDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("preflight must succeed for uncontained: %v", err)
	}
}
