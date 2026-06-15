// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

func TestFallbackCmd_ShowsReplayWatermarkAndHash(t *testing.T) {
	if testing.Short() {
		t.Skip("fallback test requires a pre-recorded run dir from a real live run")
	}

	// Produce a pre-recorded run dir via RunDemo.
	recordedDir := t.TempDir()
	var runBuf bytes.Buffer
	rep, err := playground.RunDemo(t.Context(), &runBuf, playground.DemoOpts{
		Contained:  false,
		ScenarioID: playground.LiveDemoScenarioID,
		RunDir:     recordedDir,
	})
	if err != nil {
		t.Fatalf("pre-record run: %v", err)
	}
	if !rep.OK {
		t.Fatalf("pre-record run must verify: %+v", rep)
	}

	// Now run the fallback command against the recorded dir.
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// The orchestrator key is in the verify report; use the pipelock key from the run
	// since that's what the manifest pins. But the fallback command needs the
	// orchestrator key. We need to extract it. Since RunDemo's verify prints it,
	// use the verify report's PipelockKey... but actually we need the orchestrator key.
	// The fallback cmd reads from launch-manifest.json which was signed by the orchestrator.
	// We need to pass the right key. Let's re-verify to get the orchestrator key.
	//
	// Actually, the fallback subcommand takes the orchestrator key as a flag.
	// We can extract it by running verify first.
	// For testing, let's just use the cmdTestRunDir helper pattern.

	// Simpler approach: produce a proper run dir with known orchestrator key.
	dir, orchKey := cmdTestRunDir(t)

	cmd = newRootCmd()
	buf.Reset()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"fallback", dir, "--orchestrator-key", orchKey})
	err = cmd.Execute()
	if err != nil {
		t.Fatalf("fallback must exit 0 on valid recorded dir, got: %v\noutput:\n%s", err, buf.String())
	}

	out := buf.String()

	// Must contain REPLAY watermark.
	if !strings.Contains(out, "REPLAY") {
		t.Fatalf("output must contain REPLAY watermark, got:\n%s", out)
	}

	// Must contain the packet hash.
	if !strings.Contains(out, "sha256:") {
		t.Fatalf("output must contain packet hash (sha256:), got:\n%s", out)
	}

	// Must contain the verify command.
	if !strings.Contains(out, "verify") {
		t.Fatalf("output must contain verify command, got:\n%s", out)
	}
}

func TestRunCmd_Uncontained_ExitZero(t *testing.T) {
	if testing.Short() {
		t.Skip("run test builds binaries and boots a real proxy")
	}

	rd := t.TempDir()
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"run", "--run-dir", rd, "--scenario", playground.LiveDemoScenarioID})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("run --uncontained must exit 0, got: %v\noutput:\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "VERIFY OK") {
		t.Fatalf("output must contain VERIFY OK, got:\n%s", out)
	}
}
