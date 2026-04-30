// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestResolveCompileInputsRejectsAgentPathSegments(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = t.TempDir()

	for _, agent := range []string{"", ".", "..", "team/a", `team\a`} {
		t.Run(agent, func(t *testing.T) {
			_, err := resolveCompileInputs(cfg, compileFlags{agent: agent, since: time.Hour})
			if err == nil || !strings.Contains(err.Error(), "--agent") {
				t.Fatalf("resolveCompileInputs(%q) error = %v, want --agent validation", agent, err)
			}
		})
	}
}

func TestResolveCompileInputsAcceptsSingleSegmentAgent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	agentDir := filepath.Join(dir, "agent-a")
	if err := os.MkdirAll(agentDir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	input := filepath.Join(agentDir, "capture.jsonl")
	if err := os.WriteFile(input, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = dir

	got, err := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", since: time.Hour})
	if err != nil {
		t.Fatalf("resolveCompileInputs: %v", err)
	}
	if len(got) != 1 || got[0] != input {
		t.Fatalf("paths = %#v, want [%q]", got, input)
	}
}

func TestResolveCompileInputsRejectsSymlinkInput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	cfg := config.Defaults()

	_, err := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", inputGlob: link, since: time.Hour})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("resolveCompileInputs symlink error = %v, want symlink rejection", err)
	}
}

func TestResolveCompileInputsRejectsSymlinkedCaptureRootEscape(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	captureRoot := filepath.Join(dir, "captures")
	if err := os.MkdirAll(captureRoot, 0o750); err != nil {
		t.Fatalf("MkdirAll captureRoot: %v", err)
	}
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("MkdirAll outside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "capture.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile outside capture: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(captureRoot, "agent-a")); err != nil {
		t.Fatalf("Symlink agent dir: %v", err)
	}
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = captureRoot

	_, err := resolveCompileInputs(cfg, compileFlags{agent: "agent-a", since: time.Hour})
	if err == nil || !strings.Contains(err.Error(), "escapes learn.capture_dir") {
		t.Fatalf("resolveCompileInputs error = %v, want capture root escape rejection", err)
	}
}

func TestReadCompileInputsCountsAppendedNewline(t *testing.T) {
	t.Parallel()
	input := filepath.Join(t.TempDir(), "capture.jsonl")
	if err := os.WriteFile(input, []byte("{}\n{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stream, refs, err := readCompileInputs([]string{input})
	if err != nil {
		t.Fatalf("readCompileInputs: %v", err)
	}
	data, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != "{}\n{}\n" {
		t.Fatalf("stream = %q, want appended newline", data)
	}
	if len(refs) != 1 || refs[0].EventCount != 2 {
		t.Fatalf("refs = %#v, want event_count 2", refs)
	}
}

func TestResolveCompileOutputsRejectsOverlappingPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	output := filepath.Join(dir, "candidate.yaml")
	manifest := filepath.Join(dir, "manifest.json")

	_, _, _, err := resolveCompileOutputs(compileFlags{
		agent:    "agent-a",
		output:   output,
		review:   output,
		manifest: manifest,
	})
	if err == nil || !strings.Contains(err.Error(), "overlaps output") {
		t.Fatalf("resolveCompileOutputs error = %v, want overlap rejection", err)
	}
}
