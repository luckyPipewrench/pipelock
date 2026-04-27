// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/runtime"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	// testCaptureDirAbs is the canonical absolute capture directory used
	// across these tests. Extracted to satisfy goconst.
	testCaptureDirAbs = "/tmp/learn-observe-test"
	// testFlagDirAbs is a different absolute path used to assert that the
	// flag value wins over the config-derived value.
	testFlagDirAbs = "/tmp/learn-observe-from-flag"
)

// stubRunner records whatever opts the cobra wiring hands to the
// runtime entry point and returns a sentinel error so the test can
// assert the stub fired without actually starting the proxy.
type stubRunner struct {
	called bool
	opts   runtime.ServerOpts
	ret    error
}

func (s *stubRunner) Run(_ context.Context, opts runtime.ServerOpts) error {
	s.called = true
	s.opts = opts
	return s.ret
}

// withStubRunner swaps observeRunner for the duration of the test. The
// caller is responsible for restoring it; we use t.Cleanup so the swap
// is reverted regardless of test outcome.
func withStubRunner(t *testing.T, ret error) *stubRunner {
	t.Helper()
	stub := &stubRunner{ret: ret}
	prev := observeRunner
	observeRunner = stub.Run
	t.Cleanup(func() { observeRunner = prev })
	return stub
}

// writeYAMLConfig drops a YAML config file under t.TempDir() and
// returns its path. Tests that need a config-on-disk for runObserve
// use this helper so each test gets an isolated tempdir.
func writeYAMLConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func TestCmd_HasObserveSubcommand(t *testing.T) {
	parent := Cmd()
	if parent.Use != "learn" {
		t.Fatalf("expected parent Use=%q, got %q", "learn", parent.Use)
	}

	var found bool
	for _, sub := range parent.Commands() {
		if sub.Name() == "observe" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected `observe` subcommand on `learn`, not found")
	}
}

func TestCmd_HelpText(t *testing.T) {
	parent := Cmd()

	if !strings.Contains(parent.Long, "observe") {
		t.Errorf("parent Long should describe `observe`; got %q", parent.Long)
	}

	obs := observeCmd()
	if !strings.Contains(obs.Long, "observation") {
		t.Errorf("observe Long should mention 'observation'; got %q", obs.Long)
	}
	if !strings.Contains(obs.Long, "capture-dir") {
		t.Errorf("observe Long should mention 'capture-dir'; got %q", obs.Long)
	}
}

func TestResolveCaptureDir_FlagWins(t *testing.T) {
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = testCaptureDirAbs

	got, err := resolveCaptureDir(cfg, testFlagDirAbs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testFlagDirAbs {
		t.Errorf("flag should override config; got %q, want %q", got, testFlagDirAbs)
	}
}

func TestResolveCaptureDir_FallsBackToConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = testCaptureDirAbs

	got, err := resolveCaptureDir(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testCaptureDirAbs {
		t.Errorf("expected config fallback %q, got %q", testCaptureDirAbs, got)
	}
}

func TestResolveCaptureDir_RequiresValue(t *testing.T) {
	cfg := config.Defaults() // Learn.CaptureDir == ""

	_, err := resolveCaptureDir(cfg, "")
	if err == nil {
		t.Fatal("expected error when no capture dir provided")
	}
	if !errors.Is(err, errNoCaptureDir) {
		t.Errorf("expected errNoCaptureDir, got %v", err)
	}
}

func TestResolveCaptureDir_RejectsRelativePath(t *testing.T) {
	cfg := config.Defaults()

	_, err := resolveCaptureDir(cfg, "relative/path")
	if err == nil {
		t.Fatal("expected error for relative path")
	}
	if !errors.Is(err, errRelativeCaptureDir) {
		t.Errorf("expected errRelativeCaptureDir, got %v", err)
	}
}

func TestResolveCaptureDir_RejectsRelativeFromConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = "also/relative"

	_, err := resolveCaptureDir(cfg, "")
	if err == nil {
		t.Fatal("expected error for relative path from config")
	}
	if !errors.Is(err, errRelativeCaptureDir) {
		t.Errorf("expected errRelativeCaptureDir, got %v", err)
	}
}

func TestEnableLearnObservation_SetsFields(t *testing.T) {
	cfg := config.Defaults()
	if cfg.Learn.Enabled {
		t.Fatal("precondition: defaults must have Learn.Enabled=false")
	}

	enableLearnObservation(cfg, testCaptureDirAbs)

	if !cfg.Learn.Enabled {
		t.Errorf("expected Learn.Enabled=true after enable")
	}
	if cfg.Learn.CaptureDir != testCaptureDirAbs {
		t.Errorf("expected CaptureDir=%q, got %q", testCaptureDirAbs, cfg.Learn.CaptureDir)
	}
}

func TestEnableLearnObservation_OverridesConfigDir(t *testing.T) {
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = "/tmp/old-dir"

	enableLearnObservation(cfg, testCaptureDirAbs)

	if cfg.Learn.CaptureDir != testCaptureDirAbs {
		t.Errorf("enable should overwrite stale config dir; got %q", cfg.Learn.CaptureDir)
	}
}

// TestObserveCmd_RequiresCaptureDir confirms that invoking the cobra
// command with neither --capture-dir nor a learn.capture_dir in config
// produces the canonical error.
func TestObserveCmd_RequiresCaptureDir(t *testing.T) {
	withStubRunner(t, nil)

	cfgPath := writeYAMLConfig(t, "mode: balanced\n")

	cmd := observeCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"--config", cfgPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when capture dir is unset")
	}
	if !errors.Is(err, errNoCaptureDir) {
		t.Errorf("expected errNoCaptureDir, got %v", err)
	}
}

func TestObserveCmd_RejectsRelativeCaptureDir(t *testing.T) {
	withStubRunner(t, nil)

	cmd := observeCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"--capture-dir", "rel/dir"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for relative --capture-dir")
	}
	if !errors.Is(err, errRelativeCaptureDir) {
		t.Errorf("expected errRelativeCaptureDir, got %v", err)
	}
}

func TestObserveCmd_FlagOverridesConfig(t *testing.T) {
	stub := withStubRunner(t, nil)

	body := "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: " + testCaptureDirAbs + "\n"
	cfgPath := writeYAMLConfig(t, body)

	var stdout strings.Builder
	cmd := observeCmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--capture-dir", testFlagDirAbs,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if !stub.called {
		t.Fatal("observeRunner stub was not invoked")
	}
	if stub.opts.CaptureOutput != testFlagDirAbs {
		t.Errorf("expected CaptureOutput=%q (flag), got %q", testFlagDirAbs, stub.opts.CaptureOutput)
	}
	if stub.opts.ConfigFile != cfgPath {
		t.Errorf("expected ConfigFile=%q, got %q", cfgPath, stub.opts.ConfigFile)
	}
	if !strings.Contains(stdout.String(), "observation session started") {
		t.Errorf("expected session-start banner in stdout; got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), testFlagDirAbs) {
		t.Errorf("expected capture dir in banner; got %q", stdout.String())
	}
}

func TestObserveCmd_UsesConfigDirWhenFlagAbsent(t *testing.T) {
	stub := withStubRunner(t, nil)

	body := "" +
		"mode: balanced\n" +
		"learn:\n" +
		"  enabled: true\n" +
		"  capture_dir: " + testCaptureDirAbs + "\n"
	cfgPath := writeYAMLConfig(t, body)

	cmd := observeCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"--config", cfgPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !stub.called {
		t.Fatal("runner not invoked")
	}
	if stub.opts.CaptureOutput != testCaptureDirAbs {
		t.Errorf("expected CaptureOutput=%q (from config), got %q", testCaptureDirAbs, stub.opts.CaptureOutput)
	}
}

func TestObserveCmd_PropagatesRunnerError(t *testing.T) {
	sentinel := errors.New("runner failed")
	withStubRunner(t, sentinel)

	cmd := observeCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"--capture-dir", testCaptureDirAbs})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected runner error to surface")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestObserveCmd_RejectsPositionalArgs(t *testing.T) {
	withStubRunner(t, nil)

	cmd := observeCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{"--capture-dir", testCaptureDirAbs, "stray"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for stray positional argument")
	}
}

func TestObserveCmd_BadConfigPath(t *testing.T) {
	withStubRunner(t, nil)

	cmd := observeCmd()
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	cmd.SetArgs([]string{
		"--config", "/nonexistent/pipelock.yaml",
		"--capture-dir", testCaptureDirAbs,
	})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for nonexistent config path")
	}
}
