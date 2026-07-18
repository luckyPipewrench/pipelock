// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/discover"
)

type initFailWriter struct{}

func (initFailWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestInitUsesEnvironmentHomeAndFailsWhenUnavailable(t *testing.T) {
	t.Setenv("HOME", "")
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	err := runInit(cmd, initOptions{
		preset:       config.ModeBalanced,
		dryRun:       true,
		skipValidate: true,
		skipCanary:   true,
	})
	if err == nil || !strings.Contains(err.Error(), "determining home directory") {
		t.Fatalf("home error = %v", err)
	}
	var exitErr *cliutil.ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != initExitError {
		t.Fatalf("exit error = %v", err)
	}
}

func TestInitDefaultConfigDirectoryFailureIsExplicit(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	err := runInit(cmd, initOptions{
		preset:       config.ModeBalanced,
		scanHome:     t.TempDir(),
		dryRun:       true,
		skipValidate: true,
		skipCanary:   true,
	})
	if err == nil || !strings.Contains(err.Error(), "determining config directory") {
		t.Fatalf("config directory error = %v", err)
	}
}

func TestInitJSONWriterFailureIsReported(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(initFailWriter{})
	err := runInit(cmd, initOptions{
		preset:       config.ModeBalanced,
		scanHome:     t.TempDir(),
		output:       filepath.Join(t.TempDir(), "pipelock.yaml"),
		jsonOutput:   true,
		dryRun:       true,
		skipValidate: true,
		skipCanary:   true,
	})
	if err == nil || !strings.Contains(err.Error(), "encoding JSON") {
		t.Fatalf("JSON writer error = %v", err)
	}
}

func TestInitWriteFailureLeavesExistingConfigUntouched(t *testing.T) {
	base := t.TempDir()
	configPath := filepath.Join(base, "config-dir")
	if err := os.Mkdir(configPath, 0o750); err != nil {
		t.Fatal(err)
	}

	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	err := runInit(cmd, initOptions{
		preset:       config.ModeBalanced,
		scanHome:     base,
		output:       configPath,
		force:        true,
		skipValidate: true,
		skipCanary:   true,
	})
	if err == nil || !strings.Contains(err.Error(), "writing config") {
		t.Fatalf("write error = %v", err)
	}
	info, statErr := os.Stat(configPath)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("pre-existing destination changed: info=%v err=%v", info, statErr)
	}
}

func TestWriteConfigDeterministicFilesystemFailures(t *testing.T) {
	cfg := config.Defaults()
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := writeConfig(cfg, filepath.Join(blocker, "config.yaml"), config.ModeBalanced)
	if err == nil || !strings.Contains(err.Error(), "creating directory") {
		t.Fatalf("mkdir error = %v", err)
	}
	raw, readErr := os.ReadFile(blocker) // #nosec G304 -- fixed path inside the test temp directory.
	if readErr != nil || string(raw) != "keep" {
		t.Fatalf("blocker changed: %q err=%v", raw, readErr)
	}

	destination := filepath.Join(base, "destination")
	if err := os.Mkdir(destination, 0o750); err != nil {
		t.Fatal(err)
	}
	err = writeConfig(cfg, destination, config.ModeBalanced)
	if err == nil || !strings.Contains(err.Error(), "writing ") {
		t.Fatalf("write error = %v", err)
	}
}

func TestInitVerifyAndCanaryFailClosed(t *testing.T) {
	invalid := config.Defaults()
	invalid.DLP.Patterns = append(invalid.DLP.Patterns, config.DLPPattern{
		Name:  "malformed",
		Regex: "[",
	})
	verify := runInitVerify(invalid)
	if verify.Failed != 1 || !strings.Contains(verify.Detail, "config validation failed") {
		t.Fatalf("verify result = %+v", verify)
	}
	if scanCanaryURL(invalid, "https://api.vendor.example/test?key="+canaryToken()) {
		t.Fatal("canary scan must fail closed when scanner construction fails")
	}

	result := runInitCanary(invalid)
	if result.Detected || !strings.Contains(result.Detail, "was not detected") {
		t.Fatalf("canary result = %+v", result)
	}
}

func TestPrintDiscoverPhaseReportsMalformedAndUnprotectedClients(t *testing.T) {
	report := &discover.Report{
		Clients: []discover.ClientConfig{
			{Client: "broken", ConfigPath: "/tmp/broken.json", ParseError: "invalid JSON"},
			{Client: "healthy", ConfigPath: "/tmp/healthy.json", ServerCount: 2},
		},
		Summary: discover.Summary{
			TotalClients: 2,
			TotalServers: 2,
			Unprotected:  1,
		},
	}
	var out bytes.Buffer
	printDiscoverPhase(&out, report)
	got := out.String()
	for _, want := range []string{"Found 2 client(s)", "broken", "(parse error)", "healthy", "(2 servers)", "not wrapped"} {
		if !strings.Contains(got, want) {
			t.Fatalf("discover output missing %q:\n%s", want, got)
		}
	}
}

func TestPrintProofRepresentsFailureAndUnknownStates(t *testing.T) {
	result := &initResult{
		Discover: &initDiscoverResult{
			ClientsFound: 1,
			ServersFound: 2,
			Protected:    1,
			Unprotected:  1,
			Unknown:      1,
		},
		Setup: &initSetupResult{
			ConfigPath:     "/tmp/existing.yaml",
			Preset:         config.ModeBalanced,
			SkippedExsting: true,
		},
		Verify: &initVerifyResult{Passed: 2, Failed: 1},
		Canary: &initCanaryResult{Detected: false},
	}
	var out bytes.Buffer
	printProof(&out, result)
	got := out.String()
	for _, want := range []string{
		"Unknown:", "Config exists at:", "2 passed, 1 failed", "not detected", "use --force",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("proof output missing %q:\n%s", want, got)
		}
	}
}

func TestPrintProofDryRunAndSkippedPhases(t *testing.T) {
	result := &initResult{
		Discover: &initDiscoverResult{},
		Setup: &initSetupResult{
			ConfigPath: "/tmp/planned.yaml",
			Preset:     config.ModeStrict,
		},
		Verify: &initVerifyResult{Skipped: true},
		Canary: &initCanaryResult{Skipped: true},
	}
	var out bytes.Buffer
	printProof(&out, result)
	got := out.String()
	for _, want := range []string{"Config would be at:", "Validate:           skipped", "Canary:             skipped"} {
		if !strings.Contains(got, want) {
			t.Fatalf("proof output missing %q:\n%s", want, got)
		}
	}
}

func TestInitCommandRejectsUnexpectedArguments(t *testing.T) {
	cmd := InitCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"unexpected"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("init accepted an unexpected positional argument")
	}
}
