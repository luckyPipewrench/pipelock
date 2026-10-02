// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

func TestInitChecksRetainedConfig(t *testing.T) {
	for _, tc := range []struct {
		name, contents                              string
		skipValidate, skipCanary, dryRun, wantError bool
		jsonOutput, wantLoadError, wantCanaryBlock  bool
	}{
		{name: "retained strict blocks before DLP", contents: "mode: strict\napi_allowlist: [api.vendor.example]\n", wantError: true, wantCanaryBlock: true},
		{name: "malformed", contents: "mode: [", wantError: true, wantLoadError: true},
		{name: "malformed JSON", contents: "mode: [", wantError: true, wantLoadError: true, jsonOutput: true},
		{name: "malformed canary only", contents: "mode: [", skipValidate: true, wantError: true, wantLoadError: true},
		{name: "malformed validate only", contents: "mode: [", skipCanary: true, wantError: true, wantLoadError: true},
		{name: "explicit skips", contents: "mode: [", skipValidate: true, skipCanary: true},
		{name: "dry run proposed config", contents: "mode: [", dryRun: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "retained policy.yaml")
			if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			err := runInit(cmd, initOptions{preset: config.ModeBalanced, scanHome: home, output: path, noAuditor: true, skipValidate: tc.skipValidate, skipCanary: tc.skipCanary, dryRun: tc.dryRun, jsonOutput: tc.jsonOutput})
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v; output: %s", err, &out)
			}
			if tc.wantError && strings.Contains(out.String(), "Canary:             detected") {
				t.Fatalf("misleading success: %s", &out)
			}
			if tc.wantLoadError {
				var exitErr *cliutil.ExitError
				if !errors.As(err, &exitErr) || exitErr.Code != initExitError || !strings.Contains(err.Error(), "loading config") || !strings.Contains(err.Error(), path) {
					t.Fatalf("expected retained-config load error with exit %d, got %v", initExitError, err)
				}
				if !tc.jsonOutput && (strings.Contains(out.String(), "Next steps:") || !strings.Contains(out.String(), "Fix the configuration file") || !strings.Contains(out.String(), "rerun the same pipelock init command")) {
					t.Fatalf("expected only file-repair guidance after load failure: %s", &out)
				}
			}
			if tc.wantCanaryBlock {
				var exitErr *cliutil.ExitError
				if !errors.As(err, &exitErr) || exitErr.Code != initExitFailure || !strings.Contains(err.Error(), "blocked before DLP") || !strings.Contains(err.Error(), `scanner "allowlist"`) {
					t.Fatalf("expected allowlist-stage canary failure, got %v", err)
				}
				if !strings.Contains(out.String(), err.Error()) {
					t.Fatalf("canary failure detail missing from output: %s", &out)
				}
			}
			if tc.jsonOutput {
				var result initResult
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Verify == nil || result.Verify.Skipped || result.Verify.Failed != 1 || !strings.Contains(result.Verify.Detail, "loading config") {
					t.Fatalf("expected failed validation: %+v", result.Verify)
				}
				if result.Canary == nil || !result.Canary.Skipped || result.Canary.Detected {
					t.Fatalf("expected skipped canary without detection: %+v", result.Canary)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(out.Bytes(), &fields); err != nil {
					t.Fatal(err)
				}
				var setupFields map[string]json.RawMessage
				if err := json.Unmarshal(fields["setup"], &setupFields); err != nil {
					t.Fatal(err)
				}
				if string(setupFields["preset"]) != `""` {
					t.Fatalf("retained preset must remain present and empty: %s", fields["setup"])
				}
			}
			got, err := os.ReadFile(filepath.Clean(path))
			if err != nil || string(got) != tc.contents {
				t.Fatalf("retained bytes changed: %q, %v", got, err)
			}
			if _, err := os.Stat(filepath.Join(home, "keys")); !os.IsNotExist(err) {
				t.Fatalf("retained config created keys: %v", err)
			}
		})
	}
}

func TestSidecarCanaryReportsSyntheticScopeAndConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	var out bytes.Buffer
	result := runSidecarCanary(&out, cfg, sidecarOptions{}, false)
	if !result.Detected || !strings.Contains(result.Detail, "client routing was not tested") || strings.Contains(result.Detail, "DLP is working") {
		t.Fatalf("unexpected synthetic success: %+v", result)
	}
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"api.vendor.example"}
	result = runSidecarCanary(&out, cfg, sidecarOptions{}, false)
	want := "/pipelock check --config " + initCommandQuote(sidecarConfigMount+"/"+sidecarConfigFile, "linux") + " --url "
	if result.Detected || !strings.Contains(result.Detail, "blocked before DLP") || !strings.Contains(result.Detail, want) || !strings.Contains(result.Detail, "inside its container") {
		t.Fatalf("unexpected canary recovery: %+v", result)
	}
	if !strings.Contains(out.String(), result.Detail) {
		t.Fatalf("missing human recovery: %s", &out)
	}
}

func TestInitFollowupsUseAbsoluteQuotedPath(t *testing.T) {
	home := t.TempDir()
	t.Chdir(home)
	path := "policy ' $value;.yaml"
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runInit(cmd, initOptions{preset: config.ModeBalanced, scanHome: home, output: path, noAuditor: true}); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(home, path)
	for _, command := range []string{"check", "doctor", "verify-install", "run"} {
		if !strings.Contains(out.String(), "pipelock "+command+" --config "+initCommandQuote(abs, runtime.GOOS)) {
			t.Fatalf("missing config for %s: %s", command, &out)
		}
	}
	if strings.Contains(out.String(), "DLP working") || !strings.Contains(out.String(), "do not prove a real client") {
		t.Fatalf("scope missing: %s", &out)
	}
}

func TestInitCommandQuoteWindows(t *testing.T) {
	if got := initCommandQuote(`C:\Jane's files\$policy.yaml`, "windows"); got != `'C:\Jane''s files\$policy.yaml'` {
		t.Fatalf("PowerShell quote = %s", got)
	}
}

func TestInitJSONIdentifiesCheckSourceAndScope(t *testing.T) {
	for _, source := range []string{"saved", "retained", "proposed"} {
		t.Run(source, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "pipelock.yaml")
			if source == "retained" {
				if err := os.WriteFile(path, []byte("mode: balanced\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			if err := runInit(cmd, initOptions{preset: config.ModeBalanced, scanHome: home, output: path, noAuditor: true, jsonOutput: true, dryRun: source == "proposed"}); err != nil {
				t.Fatal(err)
			}
			var result initResult
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Setup.Source != source || result.Setup.ConfigPath != path || !strings.Contains(result.Scope, "does not verify real client routing") {
				t.Fatalf("incorrect provenance: %s", &out)
			}
			if !result.Canary.Detected || !strings.Contains(result.Canary.Detail, "client routing was not tested") {
				t.Fatalf("incorrect canary scope: %s", &out)
			}
		})
	}
}

func TestInitRetainedConfigWithoutUserBus(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux auditor")
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	home := t.TempDir()
	path := filepath.Join(home, "pipelock.yaml")
	contents := "mode: strict\napi_allowlist: [api.vendor.example]\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	if err := runInit(cmd, initOptions{preset: config.ModeBalanced, scanHome: home, output: path, jsonOutput: true}); err == nil {
		t.Fatal("retained canary failure was hidden by systemd skip")
	}
	var result initResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Auditor.Status != auditorStatusSkippedNoSystemd || result.Canary.Detected {
		t.Fatalf("incorrect result: %s", &out)
	}
}
