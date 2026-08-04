// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/integrity"
)

func TestRunProxyIntegrityExecutesHashedDescriptorAfterSymlinkSwap(t *testing.T) {
	truePath, trueHash, err := integrity.ResolveAndHash("true")
	if err != nil {
		t.Fatalf("resolve true: %v", err)
	}
	falsePath, _, err := integrity.ResolveAndHash("false")
	if err != nil {
		t.Fatalf("resolve false: %v", err)
	}
	dir := t.TempDir()
	commandPath := filepath.Join(dir, "server")
	if err := os.Symlink(truePath, commandPath); err != nil {
		t.Fatalf("create initial symlink: %v", err)
	}
	manifestPath := writeFDExecManifest(t, map[string]string{truePath: trueHash})

	swapped := false
	opts := testOpts(testScannerWithAction(t, config.ActionWarn))
	opts.IntegrityCfg = &config.MCPBinaryIntegrity{
		Enabled:      true,
		ManifestPath: manifestPath,
		Action:       config.ActionBlock,
	}
	opts.afterIntegrityPreparedForTest = func() {
		if err := os.Remove(commandPath); err != nil {
			t.Fatalf("remove initial symlink: %v", err)
		}
		if err := os.Symlink(falsePath, commandPath); err != nil {
			t.Fatalf("swap symlink: %v", err)
		}
		swapped = true
	}

	var stdout bytes.Buffer
	var stderr syncBuffer
	if err := RunProxy(context.Background(), strings.NewReader(""), &stdout, &stderr, []string{commandPath}, opts); err != nil {
		t.Fatalf("descriptor-bound server returned error after swap: %v (stderr: %s)", err, stderr.String())
	}
	if !swapped {
		t.Fatal("test did not swap the pathname between verification and exec")
	}
}

func TestRunProxyIntegrityPreservesArgvZeroAndClosesExecutableFD(t *testing.T) {
	if os.Getenv("PIPELOCK_FD_EXEC_CHILD") == "1" {
		expected := os.Getenv("PIPELOCK_FD_EXEC_ARGV0")
		if os.Args[0] != expected {
			_, _ = fmt.Fprintf(os.Stderr, "argv[0]=%q want %q\n", os.Args[0], expected)
			os.Exit(91)
		}
		if target, err := os.Readlink("/proc/self/fd/3"); err == nil && target == os.Getenv("PIPELOCK_FD_EXEC_TARGET") {
			_, _ = fmt.Fprintf(os.Stderr, "executable fd 3 leaked as %q\n", target)
			os.Exit(92)
		}
		_, _ = fmt.Println(`{"jsonrpc":"2.0","id":1,"result":{"fd_exec":true}}`)
		return
	}

	executablePath, executableHash, err := integrity.ResolveAndHash(os.Args[0])
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	commandPath := filepath.Join(t.TempDir(), "argv-zero-server")
	if err := os.Symlink(executablePath, commandPath); err != nil {
		t.Fatalf("create command symlink: %v", err)
	}
	manifestPath := writeFDExecManifest(t, map[string]string{executablePath: executableHash})
	opts := testOpts(testScannerWithAction(t, config.ActionWarn))
	opts.IntegrityCfg = &config.MCPBinaryIntegrity{Enabled: true, ManifestPath: manifestPath, Action: config.ActionBlock}

	var stdout bytes.Buffer
	var stderr syncBuffer
	err = RunProxy(
		context.Background(),
		strings.NewReader(""),
		&stdout,
		&stderr,
		[]string{commandPath, "-test.run=^TestRunProxyIntegrityPreservesArgvZeroAndClosesExecutableFD$"},
		opts,
		"PIPELOCK_FD_EXEC_CHILD=1",
		"PIPELOCK_FD_EXEC_ARGV0="+commandPath,
		"PIPELOCK_FD_EXEC_TARGET="+executablePath,
	)
	if err != nil {
		t.Fatalf("descriptor child failed: %v (stderr: %s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"fd_exec":true`) {
		t.Fatalf("missing child response: %q", stdout.String())
	}
}

func TestRunProxyIntegrityDescriptorUnavailableDirections(t *testing.T) {
	truePath, trueHash, err := integrity.ResolveAndHash("true")
	if err != nil {
		t.Fatalf("resolve true: %v", err)
	}
	manifestPath := writeFDExecManifest(t, map[string]string{truePath: trueHash})
	originalHelperPath := descriptorHelperPath
	descriptorHelperPath = filepath.Join(t.TempDir(), "missing-proc-self-exe")
	t.Cleanup(func() { descriptorHelperPath = originalHelperPath })

	tests := []struct {
		name    string
		action  string
		wantErr bool
		wantLog string
	}{
		{name: "block_denies", action: config.ActionBlock, wantErr: true},
		{name: "warn_logs_and_allows_unpinned", action: config.ActionWarn, wantLog: "descriptor launch unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOpts(testScannerWithAction(t, config.ActionWarn))
			opts.IntegrityCfg = &config.MCPBinaryIntegrity{Enabled: true, ManifestPath: manifestPath, Action: tt.action}
			var stdout bytes.Buffer
			var stderr syncBuffer
			err := RunProxy(context.Background(), strings.NewReader(""), &stdout, &stderr, []string{"true"}, opts)
			if tt.wantErr && err == nil {
				t.Fatal("descriptor-unavailable enforcement allowed spawn")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("warn compatibility launch failed: %v", err)
			}
			if tt.wantLog != "" && !strings.Contains(stderr.String(), tt.wantLog) {
				t.Fatalf("log %q does not contain %q", stderr.String(), tt.wantLog)
			}
		})
	}
}

func TestRunProxyIntegrityUnpinnableWrapperDirections(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "server")
	const response = `{"jsonrpc":"2.0","id":1,"result":{"shebang":true}}`
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nprintf '%s\\n' '"+response+"'\n"), 0o600); err != nil {
		t.Fatalf("write shebang server: %v", err)
	}
	if err := os.Chmod(scriptPath, 0o700); err != nil {
		t.Fatalf("make shebang server executable: %v", err)
	}
	resolved, hash, err := integrity.ResolveAndHash(scriptPath)
	if err != nil {
		t.Fatalf("hash shebang server: %v", err)
	}
	manifestPath := writeFDExecManifest(t, map[string]string{resolved: hash})

	tests := []struct {
		name       string
		action     string
		wantErr    bool
		wantOutput bool
	}{
		{name: "block_denies", action: config.ActionBlock, wantErr: true},
		{name: "warn_logs_and_runs", action: config.ActionWarn, wantOutput: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOpts(testScannerWithAction(t, config.ActionWarn))
			opts.IntegrityCfg = &config.MCPBinaryIntegrity{Enabled: true, ManifestPath: manifestPath, Action: tt.action}
			var stdout bytes.Buffer
			var stderr syncBuffer
			err := RunProxy(context.Background(), strings.NewReader(""), &stdout, &stderr, []string{scriptPath}, opts)
			if tt.wantErr && err == nil {
				t.Fatal("unpinnable shebang command allowed under enforcement")
			}
			if tt.wantErr && !strings.Contains(err.Error(), "shebang script") {
				t.Fatalf("enforcement failed for the wrong reason: %v", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("warn compatibility launch failed: %v", err)
			}
			if tt.wantOutput && !strings.Contains(stdout.String(), `"shebang":true`) {
				t.Fatalf("missing shebang response: %q (stderr: %s)", stdout.String(), stderr.String())
			}
			if !tt.wantErr && !strings.Contains(stderr.String(), "using unpinned platform launch") {
				t.Fatalf("warn fallback was silent: %q", stderr.String())
			}
		})
	}
}

func TestRunProxyIntegrityInterpreterScriptDirections(t *testing.T) {
	shPath, shHash, err := integrity.ResolveAndHash("sh")
	if err != nil {
		t.Fatalf("resolve sh: %v", err)
	}
	scriptPath := filepath.Join(t.TempDir(), "server.sh")
	const response = `{"jsonrpc":"2.0","id":1,"result":{"interpreter":true}}`
	if err := os.WriteFile(scriptPath, []byte("printf '%s\\n' '"+response+"'\n"), 0o600); err != nil {
		t.Fatalf("write interpreter script: %v", err)
	}
	scriptResolved, scriptHash, err := integrity.ResolveAndHash(scriptPath)
	if err != nil {
		t.Fatalf("hash interpreter script: %v", err)
	}
	manifestPath := writeFDExecManifest(t, map[string]string{shPath: shHash, scriptResolved: scriptHash})

	tests := []struct {
		name       string
		action     string
		wantErr    bool
		wantOutput bool
	}{
		{name: "block_denies_without_fd_leak", action: config.ActionBlock, wantErr: true},
		{name: "warn_logs_and_runs_unpinned", action: config.ActionWarn, wantOutput: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOpts(testScannerWithAction(t, config.ActionWarn))
			opts.IntegrityCfg = &config.MCPBinaryIntegrity{Enabled: true, ManifestPath: manifestPath, Action: tt.action}
			var stdout bytes.Buffer
			var stderr syncBuffer
			err := RunProxy(context.Background(), strings.NewReader(""), &stdout, &stderr, []string{"sh", scriptPath}, opts)
			if tt.wantErr && (err == nil || !strings.Contains(err.Error(), "interpreter command")) {
				t.Fatalf("interpreter enforcement error = %v", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("warn compatibility launch failed: %v", err)
			}
			if tt.wantOutput && !strings.Contains(stdout.String(), `"interpreter":true`) {
				t.Fatalf("missing interpreter response: %q (stderr: %s)", stdout.String(), stderr.String())
			}
			if !tt.wantErr && !strings.Contains(stderr.String(), "using unpinned platform launch") {
				t.Fatalf("warn fallback was silent: %q", stderr.String())
			}
		})
	}
}

func TestRunProxyIntegrityPackageRunnerDirections(t *testing.T) {
	truePath, trueHash, err := integrity.ResolveAndHash("true")
	if err != nil {
		t.Fatalf("resolve true: %v", err)
	}
	commandPath := filepath.Join(t.TempDir(), "npx")
	if err := os.Symlink(truePath, commandPath); err != nil {
		t.Fatalf("create package-runner fixture: %v", err)
	}
	manifestPath := writeFDExecManifest(t, map[string]string{truePath: trueHash})

	tests := []struct {
		name    string
		action  string
		wantErr bool
	}{
		{name: "block_denies_downstream_resolution", action: config.ActionBlock, wantErr: true},
		{name: "warn_logs_and_runs_unpinned", action: config.ActionWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := testOpts(testScannerWithAction(t, config.ActionWarn))
			opts.IntegrityCfg = &config.MCPBinaryIntegrity{Enabled: true, ManifestPath: manifestPath, Action: tt.action}
			var stdout bytes.Buffer
			var stderr syncBuffer
			err := RunProxy(context.Background(), strings.NewReader(""), &stdout, &stderr, []string{commandPath}, opts)
			if tt.wantErr && (err == nil || !strings.Contains(err.Error(), "package runner")) {
				t.Fatalf("package-runner enforcement error = %v", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("warn compatibility launch failed: %v", err)
			}
			if !tt.wantErr && !strings.Contains(stderr.String(), "using unpinned platform launch") {
				t.Fatalf("warn fallback was silent: %q", stderr.String())
			}
		})
	}
}

func writeFDExecManifest(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := integrity.SaveManifest(path, &integrity.Manifest{Version: integrity.ManifestVersion, Entries: entries}); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

// TestExecveatRejectsInvalidInputs covers the failure branches of the raw
// syscall wrapper. Calling execveat with a descriptor that cannot be executed
// returns rather than replacing the process, so these are safe to exercise
// in-process.
//
// Each one is a path where the helper must exit non-zero instead of
// continuing: a silent failure here would leave the parent believing a
// verified descriptor was executed when nothing was.
func TestExecveatRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		argv    []string
		env     []string
		wantErr string
	}{
		{name: "empty_argv", wantErr: "empty argv"},
		{name: "invalid_argv", argv: []string{"bad\x00arg"}, wantErr: "building argv"},
		{name: "invalid_environment", argv: []string{"server"}, env: []string{"BAD=bad\x00value"}, wantErr: "building environment"},
		{name: "invalid_descriptor", argv: []string{"server"}, wantErr: "execveat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := execveat(-1, tt.argv, tt.env)
			if err == nil {
				t.Fatal("execveat() error = nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("execveat() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// TestPrepareBinaryIntegrity_ActionDirections covers the two directions of the
// prepare path: a binary whose hash does not match the manifest must block
// under the default action, and must warn-and-continue only when warn was
// asked for explicitly.
//
// The direction is the whole point. If the blocking branch were skipped rather
// than taken, a server that failed verification would launch anyway, and the
// only visible difference would be a line in a log nobody reads.
//
// The manifest is keyed by RESOLVED PATH, so the test copies a real executable
// to a known absolute path rather than naming a command. An earlier draft used
// a bare command name with a hand-written manifest body; it "passed" because
// the manifest was malformed, not because a hash mismatch was refused, which
// is exactly the kind of green that proves nothing.
func TestPrepareBinaryIntegrity_ActionDirections(t *testing.T) {
	t.Parallel()

	// A hash that cannot match whatever the copied binary really is.
	const wrongHash = "0000000000000000000000000000000000000000000000000000000000000000"

	setup := func(t *testing.T) (binPath, manifestPath string) {
		t.Helper()
		src, err := exec.LookPath("true")
		if err != nil {
			t.Skipf("no 'true' binary available: %v", err)
		}
		payload, err := os.ReadFile(filepath.Clean(src))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		dir := t.TempDir()
		binPath = filepath.Join(dir, "server")
		if err := os.WriteFile(binPath, payload, 0o700); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		manifestPath = filepath.Join(dir, "manifest.json")
		body := `{"version":1,"entries":{"` + binPath + `":"` + wrongHash + `"}}`
		if err := os.WriteFile(manifestPath, []byte(body), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return binPath, manifestPath
	}

	t.Run("block_refuses", func(t *testing.T) {
		t.Parallel()
		binPath, manifestPath := setup(t)
		var logs bytes.Buffer
		icfg := &config.MCPBinaryIntegrity{
			Enabled:      true,
			Action:       config.ActionBlock,
			ManifestPath: manifestPath,
		}
		if _, err := prepareBinaryIntegrity([]string{binPath}, icfg, &logs); err == nil {
			t.Error("a binary whose hash does not match the manifest must not be prepared for launch")
		}
	})

	t.Run("warn_allows_and_says_so", func(t *testing.T) {
		t.Parallel()
		binPath, manifestPath := setup(t)
		var logs bytes.Buffer
		icfg := &config.MCPBinaryIntegrity{
			Enabled:      true,
			Action:       config.ActionWarn,
			ManifestPath: manifestPath,
		}
		if _, err := prepareBinaryIntegrity([]string{binPath}, icfg, &logs); err != nil {
			t.Errorf("warn must not block the launch, got: %v", err)
		}
		if !strings.Contains(logs.String(), "integrity") {
			t.Errorf("warn must record why it allowed the launch, got: %q", logs.String())
		}
	})
}
