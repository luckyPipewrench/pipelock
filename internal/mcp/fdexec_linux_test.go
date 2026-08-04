// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"bytes"
	"context"
	"fmt"
	"os"
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

func TestRunProxyIntegrityExecutesHashedScriptDescriptorAfterRename(t *testing.T) {
	shPath, shHash, err := integrity.ResolveAndHash("sh")
	if err != nil {
		t.Fatalf("resolve sh: %v", err)
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "server.sh")
	replacementPath := filepath.Join(dir, "replacement.sh")
	const allowedResponse = `printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"script":"hashed"}}'`
	if err := os.WriteFile(scriptPath, []byte(allowedResponse+"\n"), 0o600); err != nil {
		t.Fatalf("write hashed script: %v", err)
	}
	if err := os.WriteFile(replacementPath, []byte("exit 93\n"), 0o600); err != nil {
		t.Fatalf("write replacement script: %v", err)
	}
	scriptResolved, scriptHash, err := integrity.ResolveAndHash(scriptPath)
	if err != nil {
		t.Fatalf("hash script: %v", err)
	}
	manifestPath := writeFDExecManifest(t, map[string]string{shPath: shHash, scriptResolved: scriptHash})
	opts := testOpts(testScannerWithAction(t, config.ActionWarn))
	opts.IntegrityCfg = &config.MCPBinaryIntegrity{Enabled: true, ManifestPath: manifestPath, Action: config.ActionBlock}
	opts.afterIntegrityPreparedForTest = func() {
		if err := os.Rename(replacementPath, scriptPath); err != nil {
			t.Fatalf("replace script pathname: %v", err)
		}
	}

	var stdout bytes.Buffer
	var stderr syncBuffer
	if err := RunProxy(context.Background(), strings.NewReader(""), &stdout, &stderr, []string{"sh", scriptPath}, opts); err != nil {
		t.Fatalf("descriptor-bound script returned error: %v (stderr: %s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"script":"hashed"`) {
		t.Fatalf("executed replacement rather than hashed script: %q", stdout.String())
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
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nprintf '%s\\n' '"+response+"'\n"), 0o700); err != nil {
		t.Fatalf("write shebang server: %v", err)
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

func writeFDExecManifest(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := integrity.SaveManifest(path, &integrity.Manifest{Version: integrity.ManifestVersion, Entries: entries}); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}
