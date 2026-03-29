// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	plsentry "github.com/luckyPipewrench/pipelock/internal/sentry"
)

// NOTE: Most mcp tests in the original cli package use rootCmd() which stays
// in internal/cli. Those tests cannot be moved here until the wiring step
// connects runtime commands to the root command. Only self-contained tests
// are included in this file.

func TestSafeWriter(t *testing.T) {
	var buf bytes.Buffer
	sw := &safeWriter{w: &buf}

	data := []byte("test-safe-writer")
	n, err := sw.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}
	if buf.String() != string(data) {
		t.Errorf("expected %q, got %q", string(data), buf.String())
	}
}

func TestBuildRedirectRT_WithFetchListen(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.FetchProxy.Listen = "127.0.0.1:8888"
	cfg.MCPToolPolicy.QuarantineDir = "/tmp/test-quarantine"

	rt := buildRedirectRT(cfg)
	if rt == nil {
		t.Fatal("expected non-nil RedirectRuntime")
	}

	const wantEndpoint = "http://127.0.0.1:8888/fetch"
	if rt.FetchEndpoint != wantEndpoint {
		t.Errorf("expected %s, got %q", wantEndpoint, rt.FetchEndpoint)
	}

	const wantQDir = "/tmp/test-quarantine"
	if rt.QuarantineDir != wantQDir {
		t.Errorf("expected %s, got %q", wantQDir, rt.QuarantineDir)
	}
}

func TestBuildRedirectRT_WildcardIPv4(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.FetchProxy.Listen = "0.0.0.0:9999"

	rt := buildRedirectRT(cfg)

	const wantEndpoint = "http://127.0.0.1:9999/fetch"
	if rt.FetchEndpoint != wantEndpoint {
		t.Errorf("expected 127.0.0.1 for wildcard, got %q", rt.FetchEndpoint)
	}
}

func TestBuildRedirectRT_WildcardIPv6(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.FetchProxy.Listen = "[::]:9999"

	rt := buildRedirectRT(cfg)

	const wantEndpoint = "http://[::1]:9999/fetch"
	if rt.FetchEndpoint != wantEndpoint {
		t.Errorf("expected [::1] for IPv6 wildcard, got %q", rt.FetchEndpoint)
	}
}

func TestBuildRedirectRT_EmptyListen(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.FetchProxy.Listen = ""
	cfg.MCPToolPolicy.QuarantineDir = "/tmp/qdir"

	rt := buildRedirectRT(cfg)
	if rt == nil {
		t.Fatal("expected non-nil even without fetch")
	}
	if rt.FetchEndpoint != "" {
		t.Errorf("expected empty FetchEndpoint, got %q", rt.FetchEndpoint)
	}

	const wantQDir = "/tmp/qdir"
	if rt.QuarantineDir != wantQDir {
		t.Errorf("QuarantineDir should still be set, got %q", rt.QuarantineDir)
	}
}

func TestBuildRedirectRT_PortOnly(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.FetchProxy.Listen = ":8888"

	rt := buildRedirectRT(cfg)

	const wantEndpoint = "http://127.0.0.1:8888/fetch"
	if rt.FetchEndpoint != wantEndpoint {
		t.Errorf("expected 127.0.0.1 for empty host, got %q", rt.FetchEndpoint)
	}
}

func TestBuildRedirectRT_InvalidListen(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.FetchProxy.Listen = "not-a-valid-host-port"

	rt := buildRedirectRT(cfg)
	if rt == nil {
		t.Fatal("expected non-nil even with invalid listen")
	}
	if rt.FetchEndpoint != "" {
		t.Errorf("expected empty FetchEndpoint for invalid listen, got %q", rt.FetchEndpoint)
	}
}

func TestBuildRedirectRT_DefaultQuarantineDir(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	// Don't override QuarantineDir -- should use the config default.

	rt := buildRedirectRT(cfg)
	want := filepath.Join(os.TempDir(), "pipelock-quarantine")
	if rt.QuarantineDir != want {
		t.Errorf("expected QuarantineDir=%q, got %q", want, rt.QuarantineDir)
	}
}

func TestHandleProxyError_SubprocessExit(t *testing.T) {
	inner := fmt.Errorf("%w: exit status 2", mcp.ErrSubprocessExit)
	var logBuf bytes.Buffer

	err := handleProxyError(inner, &logBuf, nil)
	if err == nil {
		t.Fatal("expected non-nil error")
	}

	// Should wrap as ExitError with ExitSubprocess code.
	got := cliutil.ExitCodeOf(err)
	if got != cliutil.ExitSubprocess {
		t.Errorf("exit code = %d, want %d", got, cliutil.ExitSubprocess)
	}

	// Should log the error to logW.
	if !strings.Contains(logBuf.String(), "subprocess exited") {
		t.Errorf("expected log message containing 'subprocess exited', got %q", logBuf.String())
	}
}

func TestHandleProxyError_OtherError(t *testing.T) {
	other := errors.New("connection refused")
	var logBuf bytes.Buffer

	err := handleProxyError(other, &logBuf, nil)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.Is(err, other) {
		t.Errorf("expected original error, got %v", err)
	}

	// Should NOT log subprocess message for non-subprocess errors.
	if logBuf.Len() != 0 {
		t.Errorf("expected no log output for non-subprocess error, got %q", logBuf.String())
	}
}

func TestHandleProxyError_OtherErrorWithSentry(t *testing.T) {
	other := errors.New("connection refused")
	var logBuf bytes.Buffer

	// Non-nil client (enabled=false zero value) — exercises the
	// sentryClient != nil branch without needing a real DSN.
	client := &plsentry.Client{}

	err := handleProxyError(other, &logBuf, client)
	if !errors.Is(err, other) {
		t.Errorf("expected original error, got %v", err)
	}
}
