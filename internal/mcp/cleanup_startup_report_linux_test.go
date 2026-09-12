// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The helper isolates the platform classification from other tests' process-wide
// probe cache. It exercises both launch decisions without changing host policy.
func TestRunProxyWithSandbox_UnsupportedCleanup(t *testing.T) {
	const helperEnv = "PIPELOCK_TEST_UNSUPPORTED_CLEANUP"
	if os.Getenv(helperEnv) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunProxyWithSandbox_UnsupportedCleanup$")
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("unsupported cleanup helper: %v\n%s", err, out)
		}
		return
	}
	defaultCleanupProbe = &cleanupCapabilityProbe{supported: false}
	for _, tt := range []struct {
		name   string
		strict bool
	}{
		{name: "strict", strict: true},
		{name: "best effort"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			var log strings.Builder
			opts := testOpts(testScannerWithAction(t, config.ActionWarn))
			cmd := exec.CommandContext(ctx, "cat")
			err := RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), io.Discard, &log, opts, tt.strict)
			if tt.strict {
				if err == nil || !strings.Contains(err.Error(), "unavailable on this platform") {
					t.Fatalf("strict unsupported cleanup: %v", err)
				}
				if cmd.Process != nil {
					t.Fatal("strict unsupported cleanup started the child")
				}
				return
			}
			if err != nil || cmd.Process == nil {
				t.Fatalf("best-effort unsupported cleanup did not launch: %v", err)
			}
			if !strings.Contains(log.String(), "unavailable on this platform") || strings.Contains(log.String(), "child subreaper enabled") {
				t.Fatalf("best-effort unsupported cleanup report: %q", log.String())
			}
		})
	}
}

// TestRunProxyWithSandbox_StartupCleanupReportedSuppression proves the split
// the startup report introduced: once the caller has reported the orphan-cleanup
// capability at startup, the per-child path must NOT repeat the degraded
// warning, but a strict launch must STILL refuse. Reporting cannot bypass
// strict. The failing probe is injected through the test seam so the direction
// is deterministic on any host.
func TestRunProxyWithSandbox_StartupCleanupReportedSuppression(t *testing.T) {
	failure := errors.New("subreaper unavailable")
	// Generous deadline that a healthy "cat" run cannot reach; the package
	// -timeout is the real backstop. Matches the sibling direction test.
	const deadline = 2 * time.Minute

	t.Run("best effort suppresses duplicate warning when already reported", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		var logBuf syncBuffer
		opts := testOpts(testScannerWithAction(t, config.ActionWarn))
		opts.enableSubreaperForTest = func() error { return failure }
		opts.StartupCleanupReported = true
		cmd := exec.CommandContext(ctx, "cat")
		if err := RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), io.Discard, &logBuf, opts); err != nil {
			if ctx.Err() != nil {
				t.Fatalf("deadline expired before startup finished, so this is a timing failure not a refusal: %v (context: %v)", err, ctx.Err())
			}
			t.Fatalf("best-effort sandbox proxy = %v", err)
		}
		if strings.Contains(logBuf.String(), "session descendant cleanup degraded") {
			t.Errorf("warning should be suppressed when reported at startup, got %q", logBuf.String())
		}
	})

	t.Run("strict still refuses even when reported", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		opts := testOpts(testScannerWithAction(t, config.ActionWarn))
		opts.enableSubreaperForTest = func() error { return failure }
		opts.StartupCleanupReported = true
		cmd := exec.CommandContext(ctx, "cat")
		err := RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), io.Discard, io.Discard, opts, true)
		if !errors.Is(err, failure) {
			if ctx.Err() != nil {
				t.Fatalf("deadline expired before strict mode reported, timing failure not a missing refusal: %v (context: %v)", err, ctx.Err())
			}
			t.Fatalf("strict sandbox proxy error = %v, want subreaper failure (reporting must not bypass strict)", err)
		}
	})
}
