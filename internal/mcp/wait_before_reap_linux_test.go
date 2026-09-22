// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// TestExecuteDeferApprovalResolver_ConcurrentChildSurvivesCleanup isolates the
// process-wide descendant sweep from other tests, then keeps a real resolver
// pending while a sibling finishes or the proxy cleanup mechanism runs.
func TestExecuteDeferApprovalResolver_ConcurrentChildSurvivesCleanup(t *testing.T) {
	const helperEnv = "PIPELOCK_TEST_RESOLVER_CLEANUP"
	scenario := os.Getenv(helperEnv)
	if scenario == "" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatalf("locating the test executable: %v", err)
		}
		for _, name := range []string{"ordinary_completion", "resolver_completion", "adopted_sweep", "failed_start", "cancellation"} {
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(30*time.Second))
				defer cancel()
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestExecuteDeferApprovalResolver_ConcurrentChildSurvivesCleanup$") // #nosec G204 -- re-executes this test binary
				cmd.Env = append(os.Environ(), helperEnv+"="+name)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("resolver cleanup subprocess: %v\n%s", err, output)
				}
			})
		}
		return
	}

	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	releasePath := filepath.Join(dir, "release")
	if err := syscall.Mkfifo(releasePath, 0o600); err != nil {
		t.Fatalf("creating resolver release pipe: %v", err)
	}
	// Opening both ends lets cleanup complete even if the resolver was killed.
	release, err := os.OpenFile(filepath.Clean(releasePath), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("opening resolver release pipe: %v", err)
	}
	t.Cleanup(func() { _ = release.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(15*time.Second))
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("resolver fixture has no deadline")
	}
	held := deferred.HeldAction{Deadline: deadline}
	profile := config.DeferResolverProfile{Exec: []string{
		"/bin/sh", "-c", `umask 077; printf '%s' "$$" > "$1"; read -r decision < "$2"; printf '%s' "$decision"`,
		"resolver", readyPath, releasePath,
	}}
	type result struct {
		decision string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		decision, runErr := executeDeferApprovalResolver(ctx, held, "pending", profile, "{}", nil, io.Discard)
		done <- result{decision: decision, err: runErr}
	}()
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Error("resolver fixture did not stop during cleanup")
			}
		}
	})
	var pid int
	testwait.For(t, 5*time.Second, func() bool {
		data, readErr := os.ReadFile(filepath.Clean(readyPath))
		if readErr != nil {
			return false
		}
		pid, readErr = strconv.Atoi(strings.TrimSpace(string(data)))
		return readErr == nil && pid > 0
	}, "the pending approval resolver to become ready")

	switch scenario {
	case "resolver_completion":
		short := config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}}
		decision, runErr := executeDeferApprovalResolver(ctx, held, "short", short, "{}", nil, io.Discard)
		if runErr != nil || decision != config.ActionAllow {
			t.Fatalf("short resolver = %q, %v; want allow", decision, runErr)
		}
	case "adopted_sweep":
		killAdoptedDescendants()
	case "failed_start":
		missing := config.DeferResolverProfile{Exec: []string{filepath.Join(dir, "absent-resolver")}}
		decision, runErr := executeDeferApprovalResolver(ctx, held, "missing", missing, "{}", nil, io.Discard)
		if runErr == nil || decision != config.ActionBlock {
			t.Fatalf("missing resolver = %q, %v; want block and start error", decision, runErr)
		}
	case "cancellation":
		cancel()
	case "ordinary_completion":
	default:
		t.Fatalf("unknown resolver fixture scenario %q", scenario)
	}
	if scenario != "cancellation" {
		if _, err := fmt.Fprintln(release, config.ActionAllow); err != nil {
			t.Fatalf("releasing pending resolver: %v", err)
		}
	}
	select {
	case got := <-done:
		finished = true
		if scenario == "cancellation" {
			if got.decision != config.ActionBlock || !errors.Is(got.err, context.Canceled) {
				t.Fatalf("canceled resolver = %q, %v; want block and cancellation", got.decision, got.err)
			}
		} else if got.err != nil || got.decision != config.ActionAllow {
			t.Fatalf("pending resolver after %s = %q, %v; want allow", scenario, got.decision, got.err)
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("pending resolver did not complete after release")
	}
	if isProtectedDirectPID(pid) {
		t.Fatal("completed resolver retained its direct-child protection")
	}
}

func TestWaitForCommandWithProcessGroup_CancellationAfterReapingUsesStableHandle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", "umask 077; while :; do :; done")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting resolver command: %v", err)
	}
	reaped := false

	// Model cmd.Wait winning the race. pgid is deliberately zero: a stale
	// numeric-group path is a no-op here, so only the stable process handle can
	// release the still-running command and let the helper return.
	handoff := &processExitHandoff{}
	handoff.beginReaping()
	done := make(chan error, 1)
	go func() {
		done <- waitForCommandWithProcessGroup(ctx, cmd, 0, handoff)
	}()
	t.Cleanup(func() {
		if reaped {
			return
		}
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(testwait.Deadline(5 * time.Second)):
		}
	})

	select {
	case err := <-done:
		reaped = true
		if err == nil {
			t.Fatal("resolver command exited cleanly after forced teardown")
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("resolver teardown did not use the stable process handle after reaping began")
	}
}
