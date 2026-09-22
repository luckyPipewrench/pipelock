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

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// TestDeferResolverPipeLifecycle checks group termination, bounded output waits,
// and preservation of another resolver's child as separate guarantees. Orphan
// adoption is process-wide, so each fixture runs in an isolated process.
func TestDeferResolverPipeLifecycle(t *testing.T) {
	const helperEnv = "PIPELOCK_TEST_RESOLVER_PIPE_LIFECYCLE"
	scenario := os.Getenv(helperEnv)
	if scenario == "" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"group_holder", "unadopted_holder", "other_resolver_adopted_holder"} {
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(30*time.Second))
				defer cancel()
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestDeferResolverPipeLifecycle$") // #nosec G204 -- re-executes this test binary
				cmd.Env = append(os.Environ(), helperEnv+"="+name)
				cmd.WaitDelay = time.Second
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("resolver pipe fixture: %v\n%s", err, output)
				}
			})
		}
		return
	}

	adopt := scenario == "other_resolver_adopted_holder"
	sameGroup := scenario == "group_holder"
	if scenario != "unadopted_holder" && !adopt && !sameGroup {
		t.Fatalf("unknown fixture %q", scenario)
	}
	var subreaper uintptr
	if adopt || sameGroup {
		subreaper = 1
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, subreaper, 0, 0, 0); err != nil {
		t.Fatalf("configure isolated subreaper: %v", err)
	}

	dir := t.TempDir()
	ready := filepath.Join(dir, "holder.pid")
	ack := filepath.Join(dir, "holder.finished")
	holderPipe := filepath.Join(dir, "holder.pipe")
	ownerPipe := filepath.Join(dir, "owner.pipe")
	holderRelease := resolverFixturePipe(t, holderPipe)
	ownerRelease := resolverFixturePipe(t, ownerPipe)
	holderScript := filepath.Join(dir, "holder.sh")
	if err := os.WriteFile(holderScript, []byte("umask 077\nprintf '%s' \"$$\" > \"$1\"\nread -r release < \"$2\"\nprintf finished > \"$3\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := "setsid /bin/sh \"$1\" \"$2\" \"$3\" \"$4\" &\nwhile [ ! -s \"$2\" ]; do :; done\nprintf allow"
	if sameGroup {
		// Keep the holder in the resolver's group. Only the resolver is released;
		// its blocked child must be terminated by production completion cleanup.
		command = "/bin/sh \"$1\" \"$2\" \"$3\" \"$4\" &\nread -r decision < \"$5\"\nprintf '%s' \"$decision\""
	} else if adopt {
		// The intermediate shell exits while the owning resolver stays alive.
		// Its detached child is then adopted by this test's subreaper.
		command = "/bin/sh -c 'setsid /bin/sh \"$1\" \"$2\" \"$3\" \"$4\" &' fixture \"$1\" \"$2\" \"$3\" \"$4\"\nread -r decision < \"$5\"\nprintf '%s' \"$decision\""
	}
	profile := config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", command, "fixture", holderScript, ready, holderPipe, ack, ownerPipe}}
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(20*time.Second))
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("fixture deadline missing")
	}
	held := deferred.HeldAction{Deadline: deadline}
	type result struct {
		decision string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		decision, err := executeDeferApprovalResolver(ctx, held, "pipe-fixture", profile, "{}", nil, io.Discard)
		done <- result{decision, err}
	}()
	finished := false
	var holder *os.Process
	t.Cleanup(func() {
		_, _ = fmt.Fprintln(holderRelease, "finish")
		_, _ = fmt.Fprintln(ownerRelease, config.ActionBlock)
		if holder != nil {
			_ = holder.Kill()
			if adopt || sameGroup {
				_, _ = holder.Wait()
			} else {
				_ = holder.Release()
			}
		}
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Error("resolver fixture failed to drain during cleanup")
			}
		}
	})
	var pid int
	testwait.For(t, 5*time.Second, func() bool {
		data, err := os.ReadFile(filepath.Clean(ready))
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
		return err == nil && pid > 0
	}, "the detached pipe holder to start")
	var err error
	holder, err = os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if sameGroup {
		if !processAlive(pid) {
			t.Fatal("group holder exited before resolver completion")
		}
		if _, err := fmt.Fprintln(ownerRelease, config.ActionAllow); err != nil {
			t.Fatal(err)
		}
	}
	if adopt {
		testwait.For(t, 5*time.Second, func() bool {
			var status syscall.WaitStatus
			got, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
			return err == nil && got == 0
		}, "the live pipe holder to be adopted")
		short := config.DeferResolverProfile{Exec: []string{"/bin/sh", "-c", "printf allow"}}
		decision, err := executeDeferApprovalResolver(ctx, held, "short", short, "{}", nil, io.Discard)
		if err != nil || decision != config.ActionAllow {
			t.Fatalf("short resolver = %q, %v; want allow", decision, err)
		}
		// This is a preservation check, not orphan cleanup. The holder must
		// still perform work after the unrelated resolver has completed.
		if _, err := fmt.Fprintln(holderRelease, "finish"); err != nil {
			t.Fatal(err)
		}
		testwait.For(t, 3*time.Second, func() bool {
			data, err := os.ReadFile(filepath.Clean(ack))
			return err == nil && string(data) == "finished"
		}, "the other resolver's adopted child to finish its work")
		if _, err := fmt.Fprintln(ownerRelease, config.ActionAllow); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case got := <-done:
		finished = true
		if adopt || sameGroup {
			if got.err != nil || got.decision != config.ActionAllow {
				t.Fatalf("owning resolver = %q, %v; want allow", got.decision, got.err)
			}
		} else if got.decision != config.ActionBlock || !errors.Is(got.err, exec.ErrWaitDelay) {
			t.Fatalf("incomplete output = %q, %v; want block and ErrWaitDelay", got.decision, got.err)
		}
	case <-time.After(testwait.Deadline(8 * time.Second)):
		t.Fatal("resolver wait stayed blocked on inherited output")
	}
	if sameGroup {
		// Collect the adopted child only to inspect how it exited. No fixture
		// release or signal may provide the production termination under test.
		var status syscall.WaitStatus
		testwait.For(t, 3*time.Second, func() bool {
			got, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
			if err != nil {
				t.Fatalf("collect terminated group holder: %v", err)
			}
			return got == pid
		}, "production cleanup to terminate the blocked group holder")
		_ = holder.Release()
		holder = nil
		if !status.Signaled() || (status.Signal() != syscall.SIGTERM && status.Signal() != syscall.SIGKILL) {
			t.Fatalf("group holder exit = %v; want production TERM or KILL", status)
		}
		if _, err := os.Stat(ack); !os.IsNotExist(err) {
			t.Fatalf("group holder completed through its release pipe: %v", err)
		}
	}
}

// resolverFixturePipe opens both FIFO ends so cleanup never needs a surviving
// reader before it can release or terminate a fixture process.
func resolverFixturePipe(t *testing.T, path string) *os.File {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
