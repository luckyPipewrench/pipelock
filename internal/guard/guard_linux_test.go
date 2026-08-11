// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/guard"
)

// childEnv marks a re-executed test binary that should perform an enforcement
// scenario instead of running the suite. Landlock is irreversible per process,
// so every real enforcement assertion has to happen in a fresh process.
const childEnv = "PIPELOCK_GUARD_TEST_SCENARIO"

func TestMain(m *testing.M) {
	if scenario := os.Getenv(childEnv); scenario != "" {
		os.Exit(runChild(scenario))
	}
	os.Exit(m.Run())
}

func newConfig(t *testing.T, m config.GuardManifest) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "agent", Manifests: []string{m.Name}}},
		Manifests: []config.GuardManifest{m},
	}
	return cfg
}

func outcomeFor(t *testing.T, p *guard.PreparedManifest, declared string) guard.PathOutcome {
	t.Helper()
	for _, o := range p.Outcomes() {
		if o.DeclaredPath == declared {
			return o
		}
	}
	t.Fatalf("no outcome recorded for %q; got %+v", declared, p.Outcomes())
	return guard.PathOutcome{}
}

// TestPrepare_CreatesMissingWritableLeaf covers the normal first-run state:
// the declared directory does not exist yet.
func TestPrepare_CreatesMissingWritableLeaf(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")

	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadWriteDirectories: []string{state}})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	got := outcomeFor(t, prepared, state)
	if got.State != guard.StateCreated {
		t.Fatalf("state = %q (%s), want %q", got.State, got.Reason, guard.StateCreated)
	}
	info, err := os.Stat(state)
	if err != nil {
		t.Fatalf("declared leaf was not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("created leaf is not a directory")
	}
	// mkdir applies the umask, which can only clear bits, so the result must be
	// at most 0750 and can never be group- or world-writable.
	if perm := info.Mode().Perm(); perm&0o022 != 0 || perm&^os.FileMode(0o750) != 0 {
		t.Fatalf("created leaf mode = %04o, want no more than 0750", perm)
	}
	if !prepared.Complete() {
		t.Fatal("manifest should be complete")
	}
}

// TestPrepare_RerunIsIdempotent covers the state production actually spends
// most of its life in: the directory already exists and holds real content.
func TestPrepare_RerunIsIdempotent(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o750); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(state, "existing.db")
	if err := os.WriteFile(payload, []byte("important"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadWriteDirectories: []string{state}})
	for i := range 3 {
		prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
		if err != nil {
			t.Fatalf("Prepare run %d: %v", i, err)
		}
		got := outcomeFor(t, prepared, state)
		if got.State != guard.StateGranted {
			t.Fatalf("run %d state = %q (%s), want %q", i, got.State, got.Reason, guard.StateGranted)
		}
		_ = prepared.Close()
	}
	// Content and mode must survive; a rerun that recreates or chmods state is
	// a data-loss bug wearing an idempotency costume.
	body, err := os.ReadFile(filepath.Clean(payload))
	if err != nil || string(body) != "important" {
		t.Fatalf("existing content not preserved: body=%q err=%v", body, err)
	}
}

// TestPrepare_MissingParentIsWithheldNotBuilt proves Guard does not build a
// tree under a typo or an unmounted path.
func TestPrepare_MissingParentIsWithheldNotBuilt(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "absent-parent", "state")

	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadWriteDirectories: []string{deep}})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	got := outcomeFor(t, prepared, deep)
	if got.State != guard.StateWithheld {
		t.Fatalf("state = %q, want %q", got.State, guard.StateWithheld)
	}
	if _, err := os.Stat(filepath.Join(root, "absent-parent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("guard created an ancestor directory; it must only create the declared leaf")
	}
	if prepared.Complete() {
		t.Fatal("manifest with a withheld path must not report complete")
	}
}

// TestPrepare_MissingReadPathIsWithheld: a missing read path is never invented.
func TestPrepare_MissingReadPathIsWithheld(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "config.yaml")

	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadOnly: []string{missing}})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	if got := outcomeFor(t, prepared, missing); got.State != guard.StateWithheld {
		t.Fatalf("state = %q, want %q", got.State, guard.StateWithheld)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("guard created a file for a missing read declaration")
	}
}

// TestPrepare_RefusesNonRegularObjects proves the descriptor-level type check
// fires. A socket declared as a writable file must not be granted.
func TestPrepare_RefusesNonRegularObjects(t *testing.T) {
	root := t.TempDir()
	sockPath := filepath.Join(root, "agent.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	defer func() { _ = ln.Close() }()

	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadWrite: []string{sockPath}})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	got := outcomeFor(t, prepared, sockPath)
	if got.State != guard.StateRefused {
		t.Fatalf("state = %q, want %q", got.State, guard.StateRefused)
	}
	if !strings.Contains(got.Reason, "sockets") {
		t.Fatalf("reason should name the object type, got %q", got.Reason)
	}
}

// TestPrepare_RefusesFloorViolation proves the compiled floor still governs.
func TestPrepare_RefusesFloorViolation(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	if err := os.Mkdir(ssh, 0o700); err != nil {
		t.Fatal(err)
	}

	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadOnlyDirectories: []string{ssh}})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	if got := outcomeFor(t, prepared, ssh); got.State != guard.StateRefused {
		t.Fatalf("state = %q (%s), want %q", got.State, got.Reason, guard.StateRefused)
	}
}

// TestApply_RefusesIncompleteManifest proves a partial policy is never
// enforced. This is the fail-direction check: a withheld grant is a DENY, and
// enforcing the remainder would present a narrower policy as the declared one.
func TestApply_RefusesIncompleteManifest(t *testing.T) {
	root := t.TempDir()
	cfg := newConfig(t, config.GuardManifest{
		Name:     "m",
		ReadOnly: []string{filepath.Join(root, "missing.yaml")},
	})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()

	record, err := prepared.Apply()
	if !errors.Is(err, guard.ErrManifestIncomplete) {
		t.Fatalf("err = %v, want ErrManifestIncomplete", err)
	}
	if record.Enforced() {
		t.Fatal("an incomplete manifest reported enforced")
	}
	if record.State != guard.EnforcementRefused {
		t.Fatalf("state = %q, want refused", record.State)
	}
}

func abiOrSkip(t *testing.T) int {
	t.Helper()
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil {
		t.Skipf("landlock unavailable: %v", err)
	}
	if abi < guard.RequiredABI {
		t.Skipf("landlock ABI %d below required %d", abi, guard.RequiredABI)
	}
	return abi
}

// TestEnforcement_RealBoundary is the load-bearing test: it applies the
// restriction in a real subprocess and checks the boundary from the outside.
//
// Unit assertions about rule construction cannot prove enforcement. Only a
// process that has actually been restricted, then attempts the forbidden
// operation, can.
func TestEnforcement_RealBoundary(t *testing.T) {
	abiOrSkip(t)

	for _, scenario := range []struct {
		name string
		want string
	}{
		{"granted-write", "granted write: OK"},
		{"ungranted-read", "ungranted read: DENIED"},
		{"socket-connect", "socket connect: DENIED"},
		{"other-thread", "other-thread read: DENIED"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			out := runScenario(t, scenario.name)
			if !strings.Contains(out, scenario.want) {
				t.Fatalf("scenario %s output %q, want %q", scenario.name, out, scenario.want)
			}
		})
	}
}

// TestEnforcement_NonVacuity proves the assertions above would notice if
// enforcement stopped happening. The child skips Apply entirely; every denial
// the previous test relies on must turn into a success.
func TestEnforcement_NonVacuity(t *testing.T) {
	abiOrSkip(t)

	out := runScenario(t, "no-apply")
	for _, want := range []string{
		"ungranted read: OK",
		"socket connect: OK",
		"other-thread read: OK",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("without Apply the boundary should be absent; output %q missing %q", out, want)
		}
	}
}

func runScenario(t *testing.T, scenario string) string {
	t.Helper()
	// #nosec G204,G702 -- os.Args[0] is this test binary; re-executing it is the only
	// way to assert on an irreversible per-process restriction.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=TestMain")
	cmd.Env = append(os.Environ(), childEnv+"="+scenario)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child %s failed: %v\n%s", scenario, err, out)
	}
	return string(out)
}

// runChild performs one enforcement scenario inside a fresh process.
func runChild(scenario string) int {
	root, err := os.MkdirTemp("", "guard-child-")
	if err != nil {
		fmt.Println("setup failed:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(root) }()

	granted := filepath.Join(root, "state")
	ungranted := filepath.Join(root, "elsewhere")
	for _, d := range []string{granted, ungranted} {
		if err := os.Mkdir(d, 0o750); err != nil {
			fmt.Println("setup failed:", err)
			return 1
		}
	}
	secret := filepath.Join(ungranted, "secret.txt")
	if err := os.WriteFile(secret, []byte("classified"), 0o600); err != nil {
		fmt.Println("setup failed:", err)
		return 1
	}
	// The socket lives OUTSIDE every grant, and is created before the
	// restriction is applied, which is exactly the SSH-agent shape.
	sockPath := filepath.Join(ungranted, "agent.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sockPath)
	if err != nil {
		fmt.Println("setup failed:", err)
		return 1
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	report := func(label string, err error) {
		if err == nil {
			fmt.Printf("%s: OK\n", label)
			return
		}
		fmt.Printf("%s: DENIED (%v)\n", label, err)
	}

	// Start a worker pinned to its OWN OS thread BEFORE the restriction is
	// applied, and hold it there. This is what makes the other-thread assertion
	// non-vacuous: the thread demonstrably predates Apply and never executed it,
	// so if the restriction had been applied to the calling thread alone, this
	// worker would still be able to read the secret. Spawning the worker after
	// Apply would prove nothing, since it could be scheduled onto the very
	// thread that was restricted.
	release := make(chan struct{})
	workerReady := make(chan struct{})
	workerDone := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		close(workerReady)
		<-release
		_, e := os.ReadFile(filepath.Clean(secret))
		report("other-thread read", e)
		close(workerDone)
	}()
	<-workerReady

	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "agent", Manifests: []string{"m"}}},
		Manifests: []config.GuardManifest{{Name: "m", ReadWriteDirectories: []string{granted}}},
	}

	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		fmt.Println("prepare failed:", err)
		return 1
	}
	defer func() { _ = prepared.Close() }()

	if scenario != "no-apply" {
		record, aerr := prepared.Apply()
		if aerr != nil {
			fmt.Println("apply failed:", aerr, record.Describe())
			return 1
		}
		if !record.Enforced() {
			fmt.Println("apply did not enforce:", record.Describe())
			return 1
		}
	}

	report("granted write", os.WriteFile(filepath.Join(granted, "ok.txt"), []byte("x"), 0o600))
	report("ungranted read", func() error {
		_, e := os.ReadFile(filepath.Clean(secret))
		return e
	}())
	report("socket connect", func() error {
		c, e := (&net.Dialer{}).DialContext(context.Background(), "unix", sockPath)
		if e == nil {
			_ = c.Close()
		}
		return e
	}())

	// Release the pre-existing worker thread now that the restriction is live.
	close(release)
	<-workerDone
	return 0
}
