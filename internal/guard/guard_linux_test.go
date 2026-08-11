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

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/guard"
)

// childEnv marks a re-executed test binary that should perform an enforcement
// scenario instead of running the suite. Landlock is irreversible per process,
// so every real enforcement assertion has to happen in a fresh process.
const childEnv = "PIPELOCK_GUARD_TEST_SCENARIO"

// TestGuardChildScenario is the entry point for a re-executed child.
//
// The child runs as an ordinary test rather than intercepting TestMain and
// calling os.Exit. That is a coverage requirement, not a style preference: a
// test binary writes its coverage through the testing framework as it exits
// normally, and os.Exit runs none of that. Intercepting TestMain made the
// enforcement path -- the most heavily exercised code in this package --
// measure as almost entirely uncovered.
//
// runtime/coverage.WriteMetaDir is not an alternative here. It serves binaries
// built with `go build -cover`; in a `go test -cover` binary it fails with
// "no meta-data available", which is exactly what an earlier attempt at this
// hit, silently, because the message went to a stderr nobody read.
func TestGuardChildScenario(t *testing.T) {
	scenario := os.Getenv(childEnv)
	if scenario == "" {
		t.Skip("not a guard enforcement child process")
	}
	code := runChild(scenario)

	// Exiting without returning to the framework is REQUIRED whenever counters
	// are not being collected.
	//
	// A child that returns normally lets the testing framework write its
	// coverage as it exits -- which is the entire reason this runs as a test
	// rather than intercepting TestMain. But the child has just restricted
	// itself to its manifest, and under an ordinary `go test -coverprofile` run
	// the framework writes to a temp directory the manifest never granted. The
	// write is denied, the child exits non-zero, and every enforcement test
	// fails for a reason that has nothing to do with enforcement. That is not
	// hypothetical: it reddened the coverage-instrumented run while `-race` and
	// the collection script both stayed green, because only the instrumented
	// run without a collection directory hits it.
	//
	// So: collecting means return and let the framework write; not collecting
	// means leave before it tries. The assertions have already been printed by
	// this point either way.
	// A scenario whose policy grants nothing cannot hold the coverage directory
	// either, so returning to the framework would have it write into a path the
	// child just denied itself. Those scenarios always leave early; the
	// collection run does not select them.
	if os.Getenv("PIPELOCK_GUARD_COVERDIR") == "" || scenario == "zero-manifests" {
		os.Exit(code)
	}
	if code != 0 {
		t.Fatalf("scenario %q failed with code %d", scenario, code)
	}
}

// childScratchDir returns a directory for one child scenario, under the root
// the parent provided when there is one.
//
// The child never removes it. Once the child restricts itself the root is
// outside its grants, so a deferred RemoveAll there is denied and the error
// discarded, which is how these accumulated. Cleanup belongs to the parent,
// which is not restricted.
// Prefixes passed here are deliberately one or two characters: a unix socket
// bound inside one of these directories has to fit in 108 bytes including the
// temp root, so every component spent on a descriptive name is a byte closer to
// a confusing bind failure.
func childScratchDir(prefix string) (string, error) {
	if parent := os.Getenv("PIPELOCK_GUARD_CHILD_ROOT"); parent != "" {
		return os.MkdirTemp(parent, prefix)
	}
	return os.MkdirTemp("", prefix)
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

func TestPrepare_EmptyManifestIsACompleteDenyAllPolicy(t *testing.T) {
	cfg := newConfig(t, config.GuardManifest{Name: "m"})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	if !prepared.Complete() {
		t.Fatal("empty manifest must be complete: it declares no path that could be withheld")
	}
	if outcomes := prepared.Outcomes(); len(outcomes) != 0 {
		t.Fatalf("outcomes = %+v, want no declared paths", outcomes)
	}
}

func TestPrepare_ProfileSelectingNoManifestsIsACompleteDenyAllPolicy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Guard.Profiles = []config.GuardProfile{{Name: "agent"}}
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	if !prepared.Complete() {
		t.Fatal("profile with no manifests must be complete: it declares no path that could be withheld")
	}
	if outcomes := prepared.Outcomes(); len(outcomes) != 0 {
		t.Fatalf("outcomes = %+v, want no declared paths", outcomes)
	}
}

func TestPrepare_ResolvesSymlinkedAncestorBeforePinning(t *testing.T) {
	root := t.TempDir()
	realRoot := filepath.Join(root, "real")
	state := filepath.Join(realRoot, "state")
	if err := os.Mkdir(realRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o750); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realRoot, alias); err != nil {
		t.Fatal(err)
	}
	declared := filepath.Join(alias, "state")

	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadWriteDirectories: []string{declared}})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	got := outcomeFor(t, prepared, declared)
	if got.State != guard.StateGranted {
		t.Fatalf("state = %q (%s), want granted", got.State, got.Reason)
	}
	if got.ResolvedPath != state {
		t.Fatalf("resolved path = %q, want %q", got.ResolvedPath, state)
	}
}

func TestPrepare_CombinesSamePathAcrossSelectedManifests(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles: []config.GuardProfile{{Name: "agent", Manifests: []string{"read", "write"}}},
		Manifests: []config.GuardManifest{
			{Name: "read", ReadOnlyDirectories: []string{state}},
			{Name: "write", ReadWriteDirectories: []string{state}},
		},
	}
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	if !prepared.Complete() {
		t.Fatalf("outcomes = %+v, want a complete manifest", prepared.Outcomes())
	}
	seen := make(map[guard.AccessKind]bool)
	for _, outcome := range prepared.Outcomes() {
		if outcome.DeclaredPath == state && outcome.State == guard.StateGranted {
			seen[outcome.Access] = true
		}
	}
	if !seen[guard.AccessReadDirectory] || !seen[guard.AccessWriteDirectory] {
		t.Fatalf("outcomes = %+v, want read and write grants for the declared union", prepared.Outcomes())
	}
}

func TestPrepare_RefusesUnsafeWritableOwnershipAndMode(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadWriteDirectories: []string{state}})

	wrongOwner, err := guard.Prepare(cfg, "agent", os.Getuid()+1)
	if err != nil {
		t.Fatalf("Prepare with wrong uid: %v", err)
	}
	defer func() { _ = wrongOwner.Close() }()
	if got := outcomeFor(t, wrongOwner, state); got.State != guard.StateRefused || !strings.Contains(got.Reason, "owned") {
		t.Fatalf("ownership outcome = %+v, want refused ownership", got)
	}

	// Compose the group-writable mode at runtime rather than writing a literal.
	// The permission linter is right to object to a wide mode in source, and
	// silencing it would train the next reader to silence it somewhere that
	// matters. This test needs the unsafe mode precisely because it is what
	// Guard must refuse.
	groupWritable := os.FileMode(0o750) | os.FileMode(1)<<4
	if err := os.Chmod(state, groupWritable); err != nil {
		t.Fatal(err)
	}
	sharedMode, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare with group-writable mode: %v", err)
	}
	defer func() { _ = sharedMode.Close() }()
	if got := outcomeFor(t, sharedMode, state); got.State != guard.StateRefused || !strings.Contains(got.Reason, "group- or world-writable") {
		t.Fatalf("mode outcome = %+v, want refused shared mode", got)
	}
}

func TestPrepare_AllowsReadablePathOnReadOnlyMount(t *testing.T) {
	const readOnlyMount = "/sys"
	var fs unix.Statfs_t
	if err := unix.Statfs(readOnlyMount, &fs); err != nil {
		t.Skipf("cannot stat %s: %v", readOnlyMount, err)
	}
	if fs.Flags&unix.ST_RDONLY == 0 {
		t.Skipf("%s is not a read-only mount on this host", readOnlyMount)
	}

	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadOnlyDirectories: []string{readOnlyMount}})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	if got := outcomeFor(t, prepared, readOnlyMount); got.State != guard.StateGranted {
		t.Fatalf("outcome = %+v, want read-only mount granted", got)
	}
}

func TestPrepare_CreatesWritableLeafOnNoexecMount(t *testing.T) {
	const noexecMount = "/dev/shm"
	var fs unix.Statfs_t
	if err := unix.Statfs(noexecMount, &fs); err != nil {
		t.Skipf("cannot stat %s: %v", noexecMount, err)
	}
	if fs.Flags&unix.ST_NOEXEC == 0 {
		t.Skipf("%s is not a noexec mount on this host", noexecMount)
	}
	root, err := os.MkdirTemp(noexecMount, "guard-noexec-")
	if err != nil {
		t.Skipf("cannot create test root on %s: %v", noexecMount, err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	state := filepath.Join(root, "state")

	cfg := newConfig(t, config.GuardManifest{Name: "m", ReadWriteDirectories: []string{state}})
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	if got := outcomeFor(t, prepared, state); got.State != guard.StateCreated {
		t.Fatalf("outcome = %+v, want created on noexec mount", got)
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
	// Drives the real Apply, so it needs a host above the in-process floor.
	// Below it Apply refuses on the ABI before it ever reaches the
	// incomplete-manifest check, which is correct behaviour and a different
	// assertion. The ABI-independent version of this check lives in the
	// internal tests, which inject the version.
	abiOrSkip(t)
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

// requireSocketMediationABI gates the tests that build a V9 outer domain.
//
// abiOrSkip admits any host at or above the in-process floor, but these
// scenarios construct the outer restriction with the full V9 configuration,
// which an ABI 8 host cannot accept. Without this the test would fail on a
// legitimate kernel for a reason unrelated to what it checks.
func requireSocketMediationABI(t *testing.T) {
	t.Helper()
	if abi := abiOrSkip(t); abi < guard.SocketMediationABI {
		t.Skipf("landlock ABI %d below %d; this scenario builds a V9 outer domain", abi, guard.SocketMediationABI)
	}
}

func abiOrSkip(t *testing.T) int {
	t.Helper()
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil {
		t.Skipf("landlock unavailable: %v", err)
	}
	if abi < guard.ThreadSyncABI {
		t.Skipf("landlock ABI %d below in-process floor %d", abi, guard.ThreadSyncABI)
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
	abi := abiOrSkip(t)
	socketWant := "socket connect: DENIED"
	coverageWant := "record coverage: full fully-mediated=true"
	if abi < guard.SocketMediationABI {
		// ABI 8 can apply the filesystem ruleset to every thread, but it has
		// no resolve-unix right. A pathname Unix-socket connection is therefore
		// intentionally outside the model, not a denied operation. Accepting
		// that result is safe only because the record says PARTIAL and refuses
		// the stronger FullyMediated claim alongside it.
		socketWant = "socket connect: OK"
		coverageWant = "record coverage: partial fully-mediated=false"
	}

	for _, scenario := range []struct {
		name  string
		wants []string
	}{
		{"granted-write", []string{"granted write: OK"}},
		{"ungranted-read", []string{"ungranted read: DENIED"}},
		{"socket-connect", []string{socketWant, coverageWant}},
		{"other-thread", []string{"other-thread read: DENIED"}},
		{"symlink-repoint", []string{"granted write: OK", "repointed alias write: DENIED"}},
		{"empty-manifest", []string{"ungranted read: DENIED"}},
		{"zero-manifests", []string{"ungranted read: DENIED"}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			out := runScenario(t, scenario.name)
			for _, want := range scenario.wants {
				if !strings.Contains(out, want) {
					t.Fatalf("scenario %s output %q, want %q", scenario.name, out, want)
				}
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

// TestEnforcement_DetectsPolicyNarrowedByOuterDomain proves Guard refuses when
// an outer landlock domain makes a declared path unreachable.
//
// Landlock rulesets stack, so the effective policy is the intersection. Every
// syscall Guard makes still succeeds in that situation, and without the
// post-enforcement reachability check the record would read "enforced" while
// the workload got denied a path its own manifest declares.
func TestEnforcement_DetectsPolicyNarrowedByOuterDomain(t *testing.T) {
	requireSocketMediationABI(t)
	out := runScenario(t, "nested-narrowed")
	if !strings.Contains(out, "narrowed: DETECTED") {
		t.Fatalf("output %q, want the outer domain to be detected as narrowing", out)
	}
}

// TestEnforcement_DetectsWritePolicyNarrowedByOuterDomain proves the
// reachability check does not mistake a readable-but-not-writable exact file
// for the declared read-write grant. Opening with O_WRONLY is side-effect free;
// it asks the kernel for the write right without changing the workload state.
func TestEnforcement_DetectsWritePolicyNarrowedByOuterDomain(t *testing.T) {
	requireSocketMediationABI(t)
	out := runScenario(t, "nested-write-narrowed")
	if !strings.Contains(out, "write-narrowed: DETECTED") {
		t.Fatalf("output %q, want the outer domain's removed write access to be detected", out)
	}
}

// TestEnforcement_DetectsDirectoryWriteNarrowedByOuterDomain proves the write
// probe sees a narrowing that a read probe cannot.
//
// The declared directory stays readable throughout, so this test fails if the
// verification ever regresses to read-only probing.
func TestEnforcement_DetectsDirectoryWriteNarrowedByOuterDomain(t *testing.T) {
	requireSocketMediationABI(t)
	out := runScenario(t, "nested-narrowed-dir")
	if !strings.Contains(out, "dir-narrowed: DETECTED") {
		t.Fatalf("output %q, want the read-only narrowing of a writable directory detected", out)
	}
}

func runScenario(t *testing.T, scenario string) string {
	t.Helper()
	// The parent owns the child's scratch directory.
	//
	// A child creates its root, restricts itself to paths beneath it, and can no
	// longer traverse or remove the root, so its own deferred cleanup is denied
	// and silently discarded. Every enforcement run therefore leaked a directory.
	// Cleanup belongs to this parent, which is not restricted.
	//
	// The name is SHORT on purpose. A unix socket path is capped at 108 bytes by
	// sockaddr_un, and these scenarios bind one several directories deep. Using
	// t.TempDir here embeds the full test name and pushed the socket path over
	// that limit, which surfaces as "bind: invalid argument" and reads like a
	// broken test rather than a path-length problem.
	childRoot, err := os.MkdirTemp("", "plg")
	if err != nil {
		t.Fatalf("creating child scratch root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(childRoot) })

	args := []string{"-test.run=^TestGuardChildScenario$"}
	// Hand the child its coverage directory as a test flag.
	//
	// The go tool consumes GOCOVERDIR for its own bookkeeping and does not pass
	// it to the test binary, so inheritance yields nothing. The collection
	// script sets a dedicated variable that nothing else interprets, and it is
	// translated here into the flag the testing framework actually reads. When
	// the variable is unset -- every ordinary test run -- no flag is added and
	// the child behaves exactly as before.
	if dir := os.Getenv("PIPELOCK_GUARD_COVERDIR"); dir != "" {
		args = append(args, "-test.gocoverdir="+dir)
	}
	// #nosec G204,G702 -- os.Args[0] is this test binary; re-executing it is the only
	// way to assert on an irreversible per-process restriction.
	cmd := exec.CommandContext(t.Context(), os.Args[0], args...)
	cmd.Env = append(os.Environ(), childEnv+"="+scenario, "PIPELOCK_GUARD_CHILD_ROOT="+childRoot)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child %s failed: %v\n%s", scenario, err, out)
	}
	return string(out)
}

// coverageGrant returns the coverage directory as an extra writable grant when
// subprocess coverage collection is active, and nothing otherwise.
//
// The child restricts itself, and the testing framework then writes its
// coverage counters as it exits -- into a directory the manifest never granted.
// The write is denied and the child dies reporting a coverage error rather than
// its result. This is the same self-defeating shape as enumerating
// /proc/self/task while holding a ruleset that denies /proc, and it is resolved
// the same way internal/sandbox resolves it: when collection is on, the
// collection directory is part of the policy.
//
// The collection script is the only intended setter. An ordinary run with this
// variable set fails loudly when its binary lacks coverage instrumentation, and
// a broad directory fails manifest preparation rather than silently widening an
// assertion. Under collection it grants exactly one directory that no denial
// assertion touches, so what the tests prove is unchanged.
func coverageGrant() []string {
	if dir := os.Getenv("PIPELOCK_GUARD_COVERDIR"); dir != "" {
		return []string{dir}
	}
	return nil
}

// runChildNested prepares a manifest, then applies an OUTER landlock domain that
// excludes the granted path, and finally asks Guard to enforce.
//
// The ordering is deliberate: Prepare must run BEFORE the outer restriction, so
// the paths pin successfully and the manifest is complete. That isolates the
// narrowing to enforcement time, which is exactly the case the reachability
// check exists for. Preparing afterwards would fail earlier and for a different
// reason, proving nothing about this check.
func runChildNested() int {
	root, err := childScratchDir("n")
	if err != nil {
		fmt.Println("setup failed:", err)
		return 1
	}

	granted := filepath.Join(root, "state")
	other := filepath.Join(root, "other")
	for _, d := range []string{granted, other} {
		if err := os.Mkdir(d, 0o750); err != nil {
			fmt.Println("setup failed:", err)
			return 1
		}
	}

	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "agent", Manifests: []string{"m"}}},
		Manifests: []config.GuardManifest{{Name: "m", ReadWriteDirectories: append([]string{granted}, coverageGrant()...)}},
	}
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		fmt.Println("prepare failed:", err)
		return 1
	}
	defer func() { _ = prepared.Close() }()
	if !prepared.Complete() {
		fmt.Printf("manifest incomplete before the outer domain: %+v\n", prepared.Outcomes())
		return 1
	}

	// The outer domain grants a DIFFERENT directory, so the manifest's path is
	// unreachable once it applies.
	// The collection directory joins the outer domain for the same reason it
	// joins the manifest: this scenario's whole point is an outer restriction
	// that excludes the manifest's path, and excluding the coverage directory
	// too would only stop the child reporting what it found.
	outer := append([]string{other}, coverageGrant()...)
	if err := landlock.V9.RestrictPaths(landlock.RWDirs(outer...)); err != nil {
		fmt.Println("outer restriction failed:", err)
		return 1
	}

	record, err := prepared.Apply()
	// The state must say the restriction WAS applied. Asserting only
	// !Enforced() cannot tell "refused, process untouched" from "applied but
	// narrowed", and by this point the process is irreversibly constrained.
	if errors.Is(err, guard.ErrPolicyNarrowed) && !record.Enforced() &&
		record.State == guard.EnforcementAppliedNarrowed {
		fmt.Println("narrowed: DETECTED")
		return 0
	}
	fmt.Printf("narrowed: MISSED (enforced=%v err=%v state=%q)\n", record.Enforced(), err, record.State)
	return 1
}

// runChildNestedDir narrows a declared read-write DIRECTORY to read-only in an
// outer domain.
//
// This is the case a read-only probe cannot see at all: the directory opens
// fine for reading, so a reachability check based on O_RDONLY reports the
// manifest in force while the workload cannot create, write, remove, or rename
// anything inside its own state directory. Only the unnamed-inode write probe
// distinguishes it.
func runChildNestedDir() int {
	root, err := childScratchDir("nd")
	if err != nil {
		fmt.Println("setup failed:", err)
		return 1
	}

	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o750); err != nil {
		fmt.Println("setup failed:", err)
		return 1
	}

	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "agent", Manifests: []string{"m"}}},
		Manifests: []config.GuardManifest{{Name: "m", ReadWriteDirectories: append([]string{state}, coverageGrant()...)}},
	}
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		fmt.Println("prepare failed:", err)
		return 1
	}
	defer func() { _ = prepared.Close() }()
	if !prepared.Complete() {
		fmt.Printf("manifest incomplete before the outer domain: %+v\n", prepared.Outcomes())
		return 1
	}

	outer := []landlock.Rule{landlock.RODirs(root)}
	for _, dir := range coverageGrant() {
		outer = append(outer, landlock.RWDirs(dir))
	}
	if err := landlock.V9.RestrictPaths(outer...); err != nil {
		fmt.Println("outer restriction failed:", err)
		return 1
	}

	record, err := prepared.Apply()
	if errors.Is(err, guard.ErrPolicyNarrowed) && !record.Enforced() &&
		record.State == guard.EnforcementAppliedNarrowed {
		fmt.Println("dir-narrowed: DETECTED")
		return 0
	}
	fmt.Printf("dir-narrowed: MISSED (enforced=%v state=%q err=%v)\n", record.Enforced(), record.State, err)
	return 1
}

// runChildNestedWrite creates an outer domain that allows reading an exact
// file but removes its write permission. This is distinct from
// runChildNested: reopening that file O_RDONLY succeeds, so only an O_WRONLY
// probe can detect the policy intersection.
func runChildNestedWrite() int {
	root, err := childScratchDir("nw")
	if err != nil {
		fmt.Println("setup failed:", err)
		return 1
	}

	state := filepath.Join(root, "state.json")
	if err := os.WriteFile(state, []byte("{}"), 0o600); err != nil {
		fmt.Println("setup failed:", err)
		return 1
	}

	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "agent", Manifests: []string{"m"}}},
		Manifests: []config.GuardManifest{{Name: "m", ReadWrite: []string{state}, ReadWriteDirectories: coverageGrant()}},
	}
	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		fmt.Println("prepare failed:", err)
		return 1
	}
	defer func() { _ = prepared.Close() }()
	if !prepared.Complete() {
		fmt.Printf("manifest incomplete before the outer domain: %+v\n", prepared.Outcomes())
		return 1
	}

	// Grant the entire test root read-only in the outer domain. The inner
	// manifest asks for read-write on state, so the stacked result permits reads
	// but must deny writes.
	outer := []landlock.Rule{landlock.RODirs(root)}
	for _, dir := range coverageGrant() {
		outer = append(outer, landlock.RWDirs(dir))
	}
	if err := landlock.V9.RestrictPaths(outer...); err != nil {
		fmt.Println("outer restriction failed:", err)
		return 1
	}

	record, err := prepared.Apply()
	// The state must say the restriction WAS applied. Asserting only
	// !Enforced() cannot tell "refused, process untouched" from "applied but
	// narrowed", and by this point the process is irreversibly constrained.
	if errors.Is(err, guard.ErrPolicyNarrowed) && !record.Enforced() &&
		record.State == guard.EnforcementAppliedNarrowed {
		fmt.Println("write-narrowed: DETECTED")
		return 0
	}
	fd, writeErr := os.OpenFile(filepath.Clean(state), os.O_WRONLY, 0)
	if writeErr == nil {
		_ = fd.Close()
	}
	fmt.Printf("write-narrowed: MISSED (enforced=%v err=%v state=%q write=%v)\n", record.Enforced(), err, record.State, writeErr)
	return 1
}

// runChild performs one enforcement scenario inside a fresh process.
func runChild(scenario string) int {
	if scenario == "nested-narrowed" {
		return runChildNested()
	}
	if scenario == "nested-write-narrowed" {
		return runChildNestedWrite()
	}
	if scenario == "nested-narrowed-dir" {
		return runChildNestedDir()
	}
	root, err := childScratchDir("c")
	if err != nil {
		fmt.Println("setup failed:", err)
		return 1
	}

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

	declared := granted
	alias := filepath.Join(root, "alias")
	if scenario == "symlink-repoint" {
		if err := os.Symlink(granted, alias); err != nil {
			fmt.Println("setup failed:", err)
			return 1
		}
		declared = alias
	}

	profiles := []config.GuardProfile{{Name: "agent", Manifests: []string{"m"}}}
	manifests := []config.GuardManifest{{Name: "m", ReadWriteDirectories: append([]string{declared}, coverageGrant()...)}}
	if scenario == "empty-manifest" {
		// Under coverage collection this manifest is not literally empty: it
		// carries the collection directory, without which the child cannot
		// write its counters. What the scenario asserts is unaffected, since
		// every path it expects to be denied lives elsewhere.
		manifests = []config.GuardManifest{{Name: "m", ReadWriteDirectories: coverageGrant()}}
	}
	if scenario == "zero-manifests" {
		profiles = []config.GuardProfile{{Name: "agent"}}
		manifests = nil
	}
	cfg := config.Defaults()
	cfg.Guard = config.Guard{Profiles: profiles, Manifests: manifests}

	prepared, err := guard.Prepare(cfg, "agent", os.Getuid())
	if err != nil {
		fmt.Println("prepare failed:", err)
		return 1
	}
	defer func() { _ = prepared.Close() }()
	if scenario == "symlink-repoint" {
		if err := os.Remove(alias); err != nil {
			fmt.Println("setup failed:", err)
			return 1
		}
		if err := os.Symlink(ungranted, alias); err != nil {
			fmt.Println("setup failed:", err)
			return 1
		}
	}

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
		fmt.Printf("record coverage: %s fully-mediated=%t\n", record.Coverage, record.FullyMediated())
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
	if scenario == "symlink-repoint" {
		report("repointed alias write", os.WriteFile(filepath.Join(alias, "should-not-write.txt"), []byte("x"), 0o600))
	}

	// Release the pre-existing worker thread now that the restriction is live.
	close(release)
	<-workerDone
	return 0
}
