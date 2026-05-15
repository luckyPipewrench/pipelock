// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestDefaultInstallEnvWiresContainmentDefaults(t *testing.T) {
	env := defaultInstallEnv(io.Discard)
	if env.runCmd == nil || env.stat == nil || env.lstat == nil || env.writeFile == nil || env.lookupUser == nil {
		t.Fatal("default env has nil OS hooks")
	}
	if env.proxyUserName != defaultProxyUser || env.agentUserName != defaultAgentUser {
		t.Fatalf("users: proxy=%q agent=%q", env.proxyUserName, env.agentUserName)
	}
	if env.configDir != defaultConfigDir || env.nftRulesPath != defaultNFTRulesPath {
		t.Fatalf("paths not wired to defaults: config=%q nft=%q", env.configDir, env.nftRulesPath)
	}
	if env.proxyPort != defaultProxyPort {
		t.Fatalf("proxy port: got %d want %d", env.proxyPort, defaultProxyPort)
	}
}

const containInstallOperatorUser = "operator"

// fakeCall records one invocation through env.runCmd.
type fakeCall struct {
	name string
	args []string
}

// fakeRunner is a programmable runCmd stand-in. tests register responses
// keyed by full argv joined with spaces. unmatched calls return ("",0,nil)
// so the orchestration doesn't fail just because a test didn't pre-bake a
// response for an idempotent no-op invocation.
type fakeRunner struct {
	mu        sync.Mutex
	calls     []fakeCall
	responses map[string]struct {
		out  string
		code int
		err  error
	}
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{responses: map[string]struct {
		out  string
		code int
		err  error
	}{}}
}

func (f *fakeRunner) on(argv string, out string, code int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[argv] = struct {
		out  string
		code int
		err  error
	}{out, code, err}
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) (string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fakeCall{name: name, args: append([]string(nil), args...)})
	key := name + " " + strings.Join(args, " ")
	if r, ok := f.responses[key]; ok {
		return r.out, r.code, r.err
	}
	return "", 0, nil
}

// argvFor builds the lookup key matching fakeRunner.run.
func argvFor(name string, args ...string) string {
	return name + " " + strings.Join(args, " ")
}

// newFakeEnv builds an installEnv backed by tmpdirs and fake hooks. The
// filesystem-side fields (chown, mkdirAll, etc.) are wired to real os
// calls operating under root, the tmpdir constructed for the test; the
// shell-out fields use a fakeRunner.
func newFakeEnv(t *testing.T) (*installEnv, *fakeRunner, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	runner := newFakeRunner()
	out := &bytes.Buffer{}
	env := &installEnv{
		runCmd: runner.run,
		stat:   os.Stat,
		lstat:  os.Lstat,
		readFile: func(p string) ([]byte, error) {
			return os.ReadFile(filepath.Clean(p))
		},
		writeFile: writeFileAtomic,
		removeFile: func(p string) error {
			err := os.Remove(p)
			if err != nil && errors.Is(err, os.ErrNotExist) {
				return err
			}
			return err
		},
		mkdirAll: os.MkdirAll,
		// chown can't really run under non-root tests; record the call and
		// no-op so the orchestration progresses. Tests that need to assert
		// the chown happened can substitute their own hook.
		chown:   func(string, int, int) error { return nil },
		rename:  os.Rename,
		chmod:   os.Chmod,
		symlink: os.Symlink,
		lookupUser: func(name string) (*user.User, error) {
			switch name {
			case "pipelock-proxy":
				return &user.User{Uid: "988", Gid: "988", Username: name, HomeDir: "/var/lib/pipelock-proxy"}, nil
			case "pipelock-agent":
				return &user.User{Uid: "987", Gid: "987", Username: name, HomeDir: "/home/pipelock-agent"}, nil
			case containInstallOperatorUser:
				return &user.User{Uid: "1000", Gid: "1000", Username: name, HomeDir: "/home/operator"}, nil
			}
			return nil, user.UnknownUserError(name)
		},
		selfPath: func() (string, error) { return filepath.Join(root, "src", "pipelock"), nil },
		hashFile: func(p string) (string, error) {
			data, err := os.ReadFile(filepath.Clean(p))
			if err != nil {
				return "", err
			}
			h := sha256.Sum256(data)
			return hex.EncodeToString(h[:]), nil
		},
		out:            out,
		operatorUser:   containInstallOperatorUser,
		proxyUserName:  "pipelock-proxy",
		agentUserName:  "pipelock-agent",
		configDir:      filepath.Join(root, "etc", "pipelock"),
		dataDir:        filepath.Join(root, "var", "lib", "pipelock"),
		wrapperDir:     filepath.Join(root, "usr", "local", "bin"),
		systemUnitPath: filepath.Join(root, "etc", "systemd", "system", "pipelock.service"),
		nftRulesPath:   filepath.Join(root, "etc", "nftables.d", "50-pipelock-containment.nft"),
		nftMainPath:    filepath.Join(root, "etc", "sysconfig", "nftables.conf"),
		sudoersPath:    filepath.Join(root, "etc", "sudoers.d", "50-pipelock-agent"),
		caBundlePath:   filepath.Join(root, "etc", "pipelock", "combined-ca.pem"),
		caExportPath:   filepath.Join(root, "etc", "pipelock", "ca.pem"),
		integrityDir:   filepath.Join(root, "etc", "pipelock", "integrity"),
		integrityPin:   filepath.Join(root, "etc", "pipelock", "integrity", "binary-pin.sha256"),
		wrapperInvPath: filepath.Join(root, "etc", "pipelock", "contain", "wrappers.json"),
		toolsListPath:  filepath.Join(root, "etc", "pipelock", "contain", "tools.list"),
		pipelockTarget: filepath.Join(root, "usr", "local", "bin", "pipelock"),
		proxyPort:      8888,
	}

	// Plant the source binary the install will copy.
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o750); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "pipelock"), []byte("fake pipelock binary"), 0o755); err != nil { //nolint:gosec // test binary fixture must be executable
		t.Fatalf("write fake src: %v", err)
	}
	env.pipelockBinary = filepath.Join(root, "src", "pipelock")

	// Pre-create the wrapperDir so wrapper writes don't fail.
	if err := os.MkdirAll(env.wrapperDir, 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir wrapperDir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(env.sudoersPath), 0o750); err != nil {
		t.Fatalf("mkdir sudoers parent: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(env.systemUnitPath), 0o750); err != nil {
		t.Fatalf("mkdir unit parent: %v", err)
	}
	// Plant a fake system CA bundle the install will read.
	systemBundle := filepath.Join(root, "etc", "ssl", "certs", "ca-bundle.crt")
	if err := os.MkdirAll(filepath.Dir(systemBundle), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir system bundle parent: %v", err)
	}
	if err := os.WriteFile(systemBundle, []byte("# system bundle\n"), 0o600); err != nil {
		t.Fatalf("write fake system bundle: %v", err)
	}
	// Plant a CA export file (will be created during install but we
	// pre-create it so the runner doesn't need to mock the export
	// subprocess writing through pipelock).
	if err := os.MkdirAll(env.configDir, 0o750); err != nil {
		t.Fatalf("mkdir configDir: %v", err)
	}

	// Patch defaultSystemCABundle indirection by overriding readFile so
	// the canonical path resolves to our test path.
	origReadFile := env.readFile
	env.readFile = func(p string) ([]byte, error) {
		if p == defaultSystemCABundle {
			return os.ReadFile(systemBundle) //nolint:gosec // tmpdir-scoped test path
		}
		return origReadFile(p)
	}

	return env, runner, out
}

// ---------------------------------------------------------------------------
// runInstall: root-check coverage lives in TestMutatingSubcommandsRequireRoot
// (verify_test.go). The functions below cover the post-root-check branches.
// ---------------------------------------------------------------------------

func TestRunInstall_RejectsMissingOperatorUser(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.operatorUser = ""
	err := runInstall(context.Background(), env, installOpts{})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
	if !strings.Contains(err.Error(), "operator user not set") {
		t.Errorf("err: %v", err)
	}
}

func TestRunInstall_RejectsInvalidOperatorUser(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	err := runInstall(context.Background(), env, installOpts{operatorUser: "operator\nroot ALL=(ALL) NOPASSWD:ALL"})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
	if !strings.Contains(err.Error(), "invalid operator user") {
		t.Errorf("err: %v", err)
	}
}

func TestRunInstall_RejectsUnknownOperatorUserBeforeMutation(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	err := runInstall(context.Background(), env, installOpts{operatorUser: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
	if !strings.Contains(err.Error(), "lookup operator user ghost") {
		t.Errorf("err: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no mutating commands before operator lookup succeeds, got %v", runner.calls)
	}
}

func TestRunInstall_RejectsMissingConfigSource(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	err := runInstall(context.Background(), env, installOpts{configSource: "/nonexistent/pipelock.yaml"})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
}

func TestRunInstall_RejectsDirectoryConfigSource(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	err := runInstall(context.Background(), env, installOpts{configSource: dir})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("err: %v", err)
	}
}

func TestRunInstall_RejectsMissingBinary(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.pipelockBinary = ""
	env.selfPath = func() (string, error) { return "/nonexistent/pipelock", nil }
	err := runInstall(context.Background(), env, installOpts{})
	if err == nil {
		t.Fatal("expected error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Errorf("exit code: %d", cliutil.ExitCodeOf(err))
	}
}

func TestRunInstall_RejectsBinaryIsDirectory(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.pipelockBinary = t.TempDir() // a dir
	err := runInstall(context.Background(), env, installOpts{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("err: %v", err)
	}
}

func TestRunInstall_SelfPathFallback(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.pipelockBinary = ""
	env.selfPath = func() (string, error) { return "", errors.New("no exe") }
	err := runInstall(context.Background(), env, installOpts{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "locate pipelock binary") {
		t.Errorf("err: %v", err)
	}
}

func TestRunInstall_DryRunSucceedsWithoutMutation(t *testing.T) {
	env, runner, buf := newFakeEnv(t)
	err := runInstall(context.Background(), env, installOpts{dryRun: true})
	if err != nil {
		t.Fatalf("dry-run err: %v", err)
	}
	// Dry-run should NOT have shelled out for any mutation.
	if len(runner.calls) != 0 {
		t.Errorf("dry-run shelled out: %v", runner.calls)
	}
	if !strings.Contains(buf.String(), "planned steps") {
		t.Errorf("missing 'planned steps' header: %q", buf.String())
	}
}

func TestRunInstall_DryRunPrintsPlan(t *testing.T) {
	if os.Geteuid() != 0 {
		// We can't bypass the root check from a unit test. Instead, drive
		// installSteps directly and print the plan to verify content.
		opts := installOpts{dryRun: true}
		steps := installSteps(opts)
		var buf bytes.Buffer
		printPlan(&buf, "header:", steps)
		out := buf.String()
		if !strings.Contains(out, "preflight") || !strings.Contains(out, "install pipelock binary") || !strings.Contains(out, "/etc/sudoers.d/50-pipelock-agent") {
			t.Errorf("plan missing required steps: %q", out)
		}
		// Sanity: the plan should NOT execute anything in dry-run.
		if strings.Contains(out, "[FAIL]") || strings.Contains(out, "[ OK ]") {
			t.Errorf("dry-run plan should not include step outcomes: %q", out)
		}
		return
	}
	t.Skip("root path covered in TestRunInstall_EndToEnd")
}

func TestRunInstall_EndToEndWithExistingUsers(t *testing.T) {
	env, runner, buf := newFakeEnv(t)
	binDir := t.TempDir()
	for _, name := range []string{"useradd", "userdel", "systemctl", "nft", "visudo"} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // executable fixture required for preflight PATH lookup.
			t.Fatalf("write %s: %v", name, err)
		}
	}
	t.Setenv("PATH", binDir)

	// Let the default allow-list find one agent tool without depending on
	// host-global /usr/local/bin contents.
	origStat := env.stat
	env.stat = func(path string) (os.FileInfo, error) {
		if path == "/usr/local/bin/claude" {
			return origStat(env.pipelockBinary)
		}
		return origStat(path)
	}
	if err := os.WriteFile(env.caExportPath, []byte(testPEMCA(t)), 0o600); err != nil {
		t.Fatalf("write ca export: %v", err)
	}

	if err := runInstall(context.Background(), env, installOpts{}); err != nil {
		t.Fatalf("runInstall: %v\noutput:\n%s\ncalls:%+v", err, buf.String(), runner.calls)
	}
	for _, path := range []string{
		env.pipelockTarget,
		env.integrityPin,
		env.systemUnitPath,
		env.nftRulesPath,
		filepath.Join(env.wrapperDir, "plk-launch"),
		filepath.Join(env.wrapperDir, "plk-claude"),
		env.wrapperInvPath,
		env.sudoersPath,
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected install artifact %s: %v", path, err)
		}
	}
	if !strings.Contains(buf.String(), "install complete") {
		t.Fatalf("missing success output:\n%s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// step-level idempotency and rollback
// ---------------------------------------------------------------------------

func TestStepCreateUser_SkipsWhenExists(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	s := stepCreateUser(true) // proxy
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Errorf("expected skip (user already exists in fake lookup), got applied=true; runner=%v", runner.calls)
	}
	if len(runner.calls) != 0 {
		t.Errorf("expected no useradd shell-out, got %v", runner.calls)
	}
}

func TestStepPreflightChecksRequiredBinaries(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	s := stepPreflight(installOpts{})

	t.Run("success", func(t *testing.T) {
		binDir := t.TempDir()
		for _, name := range []string{"useradd", "userdel", "systemctl", "nft", "visudo"} {
			path := filepath.Join(binDir, name)
			if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // executable fixture required for preflight PATH lookup.
				t.Fatalf("write %s: %v", name, err)
			}
		}
		t.Setenv("PATH", binDir)
		applied, err := s.apply(context.Background(), env)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !applied {
			t.Fatal("preflight should report applied=true")
		}
	})

	t.Run("missing binary", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		applied, err := s.apply(context.Background(), env)
		if err == nil {
			t.Fatal("expected missing executable error")
		}
		if applied {
			t.Fatal("missing executable must not report applied")
		}
		if !strings.Contains(err.Error(), "required executable") {
			t.Fatalf("err: %v", err)
		}
	})
}

func TestStepCreateUser_CallsUseradd(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Make the proxy user unknown so apply has to call useradd.
	env.lookupUser = func(name string) (*user.User, error) {
		if name == "pipelock-proxy" {
			return nil, user.UnknownUserError(name)
		}
		return &user.User{Uid: "987", Gid: "987", Username: name}, nil
	}
	s := stepCreateUser(true)
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Errorf("expected applied=true")
	}
	if len(runner.calls) != 1 || runner.calls[0].name != "useradd" {
		t.Errorf("expected one useradd call, got %v", runner.calls)
	}
	if !containsArg(runner.calls[0].args, "pipelock-proxy") {
		t.Errorf("useradd missing target user: %v", runner.calls[0].args)
	}
}

func TestStepWriteSystemUnit_IdempotentOnReapply(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	s := stepWriteSystemUnit()
	a1, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	if !a1 {
		t.Errorf("first apply should write the unit")
	}
	a2, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if a2 {
		t.Errorf("second apply should skip (unit already correct)")
	}
}

func TestStepWriteSystemUnit_UndoRestoresBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// Pre-create a unit file so write triggers backup.
	prior := []byte("[Unit]\nDescription=original\n")
	if err := os.WriteFile(env.systemUnitPath, prior, 0o600); err != nil {
		t.Fatalf("seed unit: %v", err)
	}
	s := stepWriteSystemUnit()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Backup must exist with original contents.
	bak, err := os.ReadFile(env.systemUnitPath + ".bak")
	if err != nil {
		t.Fatalf("read bak: %v", err)
	}
	if string(bak) != string(prior) {
		t.Errorf(".bak contents drift: got %q", bak)
	}
	// Undo must restore.
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	restored, err := os.ReadFile(env.systemUnitPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(restored) != string(prior) {
		t.Errorf("restore drift: got %q", restored)
	}
}

func TestStepInstallPipelockBinary_SkipsWhenIdentical(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	// Run apply once.
	s := stepInstallPipelockBinary()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	// Re-run apply; should skip because hashes match.
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if applied {
		t.Errorf("expected skip when binary already matches")
	}
}

func TestStepWriteIntegrityPin_WritesAndIsIdempotent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	var chowned []string
	env.chown = func(path string, _, _ int) error {
		chowned = append(chowned, path)
		return nil
	}
	// Plant the target binary.
	if err := os.MkdirAll(filepath.Dir(env.pipelockTarget), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.pipelockTarget, []byte("installed pipelock"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("plant target: %v", err)
	}

	pinStep := stepWriteIntegrityPin()
	a1, err := pinStep.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !a1 {
		t.Errorf("first apply should write pin")
	}

	pin, err := os.ReadFile(env.integrityPin)
	if err != nil {
		t.Fatalf("read pin: %v", err)
	}
	want := sha256.Sum256([]byte("installed pipelock"))
	if strings.TrimSpace(string(pin)) != hex.EncodeToString(want[:]) {
		t.Errorf("pin: got %q, want %q", pin, hex.EncodeToString(want[:]))
	}
	if !containsString(chowned, env.integrityDir) {
		t.Errorf("integrity dir was not chowned: %v", chowned)
	}
	if !containsString(chowned, env.integrityPin) {
		t.Errorf("integrity pin was not chowned: %v", chowned)
	}

	a2, err := pinStep.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if a2 {
		t.Errorf("second apply should skip when pin matches")
	}
}

func TestRenderNFTRules_ContainsExpectedRules(t *testing.T) {
	body := renderNFTRules(1000, 988, 987, 8888, "pipelock_containment", "output_filter")
	wantSubstrings := []string{
		`table inet pipelock_containment`,
		`chain output_filter`,
		"meta skuid 1000 accept",
		"meta skuid 988 accept",
		"meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept",
		"meta skuid 987 drop",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(body, s) {
			t.Errorf("rules missing %q in:\n%s", s, body)
		}
	}
}

func TestRenderLaunchWrapper_HasExpectedEnv(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	body := renderLaunchWrapper(env)
	wants := []string{
		"#!/bin/bash",
		"HTTPS_PROXY=http://127.0.0.1:8888",
		"NO_PROXY=127.0.0.1,localhost",
		"NODE_EXTRA_CA_CERTS=" + env.caExportPath,
		"SSL_CERT_FILE=" + env.caBundlePath,
		`"$TARGET"`,
	}
	for _, s := range wants {
		if !strings.Contains(body, s) {
			t.Errorf("plk-launch body missing %q", s)
		}
	}
	// plk-launch must never call sudo as a command — the per-tool wrapper
	// does the outer sudo. We allow the word "sudo" to appear inside
	// comments (describing why we set our own PATH instead of inheriting
	// sudo's secure_path), but NOT as an actual command invocation.
	for _, l := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "sudo ") || strings.HasPrefix(trimmed, "sudo") {
			t.Errorf("plk-launch must NOT use inner sudo (found: %q)", l)
		}
	}
}

func TestRenderToolWrapper_UsesSudo(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	body := renderToolWrapper(env, "claude")
	if !strings.Contains(body, "sudo -n -u pipelock-agent") {
		t.Errorf("missing outer non-interactive sudo: %s", body)
	}
	if !strings.Contains(body, "plk-launch claude") {
		t.Errorf("missing plk-launch dispatch: %s", body)
	}
}

func TestRenderSudoers_HasOperatorAndLauncher(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	body := renderSudoers(env)
	if !strings.Contains(body, "operator ALL=(pipelock-agent) NOPASSWD: ") {
		t.Errorf("sudoers missing rule: %s", body)
	}
	if !strings.Contains(body, "plk-launch *") {
		t.Errorf("sudoers missing glob: %s", body)
	}
}

func TestStepInstallSudoers_VisudoRejectsBadFile(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Make visudo fail validation. The step must roll the file back via
	// restoreBackup so a bad sudoers never persists.
	runner.on(argvFor("visudo", "-cf", env.sudoersPath), "syntax error", 1, nil)
	s := stepInstallSudoers()
	applied, err := s.apply(context.Background(), env)
	if err == nil {
		t.Fatalf("expected visudo rejection error; applied=%v", applied)
	}
	if !strings.Contains(err.Error(), "visudo rejected") {
		t.Errorf("err: %v", err)
	}
	if _, err := os.Stat(env.sudoersPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("bad sudoers must be removed after visudo failure; stat err=%v", err)
	}
}

func TestStepInstallSudoers_IdempotentExistingRule(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.sudoersPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.sudoersPath, []byte(renderSudoers(env)), 0o600); err != nil {
		t.Fatalf("seed sudoers: %v", err)
	}
	s := stepInstallSudoers()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Fatal("expected existing sudoers to skip")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("idempotent sudoers should not run visudo, got %v", runner.calls)
	}
	info, err := os.Stat(env.sudoersPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != modeSudoers {
		t.Fatalf("mode: got 0o%03o want 0o%03o", info.Mode().Perm(), modeSudoers)
	}
}

func TestStepWriteToolWrappers_WritesAllowListedWrappers(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	writeTestToolsList(t, env, []toolsListEntry{{name: "claude", target: "/usr/local/bin/claude"}, {name: "codex", target: "/usr/local/bin/codex"}})
	s := stepWriteToolWrappers()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, tool := range []string{"plk-claude", "plk-codex"} {
		if _, err := os.Stat(filepath.Join(env.wrapperDir, tool)); err != nil {
			t.Errorf("missing wrapper %s: %v", tool, err)
		}
	}
	if _, err := os.Stat(filepath.Join(env.wrapperDir, "plk-playwright")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unexpected unresolved wrapper stat err=%v", err)
	}
}

func TestStepWriteToolWrappers_BackupsStaleDefaultWrapper(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	writeTestToolsList(t, env, []toolsListEntry{{name: "claude", target: "/usr/local/bin/claude"}})
	stale := filepath.Join(env.wrapperDir, "plk-codex")
	if err := os.WriteFile(stale, []byte("old codex wrapper\n"), 0o755); err != nil { //nolint:gosec // executable wrapper fixture
		t.Fatalf("seed stale wrapper: %v", err)
	}
	s := stepWriteToolWrappers()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected stale wrapper backup to apply")
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale wrapper should be moved aside, stat err=%v", err)
	}
	if _, err := os.Stat(stale + ".bak"); err != nil {
		t.Fatalf("stale backup missing: %v", err)
	}
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("stale wrapper not restored: %v", err)
	}
}

func TestStepWriteToolWrappers_UndoRestoresCustomWrapper(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	writeTestToolsList(t, env, []toolsListEntry{{name: "rustup", target: "/usr/local/bin/rustup"}})
	path := filepath.Join(env.wrapperDir, "plk-rustup")
	if err := os.WriteFile(path, []byte("old wrapper\n"), 0o755); err != nil { //nolint:gosec // wrapper fixture
		t.Fatalf("write old wrapper: %v", err)
	}

	s := stepWriteToolWrappers()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected wrapper rewrite")
	}
	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	got, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // test fixture path is under t.TempDir.
	if err != nil {
		t.Fatalf("read restored wrapper: %v", err)
	}
	if string(got) != "old wrapper\n" {
		t.Fatalf("wrapper not restored: %q", got)
	}
}

func TestStepWriteWrapperInventory_RoundTrip(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	writeTestToolsList(t, env, []toolsListEntry{{name: "claude", target: "/usr/local/bin/claude"}})
	s := stepWriteWrapperInventory()
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Idempotency: rerun.
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if applied {
		t.Errorf("expected idempotent no-op on second apply")
	}
	inv := readWrapperInventory(env)
	if !stringSlicesEqual(inv, []string{"plk-claude"}) {
		t.Errorf("inventory: got %v, want [plk-claude]", inv)
	}
}

func TestStepWriteWrapperInventory_UsesToolsListEntries(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	writeTestToolsList(t, env, []toolsListEntry{{name: "rustup", target: "/usr/local/bin/rustup"}})
	if err := os.MkdirAll(filepath.Dir(env.wrapperInvPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir: %v", err)
	}
	body, err := marshalWrapperInventory(wrapperInventory{
		Wrappers: []string{"plk-claude", "plk-rustup"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(env.wrapperInvPath, body, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := stepWriteWrapperInventory()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected inventory rewrite to match tools.list")
	}
	inv := readWrapperInventory(env)
	if !stringSlicesEqual(inv, []string{"plk-rustup"}) {
		t.Fatalf("inventory: %v, want [plk-rustup]", inv)
	}
}

func TestStepWriteWrapperInventory_AddsMissingToolsListWrapper(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	writeTestToolsList(t, env, []toolsListEntry{{name: "claude", target: "/usr/local/bin/claude"}, {name: "rustup", target: "/usr/local/bin/rustup"}})
	if err := os.MkdirAll(filepath.Dir(env.wrapperInvPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir: %v", err)
	}
	body, err := marshalWrapperInventory(wrapperInventory{Wrappers: []string{"plk-rustup"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(env.wrapperInvPath, body, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := stepWriteWrapperInventory()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected missing defaults to be added")
	}
	inv := readWrapperInventory(env)
	if !stringSlicesEqual(inv, []string{"plk-claude", "plk-rustup"}) {
		t.Fatalf("inventory: %v, want [plk-claude plk-rustup]", inv)
	}
}

func writeTestToolsList(t *testing.T, env *installEnv, entries []toolsListEntry) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir tools.list parent: %v", err)
	}
	if err := os.WriteFile(env.toolsListPath, []byte(renderToolsList(entries)), 0o600); err != nil {
		t.Fatalf("write tools.list: %v", err)
	}
}

func TestStepInstallNFTRules_SkipsWhenLoaded(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// Pre-write the file so the body matches.
	operatorUID, proxyUID, agentUID := 1000, 988, 987
	body := renderNFTRules(operatorUID, proxyUID, agentUID, env.proxyPort, defaultNFTTable, defaultNFTChain)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(env.nftMainPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir main config parent: %v", err)
	}
	if err := os.WriteFile(env.nftMainPath, []byte(nftRulesIncludeLine(env.nftRulesPath)+"\n"), 0o600); err != nil {
		t.Fatalf("write main config: %v", err)
	}
	// Make `nft list table` succeed with a healthy live table.
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), body, 0, nil)

	s := stepInstallNFTRules()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied {
		t.Errorf("expected skip when rules file matches and table is loaded")
	}
}

func TestStepInstallNFTRules_ReloadsWhenLoadedTableDrifted(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	operatorUID, proxyUID, agentUID := 1000, 988, 987
	body := renderNFTRules(operatorUID, proxyUID, agentUID, env.proxyPort, defaultNFTTable, defaultNFTChain)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir rules parent: %v", err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(env.nftMainPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir main config parent: %v", err)
	}
	if err := os.WriteFile(env.nftMainPath, []byte(nftRulesIncludeLine(env.nftRulesPath)+"\n"), 0o600); err != nil {
		t.Fatalf("write main config: %v", err)
	}
	drifted := `table inet pipelock_containment {
		chain output_filter {
			meta oif "lo" accept
			meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept
			meta skuid 987 drop
		}
	}
`
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), drifted, 0, nil)

	s := stepInstallNFTRules()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected live drift repair")
	}

	var sawDelete, sawLoad bool
	for _, c := range runner.calls {
		if c.name == testNFT && strings.Join(c.args, " ") == "delete table inet "+defaultNFTTable {
			sawDelete = true
		}
		if c.name == testNFT && len(c.args) == 2 && c.args[0] == "-f" && c.args[1] == env.nftRulesPath {
			sawLoad = true
		}
	}
	if !sawDelete || !sawLoad {
		t.Fatalf("expected delete+reload for live drift, got %v", runner.calls)
	}
}

func TestStepInstallNFTRules_RepairsMissingPersistenceOnRerun(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	operatorUID, proxyUID, agentUID := 1000, 988, 987
	body := renderNFTRules(operatorUID, proxyUID, agentUID, env.proxyPort, defaultNFTTable, defaultNFTChain)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir rules parent: %v", err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), "table inet pipelock_containment {}", 0, nil)

	s := stepInstallNFTRules()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected rerun to repair missing persistence include")
	}
	mainBody, err := os.ReadFile(env.nftMainPath)
	if err != nil {
		t.Fatalf("read main config: %v", err)
	}
	if !strings.Contains(string(mainBody), nftRulesIncludeLine(env.nftRulesPath)) {
		t.Fatalf("main config missing include:\n%s", mainBody)
	}
}

func TestStepInstallNFTRules_LoadsWhenAbsent(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	// nft validate + load + systemctl enable should all succeed by default.
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), "", 1, fmt.Errorf("not loaded"))
	s := stepInstallNFTRules()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Errorf("expected apply=true on fresh install")
	}
	// Verify the file exists.
	if _, err := os.Stat(env.nftRulesPath); err != nil {
		t.Errorf("rules file not written: %v", err)
	}
	// Verify the run sequence included validate then load.
	var sawValidate, sawLoad bool
	for _, c := range runner.calls {
		if c.name == testNFT && len(c.args) >= 2 && c.args[0] == "-c" && c.args[1] == "-f" {
			sawValidate = true
		}
		if c.name == testNFT && len(c.args) >= 1 && c.args[0] == "-f" && (len(c.args) < 2 || c.args[0] != "-c") {
			sawLoad = true
		}
	}
	if !sawValidate || !sawLoad {
		t.Errorf("expected validate + load in run sequence, got %v", runner.calls)
	}
}

func TestStepInstallNFTRules_DropsLoadedTableBeforeChangedReload(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir rules parent: %v", err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte("old broad-loopback rules\n"), 0o600); err != nil {
		t.Fatalf("write old rules: %v", err)
	}
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), "table inet pipelock_containment {}", 0, nil)

	s := stepInstallNFTRules()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected changed rules to apply")
	}

	deleteIdx, loadIdx := -1, -1
	for i, c := range runner.calls {
		if c.name == testNFT && strings.Join(c.args, " ") == "delete table inet "+defaultNFTTable {
			deleteIdx = i
		}
		if c.name == testNFT && len(c.args) == 2 && c.args[0] == "-f" && c.args[1] == env.nftRulesPath {
			loadIdx = i
		}
	}
	if deleteIdx == -1 {
		t.Fatalf("expected nft delete table before reload, got %v", runner.calls)
	}
	if loadIdx == -1 {
		t.Fatalf("expected nft -f reload, got %v", runner.calls)
	}
	if deleteIdx > loadIdx {
		t.Fatalf("delete must precede reload: delete=%d load=%d calls=%v", deleteIdx, loadIdx, runner.calls)
	}
}

func TestStepInstallNFTRules_PersistsViaMainConfigAndRestores(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	original := "flush ruleset\n"
	if err := os.MkdirAll(filepath.Dir(env.nftMainPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir main config parent: %v", err)
	}
	if err := os.WriteFile(env.nftMainPath, []byte(original), 0o600); err != nil {
		t.Fatalf("write main config: %v", err)
	}
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), "", 1, fmt.Errorf("not loaded"))

	s := stepInstallNFTRules()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected apply=true")
	}

	mainBody, err := os.ReadFile(env.nftMainPath)
	if err != nil {
		t.Fatalf("read main config: %v", err)
	}
	if !strings.Contains(string(mainBody), nftRulesIncludeLine(env.nftRulesPath)) {
		t.Fatalf("main config missing include:\n%s", mainBody)
	}

	var sawMainValidation bool
	for _, c := range runner.calls {
		if c.name == testNFT && len(c.args) == 3 && c.args[0] == "-c" && c.args[1] == "-f" && c.args[2] == env.nftMainPath {
			sawMainValidation = true
		}
	}
	if !sawMainValidation {
		t.Fatalf("expected nft -c -f main config validation, got %v", runner.calls)
	}

	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	restored, err := os.ReadFile(env.nftMainPath)
	if err != nil {
		t.Fatalf("read restored main config: %v", err)
	}
	if string(restored) != original {
		t.Fatalf("main config not restored: got %q want %q", restored, original)
	}
}

func TestStepInstallNFTRules_UndoRestoresPreviousLiveTableAndServiceState(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	previousTable := `table inet pipelock_containment {
	chain output_filter {
		meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept
		meta skuid 987 drop
	}
}
`
	runner.on(argvFor(testNFT, "list", "table", "inet", defaultNFTTable), previousTable, 0, nil)
	runner.on(argvFor(testSystemctl, "is-enabled", "nftables.service"), "disabled\n", 1, nil)

	s := stepInstallNFTRules()
	applied, err := s.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected changed nft rules to apply")
	}
	if env.prevNFTTableDump != previousTable {
		t.Fatalf("previous table not captured: %q", env.prevNFTTableDump)
	}
	if !env.prevNftablesStateKnown || env.prevNftablesEnabled {
		t.Fatalf("previous nftables service state not captured as disabled")
	}

	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	restorePath := env.nftRulesPath + ".restore"
	if _, err := os.Stat(restorePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restore file should be removed, stat err=%v", err)
	}
	var sawRestore, sawDisable bool
	for _, c := range runner.calls {
		if c.name == testNFT && len(c.args) == 2 && c.args[0] == "-f" && c.args[1] == restorePath {
			sawRestore = true
		}
		if c.name == testSystemctl && strings.Join(c.args, " ") == "disable nftables.service" {
			sawDisable = true
		}
	}
	if !sawRestore {
		t.Fatalf("expected nft restore from captured table, got %v", runner.calls)
	}
	if !sawDisable {
		t.Fatalf("expected nftables.service disabled-state restore, got %v", runner.calls)
	}
}

func TestStepInstallNFTRules_UndoRemovesManagedIncludeWhenNoBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.nftMainPath), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir main config parent: %v", err)
	}
	body := "flush ruleset\n\n# Pipelock containment persistence\n" + nftRulesIncludeLine(env.nftRulesPath) + "\n"
	if err := os.WriteFile(env.nftMainPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write main config: %v", err)
	}

	if err := restoreOrRemoveNFTMainInclude(env); err != nil {
		t.Fatalf("restore/remove include: %v", err)
	}
	got, err := os.ReadFile(env.nftMainPath)
	if err != nil {
		t.Fatalf("read main config: %v", err)
	}
	if strings.Contains(string(got), nftRulesIncludeLine(env.nftRulesPath)) {
		t.Fatalf("include not removed:\n%s", got)
	}
	if strings.Contains(string(got), "Pipelock containment persistence") {
		t.Fatalf("managed comment not removed:\n%s", got)
	}
}

func TestStepCreateDirRejectsSymlinkTarget(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := stepCreateDir("test", func(*installEnv) string { return link }, modeDirPrivate)
	applied, err := s.apply(context.Background(), env)
	if err == nil {
		t.Fatal("expected symlink target rejection")
	}
	if applied {
		t.Fatal("symlink rejection must not report applied")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err: %v", err)
	}
}

func TestStepCreateDirRejectsSymlinkParent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	root := t.TempDir()
	realParent := filepath.Join(root, "real-parent")
	if err := os.MkdirAll(realParent, 0o750); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	linkParent := filepath.Join(root, "link-parent")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(linkParent, "child")
	s := stepCreateDir("test", func(*installEnv) string { return path }, modeDirPrivate)
	applied, err := s.apply(context.Background(), env)
	if err == nil {
		t.Fatal("expected symlink parent rejection")
	}
	if applied {
		t.Fatal("symlink parent rejection must not report applied")
	}
	if !strings.Contains(err.Error(), "symlink parent") {
		t.Fatalf("err: %v", err)
	}
}

func TestInstallSteps_Count(t *testing.T) {
	// Sanity: the install flow has 21 steps total (20 install + 1 tools.list
	// allow-list). Changing this count is a documented breaking change for
	// the dry-run / verify probe-4 inventory.
	steps := installSteps(installOpts{})
	if len(steps) != 21 {
		t.Errorf("installSteps count: got %d, want 21", len(steps))
	}
}

func TestInstallCmd_Wiring(t *testing.T) {
	cmd := installCmd()
	if cmd.Use != "install" {
		t.Errorf("cmd.Use: %q", cmd.Use)
	}
	if cmd.Flag("dry-run") == nil {
		t.Errorf("--dry-run flag missing")
	}
	if cmd.Flag("pipelock-binary") == nil {
		t.Errorf("--pipelock-binary flag missing")
	}
	if cmd.Flag("config") == nil {
		t.Errorf("--config flag missing")
	}
	if cmd.Flag("proxy-port") == nil {
		t.Errorf("--proxy-port flag missing")
	}
}

func TestInstallCmdRejectsInvalidPortBeforeRootCheck(t *testing.T) {
	cmd := installCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--dry-run", "--proxy-port", "0", "--operator-user", containInstallOperatorUser})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected invalid port error")
	}
	if cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Fatalf("exit code: got %d want %d", cliutil.ExitCodeOf(err), cliutil.ExitConfig)
	}
	if !strings.Contains(err.Error(), "--port") {
		t.Fatalf("err: %v", err)
	}
}

func TestWalkAndChown_NoOpEnvCallsForEveryFile(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	chownCalls := 0
	env.chown = func(string, int, int) error {
		chownCalls++
		return nil
	}
	root := filepath.Join(t.TempDir(), "tree")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil { //nolint:gosec // tmpdir
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "file2"), []byte("y"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := walkAndChown(env, root, 988, 988); err != nil {
		t.Fatalf("walk: %v", err)
	}
	// root + sub + file + file2 = 4 entries.
	if chownCalls != 4 {
		t.Errorf("chown calls: got %d, want 4", chownCalls)
	}
}

func TestPathExists(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if pathExists(env, "/definitely/not/a/real/path/here") {
		t.Errorf("expected false for missing")
	}
	if !pathExists(env, env.pipelockBinary) {
		t.Errorf("expected true for planted source binary")
	}
}

func TestExpectExec_HitsAndMisses(t *testing.T) {
	// /bin/sh exists everywhere we care about.
	if err := expectExec("sh"); err != nil {
		t.Errorf("sh expected to exist: %v", err)
	}
	if err := expectExec("nonexistent-binary-pipelock-test-12345"); err == nil {
		t.Errorf("expected error for missing binary")
	}
}

func TestCollapseWS(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"hello\n  world", "hello world"},
		{"  leading  ", "leading"},
		{"tabs\tand\tnewlines\n", "tabs and newlines"},
		{"", ""},
	}
	for _, c := range cases {
		if got := collapseWS(c.in); got != c.want {
			t.Errorf("collapseWS(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTruncateForErr(t *testing.T) {
	long := strings.Repeat("x", 500)
	got := truncateForErr(long)
	// 200 chars + the UTF-8 ellipsis (3 bytes). Use HasSuffix to avoid
	// hard-coding the rune byte length.
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated string missing ellipsis suffix: %q", got)
	}
	if len(strings.TrimSuffix(got, "…")) != 200 {
		t.Errorf("truncated prefix len: got %d, want 200", len(strings.TrimSuffix(got, "…")))
	}
	if got := truncateForErr("short"); got != "short" {
		t.Errorf("short: %q", got)
	}
}

func TestSHA256HexOfFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(tmp, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := sha256HexOfFile(tmp)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("hash: got %s, want %s", got, want)
	}
}

func TestBackupAndWrite_NewFileNoBak(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "new")
	if err := backupAndWrite(env, path, []byte("data"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); err == nil {
		t.Errorf("unexpected .bak when path was new")
	}
}

func TestWriteFileAtomicWritesContentsAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "atomic")
	if err := writeFileAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := writeFileAtomic(path, []byte("two"), 0o600); err != nil {
		t.Fatalf("write second: %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // tmpdir-scoped test path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "two" {
		t.Fatalf("contents: got %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: got 0o%03o want 0o600", info.Mode().Perm())
	}
}

func TestBackupAndWrite_ExistingPromotesToBak(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := backupAndWrite(env, path, []byte("new"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	bak, err := os.ReadFile(path + ".bak") //nolint:gosec // tmpdir-scoped test path
	if err != nil {
		t.Fatalf("read bak: %v", err)
	}
	if string(bak) != "old" {
		t.Errorf("bak: %q", bak)
	}
	cur, _ := os.ReadFile(path) //nolint:gosec // tmpdir-scoped test path
	if string(cur) != "new" {
		t.Errorf("cur: %q", cur)
	}
}

func TestBackupAndWriteRefusesExistingBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	err := backupAndWrite(env, path, []byte("new"), 0o600)
	if err == nil {
		t.Fatal("expected existing backup guard")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite existing backup") {
		t.Fatalf("err: %v", err)
	}
	got, err := env.readFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(got) != "current" {
		t.Fatalf("current file changed: %q", got)
	}
	bak, err := env.readFile(path + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(bak) != "original" {
		t.Fatalf("backup changed: %q", bak)
	}
}

func TestRestoreBackupIfPresentRestoresOnlyWhenBakExists(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := restoreBackupIfPresent(env, path); err != nil {
		t.Fatalf("restore without backup: %v", err)
	}
	got, err := env.readFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(got) != "current" {
		t.Fatalf("file changed without backup: %q", got)
	}
	if err := os.WriteFile(path+".bak", []byte("backup"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	if err := restoreBackupIfPresent(env, path); err != nil {
		t.Fatalf("restore with backup: %v", err)
	}
	got, err = env.readFile(path)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != "backup" {
		t.Fatalf("restored: got %q want backup", got)
	}
}

func TestRestoreBackup_PromotesBak(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path+".bak", []byte("backup"), 0o600); err != nil {
		t.Fatalf("seed bak: %v", err)
	}
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := restoreBackup(env, path); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, _ := os.ReadFile(path) //nolint:gosec // tmpdir-scoped test path
	if string(got) != "backup" {
		t.Errorf("restored: %q", got)
	}
}

func TestRestoreBackup_RemovesWhenNoBak(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := restoreBackup(env, path); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected path removed; stat err=%v", err)
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
