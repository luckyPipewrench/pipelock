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
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

type fakeFileInfo struct {
	mode os.FileMode
	sys  any
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return f.sys }

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
	// nftMainPath must be populated so rollback's legacy-include cleanup
	// (gated on env.nftMainPath != "") is reachable for systems upgraded
	// from a pre-portability build. A regression here silently orphans the
	// `include` line in the distro nft config on rollback.
	if env.nftMainPath != defaultNFTMainConfigPath {
		t.Fatalf("nftMainPath: got %q, want %q (legacy rollback cleanup must stay wired)", env.nftMainPath, defaultNFTMainConfigPath)
	}
	if env.proxyPort != defaultProxyPort {
		t.Fatalf("proxy port: got %d want %d", env.proxyPort, defaultProxyPort)
	}
}

func TestRenderNFTRulesAddsClassedRawEgressLogs(t *testing.T) {
	body := renderNFTRules(1000, 1001, 1002, 8888, defaultNFTTable, defaultNFTChain)
	for _, want := range []string{
		`udp dport 53 counter log prefix "pipelock-contain class=direct_dns_blocked " drop`,
		`tcp dport 53 counter log prefix "pipelock-contain class=direct_dns_blocked " drop`,
		`counter log prefix "pipelock-contain class=not_routing_through_pipelock " drop`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("nft rules missing %q:\n%s", want, body)
		}
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
		// chown/lchown can't really run under non-root tests; no-op so the
		// orchestration progresses. Tests that need to assert ownership calls
		// can substitute their own hooks.
		chown:   func(string, int, int) error { return nil },
		lchown:  func(string, int, int) error { return nil },
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
		out:                out,
		errOut:             out,
		operatorUser:       containInstallOperatorUser,
		proxyUserName:      "pipelock-proxy",
		agentUserName:      "pipelock-agent",
		configDir:          filepath.Join(root, "etc", "pipelock"),
		dataDir:            filepath.Join(root, "var", "lib", "pipelock"),
		wrapperDir:         filepath.Join(root, "usr", "local", "bin"),
		systemUnitPath:     filepath.Join(root, "etc", "systemd", "system", "pipelock.service"),
		nftRulesPath:       filepath.Join(root, "etc", "nftables.d", "50-pipelock-containment.nft"),
		nftMainPath:        filepath.Join(root, "etc", "sysconfig", "nftables.conf"),
		nftPersistUnitPath: filepath.Join(root, "etc", "systemd", "system", "pipelock-containment-nft.service"),
		sudoersPath:        filepath.Join(root, "etc", "sudoers.d", "50-pipelock-agent"),
		caBundlePath:       filepath.Join(root, "etc", "pipelock", "combined-ca.pem"),
		systemCABundlePath: filepath.Join(root, "etc", "ssl", "certs", "ca-certificates.crt"),
		caExportPath:       filepath.Join(root, "etc", "pipelock", "ca.pem"),
		integrityDir:       filepath.Join(root, "etc", "pipelock", "integrity"),
		integrityPin:       filepath.Join(root, "etc", "pipelock", "integrity", "binary-pin.sha256"),
		wrapperInvPath:     filepath.Join(root, "etc", "pipelock", "contain", "wrappers.json"),
		toolsListPath:      filepath.Join(root, "etc", "pipelock", "contain", "tools.list"),
		workspaceInvPath:   filepath.Join(root, "etc", "pipelock", "contain", "workspaces.json"),
		evidenceACLInvPath: filepath.Join(root, "etc", "pipelock", "contain", "evidence-acls.json"),
		guardScriptPath:    filepath.Join(root, "usr", "local", "bin", "plk-cred-guard"),
		guardServiceUnit:   filepath.Join(root, "etc", "systemd", "system", "pipelock-cred-guard.service"),
		guardPathUnit:      filepath.Join(root, "etc", "systemd", "system", "pipelock-cred-guard.path"),
		undiciShimPath:     filepath.Join(root, "etc", "pipelock", "contain", "undici-shim.cjs"),
		profileScriptPath:  filepath.Join(root, "etc", "profile.d", "pipelock-contain.sh"),
		agentHome:          filepath.Join(root, "home", "pipelock-agent"),
		pipelockTarget:     filepath.Join(root, "usr", "local", "bin", "pipelock"),
		bashPath:           "/bin/bash",
		nologinPath:        "/usr/sbin/nologin",
		nftPath:            testNFT,
		curlPath:           "/usr/bin/curl",
		proxyPort:          8888,
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
	systemBundle := env.systemCABundlePath
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
	binDir := installContainCommandFixtures(t)
	env.nftPath = filepath.Join(binDir, "nft")

	// Let the default allow-list find one agent tool without depending on
	// host-global /usr/local/bin contents.
	origStat := env.stat
	env.stat = func(path string) (os.FileInfo, error) {
		if path == "/usr/local/bin/claude" {
			return origStat(env.pipelockBinary)
		}
		if path == env.nftPath {
			return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(0)}, nil
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
		filepath.Join(env.wrapperDir, "plk"),
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

func TestRunInstall_UpgradeRotatesExistingBackups(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	binDir := installContainCommandFixtures(t)
	env.nftPath = filepath.Join(binDir, "nft")

	cfgDir := t.TempDir()
	cfg1 := filepath.Join(cfgDir, "pipelock-1.yaml")
	cfg2 := filepath.Join(cfgDir, "pipelock-2.yaml")
	if err := os.WriteFile(cfg1, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("write cfg1: %v", err)
	}
	if err := os.WriteFile(cfg2, []byte("mode: strict\n"), 0o600); err != nil {
		t.Fatalf("write cfg2: %v", err)
	}

	enabledTools := map[string]bool{"claude": true}
	origStat := env.stat
	env.stat = func(path string) (os.FileInfo, error) {
		if path == env.nftPath {
			return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(0)}, nil
		}
		for _, tool := range defaultToolNames() {
			for _, dir := range filepath.SplitList(agentExecPath(env.agentUserName)) {
				if path != filepath.Join(dir, tool) {
					continue
				}
				if enabledTools[tool] {
					return origStat(env.pipelockBinary)
				}
				return nil, os.ErrNotExist
			}
		}
		return origStat(path)
	}

	origLookup := env.lookupUser
	env.lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "operator2":
			return &user.User{Uid: "1001", Gid: "1001", Username: name, HomeDir: "/home/operator2"}, nil
		case "pipelock-agent2":
			return &user.User{Uid: "986", Gid: "986", Username: name, HomeDir: "/home/pipelock-agent2"}, nil
		default:
			return origLookup(name)
		}
	}

	systemBundle := []byte("# system bundle v1\n")
	origReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.systemCABundlePath {
			return append([]byte(nil), systemBundle...), nil
		}
		return origReadFile(path)
	}

	if err := os.WriteFile(env.caExportPath, []byte(testPEMCA(t)), 0o600); err != nil {
		t.Fatalf("write ca export: %v", err)
	}

	configPath := filepath.Join(env.configDir, "pipelock.yaml")
	tracked := []string{
		configPath,
		env.pipelockTarget,
		env.integrityPin,
		env.systemUnitPath,
		env.caBundlePath,
		env.nftRulesPath,
		env.toolsListPath,
		filepath.Join(env.wrapperDir, "plk-launch"),
		filepath.Join(env.wrapperDir, "plk"),
		filepath.Join(env.wrapperDir, "plk-claude"),
		env.wrapperInvPath,
		env.sudoersPath,
	}
	legacyBodies := map[string][]byte{
		env.toolsListPath:  []byte("custom\t/usr/bin/custom\n"),
		env.wrapperInvPath: []byte("{\"wrappers\":[\"plk-old\"]}\n"),
	}
	seedLegacyInstallFiles(t, tracked, legacyBodies)

	if err := runInstall(context.Background(), env, installOpts{configSource: cfg1}); err != nil {
		t.Fatalf("first runInstall: %v\noutput:\n%s\ncalls:%+v", err, envOutput(env), runner.calls)
	}

	firstLive := readInstallFiles(t, tracked)
	firstBackupMode := statBackupModes(t, tracked)
	for _, path := range tracked {
		assertFileContents(t, path+".bak", legacyBody(path, legacyBodies))
	}

	if err := os.WriteFile(env.pipelockBinary, []byte("fake pipelock binary v2"), 0o755); err != nil { //nolint:gosec // test binary fixture must be executable
		t.Fatalf("write second source binary: %v", err)
	}
	systemBundle = []byte("# system bundle v2\n")
	enabledTools["codex"] = true
	env.proxyPort = 9999
	env.dataDir += "-v2"
	env.agentUserName = "pipelock-agent2"

	if err := runInstall(context.Background(), env, installOpts{configSource: cfg2, operatorUser: "operator2", proxyPort: 9999}); err != nil {
		t.Fatalf("second runInstall: %v\noutput:\n%s\ncalls:%+v", err, envOutput(env), runner.calls)
	}

	for _, path := range tracked {
		assertFileContents(t, path+".bak", firstLive[path])
		archives := backupArchives(t, path)
		if len(archives) != 1 {
			t.Fatalf("archives for %s: got %d want 1 (%v)", path, len(archives), archives)
		}
		assertFileContents(t, archives[0], legacyBody(path, legacyBodies))
		info, err := os.Stat(archives[0])
		if err != nil {
			t.Fatalf("stat archive %s: %v", archives[0], err)
		}
		if got := info.Mode().Perm(); got != firstBackupMode[path] {
			t.Fatalf("archive mode for %s: got %s want %s", path, got, firstBackupMode[path])
		}
		live, err := os.ReadFile(path) //nolint:gosec // tmpdir-scoped test path
		if err != nil {
			t.Fatalf("read live %s: %v", path, err)
		}
		if bytesEqual(live, firstLive[path]) {
			t.Fatalf("live file did not update on second install: %s", path)
		}
	}
}

func TestRunInstallResetsArchiveTrackingPerInvocation(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.archivedBackups = map[string][]string{
		env.integrityPin + ".bak": {env.integrityPin + ".bak.archived-old"},
	}
	err := runInstall(context.Background(), env, installOpts{operatorUser: "ghost"})
	if err == nil {
		t.Fatal("expected invalid operator error")
	}
	if len(env.archivedBackups) != 0 {
		t.Fatalf("archive tracking not reset: %+v", env.archivedBackups)
	}
}

func legacyBody(path string, overrides map[string][]byte) []byte {
	if override, ok := overrides[path]; ok {
		return override
	}
	return []byte("legacy:" + filepath.Base(path) + "\n")
}

func installContainCommandFixtures(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	for _, name := range []string{"useradd", "userdel", "systemctl", "nft", "visudo", "sudo", "setfacl", "find", "chmod"} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // executable fixture required for preflight PATH lookup.
			t.Fatalf("write %s: %v", name, err)
		}
	}
	t.Setenv("PATH", binDir)
	return binDir
}

func writeNFTPersistUnitFixture(t *testing.T, env *installEnv) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(env.nftPersistUnitPath), 0o750); err != nil {
		t.Fatalf("mkdir persistence unit parent: %v", err)
	}
	if err := os.WriteFile(env.nftPersistUnitPath, []byte(renderNFTPersistUnit(env)), 0o600); err != nil {
		t.Fatalf("write persistence unit: %v", err)
	}
}

func seedLegacyInstallFiles(t *testing.T, paths []string, overrides map[string][]byte) {
	t.Helper()
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		body := []byte("legacy:" + filepath.Base(path) + "\n")
		if override, ok := overrides[path]; ok {
			body = override
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
}

func readInstallFiles(t *testing.T, paths []string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path) //nolint:gosec // tmpdir-scoped test path
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		out[path] = data
	}
	return out
}

func statBackupModes(t *testing.T, paths []string) map[string]os.FileMode {
	t.Helper()
	out := make(map[string]os.FileMode, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path + ".bak")
		if err != nil {
			t.Fatalf("stat %s.bak: %v", path, err)
		}
		out[path] = info.Mode().Perm()
	}
	return out
}

func assertFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path) //nolint:gosec // tmpdir-scoped test path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytesEqual(got, want) {
		t.Fatalf("%s contents: got %q want %q", path, got, want)
	}
}

func backupArchives(t *testing.T, path string) []string {
	t.Helper()
	matches, err := filepath.Glob(path + ".bak.archived-*")
	if err != nil {
		t.Fatalf("glob archives for %s: %v", path, err)
	}
	return matches
}

func envOutput(env *installEnv) string {
	if buf, ok := env.out.(*bytes.Buffer); ok {
		return buf.String()
	}
	return ""
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
		for _, name := range []string{"useradd", "userdel", "systemctl", "nft", "visudo", "sudo", "setfacl", "find", "chmod"} {
			path := filepath.Join(binDir, name)
			if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // executable fixture required for preflight PATH lookup.
				t.Fatalf("write %s: %v", name, err)
			}
		}
		env.nftPath = filepath.Join(binDir, "nft")
		origStat := env.stat
		env.stat = func(path string) (os.FileInfo, error) {
			if path == env.nftPath {
				return fakeFileInfo{mode: 0o700, sys: fakeFileSysWithUID(0)}, nil
			}
			return origStat(path)
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

func TestStepPreflightRejectsUntrustedNFTPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		mode    os.FileMode
		uid     uint32
		wantErr string
	}{
		{
			name:    "relative path",
			path:    "nft",
			mode:    0o700,
			uid:     0,
			wantErr: "absolute path",
		},
		{
			name:    "operator owned",
			path:    "/tmp/nft",
			mode:    0o700,
			uid:     1000,
			wantErr: "root-owned",
		},
		{
			name:    "world writable",
			path:    "/tmp/nft",
			mode:    0o722,
			uid:     0,
			wantErr: "group- or world-writable",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			binDir := installContainCommandFixtures(t)
			env.nftPath = tc.path
			env.stat = func(path string) (os.FileInfo, error) {
				if path == filepath.Clean(tc.path) {
					return fakeFileInfo{mode: tc.mode, sys: fakeFileSysWithUID(tc.uid)}, nil
				}
				return os.Stat(path)
			}
			t.Setenv("PATH", binDir)

			_, err := stepPreflight(installOpts{}).apply(context.Background(), env)
			if err == nil {
				t.Fatal("expected preflight error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error: got %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
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
		`meta skuid 987 counter log prefix "pipelock-contain class=not_routing_through_pipelock " drop`,
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
		"https_proxy=http://127.0.0.1:8888",
		"NO_PROXY=127.0.0.1,localhost,::1",
		"NODE_EXTRA_CA_CERTS=" + env.caExportPath,
		"SSL_CERT_FILE=" + env.caBundlePath,
		"GIT_SSL_CAINFO=" + env.caBundlePath,
		"NODE_OPTIONS='--require " + env.undiciShimPath + "'",
		`"$TARGET"`,
	}
	for _, s := range wants {
		if !strings.Contains(body, s) {
			t.Errorf("plk-launch body missing %q", s)
		}
	}
	// plk-launch must never call sudo as a command - the per-tool wrapper
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

func TestRenderMetaWrapper_UsesSudoAndDispatchesArgs(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	body := renderMetaWrapper(env)
	if !strings.Contains(body, "usage: plk <tool> [args...]") {
		t.Errorf("missing usage: %s", body)
	}
	if !strings.Contains(body, "sudo -n -u pipelock-agent") {
		t.Errorf("missing outer non-interactive sudo: %s", body)
	}
	if !strings.Contains(body, `=~ ^[a-z0-9][a-z0-9_-]{0,30}$`) {
		t.Errorf("missing tool-name regex guard: %s", body)
	}
	if !strings.Contains(body, "missing or empty allow-list") {
		t.Errorf("missing allow-list precheck: %s", body)
	}
	if !strings.Contains(body, "plk-launch") || !strings.Contains(body, `"$@"`) {
		t.Errorf("missing full argv dispatch to plk-launch: %s", body)
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
	writeNFTPersistUnitFixture(t, env)
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
	writeNFTPersistUnitFixture(t, env)
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

func TestStepInstallNFTRules_RepairsMissingPersistenceUnitOnRerun(t *testing.T) {
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
		t.Fatal("expected rerun to repair missing persistence unit")
	}
	unitBody, err := os.ReadFile(env.nftPersistUnitPath)
	if err != nil {
		t.Fatalf("read persistence unit: %v", err)
	}
	if !strings.Contains(string(unitBody), env.nftRulesPath) {
		t.Fatalf("persistence unit missing rules path:\n%s", unitBody)
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

func TestStepInstallNFTRules_PersistsViaOwnedSystemdUnitAndRestores(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	original := "[Unit]\nDescription=old unit\n"
	if err := os.MkdirAll(filepath.Dir(env.nftPersistUnitPath), 0o750); err != nil {
		t.Fatalf("mkdir unit parent: %v", err)
	}
	if err := os.WriteFile(env.nftPersistUnitPath, []byte(original), 0o600); err != nil {
		t.Fatalf("write unit: %v", err)
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

	unitBody, err := os.ReadFile(env.nftPersistUnitPath)
	if err != nil {
		t.Fatalf("read persistence unit: %v", err)
	}
	if !strings.Contains(string(unitBody), "ExecStart="+env.nftPath+" -f "+env.nftRulesPath) {
		t.Fatalf("unit missing ExecStart:\n%s", unitBody)
	}

	if err := s.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	restored, err := os.ReadFile(env.nftPersistUnitPath)
	if err != nil {
		t.Fatalf("read restored unit: %v", err)
	}
	if string(restored) != original {
		t.Fatalf("unit not restored: got %q want %q", restored, original)
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
	runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(env.nftPersistUnitPath)), "disabled\n", 1, nil)

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
	if !env.prevNFTPersistStateKnown || env.prevNFTPersistEnabled {
		t.Fatalf("previous nft persistence unit state not captured as disabled")
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
		if c.name == testSystemctl && strings.Join(c.args, " ") == "disable "+filepath.Base(env.nftPersistUnitPath) {
			sawDisable = true
		}
	}
	if !sawRestore {
		t.Fatalf("expected nft restore from captured table, got %v", runner.calls)
	}
	if !sawDisable {
		t.Fatalf("expected persistence unit disabled-state restore, got %v", runner.calls)
	}
}

func TestStepInstallNFTRules_UndoRemovesManagedIncludeWhenNoBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.nftMainPath = filepath.Join(t.TempDir(), "nftables.conf")
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
	// Sanity: the install flow has 28 steps total after combining the runtime
	// contract steps with the credential guard and the operator evidence ACL
	// step. Changing this count is a documented breaking change for the
	// dry-run / verify probe-4 inventory.
	steps := installSteps(installOpts{})
	if len(steps) != 28 {
		t.Errorf("installSteps count: got %d, want 28", len(steps))
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

func TestBackupAndWriteRotatesExistingBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	if err := backupAndWrite(env, path, []byte("new"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := env.readFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("current file: %q", got)
	}
	bak, err := env.readFile(path + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(bak) != "current" {
		t.Fatalf("backup: %q", bak)
	}
	archives := backupArchives(t, path)
	if len(archives) != 1 {
		t.Fatalf("archives: got %d want 1 (%v)", len(archives), archives)
	}
	archived, err := env.readFile(archives[0])
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	if string(archived) != "original" {
		t.Fatalf("archive: %q", archived)
	}
}

func TestBackupAndWriteSkipsRotationWhenBackupMatchesCurrent(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("current"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	if err := backupAndWrite(env, path, []byte("new"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertFileContents(t, path, []byte("new"))
	assertFileContents(t, path+".bak", []byte("current"))
	if archives := backupArchives(t, path); len(archives) != 0 {
		t.Fatalf("unexpected archives: %v", archives)
	}
}

func TestBackupAndWriteArchiveNameCollisionUsesDistinctNames(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "host.conf")
	now := time.Date(2026, 5, 17, 16, 53, 0, 123, time.UTC)
	origNow := backupArchiveNow
	backupArchiveNow = func() time.Time { return now }
	t.Cleanup(func() { backupArchiveNow = origNow })

	if err := os.WriteFile(path, []byte("current-1"), 0o600); err != nil {
		t.Fatalf("seed current 1: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original-1"), 0o600); err != nil {
		t.Fatalf("seed backup 1: %v", err)
	}
	if err := backupAndWrite(env, path, []byte("new-1"), 0o600); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := backupAndWrite(env, path, []byte("new-2"), 0o600); err != nil {
		t.Fatalf("write 2: %v", err)
	}

	archives := backupArchives(t, path)
	if len(archives) != 2 {
		t.Fatalf("archives: got %d want 2 (%v)", len(archives), archives)
	}
	if archives[0] == archives[1] {
		t.Fatalf("archive names collided: %v", archives)
	}
	assertFileContents(t, archives[0], []byte("original-1"))
	assertFileContents(t, archives[1], []byte("current-1"))
	assertFileContents(t, path+".bak", []byte("new-1"))
	assertFileContents(t, path, []byte("new-2"))
}

func TestBackupAndWriteRestoresRotatedBackupOnWriteFailure(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	env.writeFile = func(string, []byte, os.FileMode) error {
		return stringError("disk full")
	}
	err := backupAndWrite(env, path, []byte("new"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("expected write failure, got %v", err)
	}
	assertFileContents(t, path, []byte("current"))
	assertFileContents(t, path+".bak", []byte("original"))
	if archives := backupArchives(t, path); len(archives) != 0 {
		t.Fatalf("archive should be restored after failed write: %v", archives)
	}
}

func TestBackupAndWriteRemovesNewFileAfterWriteFailure(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "new-file")
	env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
		if err := os.WriteFile(path, contents, mode); err != nil {
			return err
		}
		return stringError("late write failure")
	}
	err := backupAndWrite(env, path, []byte("partial"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "late write failure") {
		t.Fatalf("expected write failure, got %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed new file should be removed, stat err=%v", err)
	}
}

func TestBackupAndWriteReportsRemoveFailureAfterNewFileWriteFailure(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "new-file")
	env.writeFile = func(string, []byte, os.FileMode) error {
		return stringError("write denied")
	}
	env.removeFile = func(string) error {
		return stringError("remove denied")
	}
	err := backupAndWrite(env, path, []byte("partial"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "write denied") || !strings.Contains(err.Error(), "remove denied") {
		t.Fatalf("expected joined write/remove error, got %v", err)
	}
}

func TestBackupAndWriteReportsRestoreFailureAfterWriteFailure(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	env.writeFile = func(string, []byte, os.FileMode) error {
		return stringError("write denied")
	}
	origRename := env.rename
	env.rename = func(oldPath, newPath string) error {
		if oldPath == path+".bak" && newPath == path {
			return stringError("restore denied")
		}
		return origRename(oldPath, newPath)
	}
	err := backupAndWrite(env, path, []byte("new"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "write denied") || !strings.Contains(err.Error(), "restore denied") {
		t.Fatalf("expected joined write/restore error, got %v", err)
	}
}

func TestBackupCurrentToBakReportsCurrentStatError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	origLstat := env.lstat
	var currentStats int
	env.lstat = func(p string) (os.FileInfo, error) {
		if p == path {
			currentStats++
			if currentStats == 1 {
				return nil, os.ErrNotExist
			}
			return nil, stringError("stat denied")
		}
		return origLstat(p)
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "stat denied") {
		t.Fatalf("expected stat error, got %v", err)
	}
}

func TestBackupCurrentToBakReportsCurrentReadError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	env.readFile = func(string) ([]byte, error) {
		return nil, stringError("read denied")
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "read denied") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestBackupCurrentToBakRejectsCurrentSymlinkAfterPrecheck(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	origLstat := env.lstat
	var pathStats int
	env.lstat = func(p string) (os.FileInfo, error) {
		if p == path {
			pathStats++
			if pathStats == 2 {
				return fakeFileInfo{mode: os.ModeSymlink}, nil
			}
		}
		return origLstat(p)
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected late symlink rejection, got %v", err)
	}
}

func TestBackupCurrentToBakReportsBackupStatError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	origLstat := env.lstat
	env.lstat = func(p string) (os.FileInfo, error) {
		if p == path+".bak" {
			return nil, stringError("backup stat denied")
		}
		return origLstat(p)
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "backup stat denied") {
		t.Fatalf("expected backup stat error, got %v", err)
	}
}

func TestBackupCurrentToBakReportsBackupReadError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	origReadFile := env.readFile
	env.readFile = func(p string) ([]byte, error) {
		if p == path+".bak" {
			return nil, stringError("backup read denied")
		}
		return origReadFile(p)
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "backup read denied") {
		t.Fatalf("expected backup read error, got %v", err)
	}
}

func TestBackupCurrentToBakReportsSecondBackupReadError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("current"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	origReadFile := env.readFile
	var backupReads int
	env.readFile = func(p string) ([]byte, error) {
		if p == path+".bak" {
			backupReads++
			if backupReads == 2 {
				return nil, stringError("second backup read denied")
			}
		}
		return origReadFile(p)
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "second backup read denied") {
		t.Fatalf("expected second backup read error, got %v", err)
	}
}

func TestBackupCurrentToBakReportsArchiveStatError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	origLstat := env.lstat
	env.lstat = func(p string) (os.FileInfo, error) {
		if strings.Contains(p, ".bak.archived-") {
			return nil, stringError("archive stat denied")
		}
		return origLstat(p)
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "archive stat denied") {
		t.Fatalf("expected archive stat error, got %v", err)
	}
}

func TestBackupCurrentToBakReportsArchiveRenameFailure(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	origRename := env.rename
	env.rename = func(oldPath, newPath string) error {
		if oldPath == path+".bak" && strings.Contains(newPath, ".bak.archived-") {
			return stringError("archive rename denied")
		}
		return origRename(oldPath, newPath)
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "archive rename denied") {
		t.Fatalf("expected archive rename error, got %v", err)
	}
}

func TestNextBackupArchivePathSkipsSymlinkCollision(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	bak := filepath.Join(dir, "host.conf.bak")
	now := time.Date(2026, 5, 17, 16, 53, 0, 123, time.UTC)
	first := fmt.Sprintf("%s.archived-%s", bak, now.Format(backupArchiveTimeFormat))
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), first); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	got, err := nextBackupArchivePath(env, bak, now)
	if err != nil {
		t.Fatalf("next archive path: %v", err)
	}
	if got != first+".1" {
		t.Fatalf("archive path = %q, want %q", got, first+".1")
	}
}

func TestBackupCurrentToBakRestoresArchiveWhenPromoteFails(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	origRename := env.rename
	env.rename = func(oldPath, newPath string) error {
		if oldPath == path && newPath == path+".bak" {
			return stringError("promote denied")
		}
		return origRename(oldPath, newPath)
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "promote denied") {
		t.Fatalf("expected promote error, got %v", err)
	}
	assertFileContents(t, path, []byte("current"))
	assertFileContents(t, path+".bak", []byte("original"))
	if len(env.archivedBackups[path+".bak"]) != 0 {
		t.Fatalf("archive tracking not cleared: %+v", env.archivedBackups)
	}
}

func TestBackupCurrentToBakReportsArchiveRestoreFailure(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	path := filepath.Join(t.TempDir(), "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	origRename := env.rename
	env.rename = func(oldPath, newPath string) error {
		switch {
		case oldPath == path && newPath == path+".bak":
			return stringError("promote denied")
		case strings.Contains(oldPath, ".bak.archived-") && newPath == path+".bak":
			return stringError("archive restore denied")
		default:
			return origRename(oldPath, newPath)
		}
	}
	_, err := backupCurrentToBak(env, path)
	if err == nil || !strings.Contains(err.Error(), "promote denied") || !strings.Contains(err.Error(), "archive restore denied") {
		t.Fatalf("expected joined promote/archive restore error, got %v", err)
	}
}

func TestForgetArchivedBackupHandlesEmptyAndMiddleEntries(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	forgetArchivedBackup(env, "missing.bak", "archive")

	bak := filepath.Join(t.TempDir(), "host.conf.bak")
	env.archivedBackups = map[string][]string{
		bak: {"first", "second"},
	}
	forgetArchivedBackup(env, bak, "first")
	if got := env.archivedBackups[bak]; len(got) != 1 || got[0] != "second" {
		t.Fatalf("archives = %#v, want second retained", got)
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

func TestRestoreLatestArchivedBackupIgnoresMissingArchive(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	bak := filepath.Join(t.TempDir(), "host.conf.bak")
	archive := bak + ".archived-2026-05-17T16:53:00.000000000Z"
	env.archivedBackups = map[string][]string{bak: {archive}}
	if err := restoreLatestArchivedBackup(env, bak); err != nil {
		t.Fatalf("restore missing archive: %v", err)
	}
	if len(env.archivedBackups) != 0 {
		t.Fatalf("archive tracking not popped: %+v", env.archivedBackups)
	}
}

func TestRestoreLatestArchivedBackupReportsStatError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	bak := filepath.Join(t.TempDir(), "host.conf.bak")
	archive := bak + ".archived-2026-05-17T16:53:00.000000000Z"
	env.archivedBackups = map[string][]string{bak: {archive}}
	origLstat := env.lstat
	env.lstat = func(p string) (os.FileInfo, error) {
		if p == archive {
			return nil, stringError("archive stat denied")
		}
		return origLstat(p)
	}
	err := restoreLatestArchivedBackup(env, bak)
	if err == nil || !strings.Contains(err.Error(), "archive stat denied") {
		t.Fatalf("expected archive stat error, got %v", err)
	}
}

func TestRestoreLatestArchivedBackupReportsRenameError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	bak := filepath.Join(t.TempDir(), "host.conf.bak")
	archive := bak + ".archived-2026-05-17T16:53:00.000000000Z"
	if err := os.WriteFile(archive, []byte("original"), 0o600); err != nil {
		t.Fatalf("seed archive: %v", err)
	}
	env.archivedBackups = map[string][]string{bak: {archive}}
	env.rename = func(string, string) error {
		return stringError("archive restore denied")
	}
	err := restoreLatestArchivedBackup(env, bak)
	if err == nil || !strings.Contains(err.Error(), "archive restore denied") {
		t.Fatalf("expected archive restore error, got %v", err)
	}
}

func TestPopArchivedBackupMissingKey(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.archivedBackups = map[string][]string{"other.bak": {"archive"}}
	if got := popArchivedBackup(env, "missing.bak"); got != "" {
		t.Fatalf("pop missing key = %q, want empty", got)
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

func TestRestoreBackupRestoresLatestArchivedBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("pre-upgrade"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original-backup"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	if err := backupAndWrite(env, path, []byte("new"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := restoreBackup(env, path); err != nil {
		t.Fatalf("restore: %v", err)
	}
	assertFileContents(t, path, []byte("pre-upgrade"))
	assertFileContents(t, path+".bak", []byte("original-backup"))
	if archives := backupArchives(t, path); len(archives) != 0 {
		t.Fatalf("archive should be promoted back to .bak: %v", archives)
	}
}

func TestRestoreBackupUsesRunArchiveStackOrder(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	now := time.Date(2026, 5, 17, 16, 53, 0, 123, time.UTC)
	origNow := backupArchiveNow
	backupArchiveNow = func() time.Time { return now }
	t.Cleanup(func() { backupArchiveNow = origNow })

	if err := os.WriteFile(path, []byte("current-0"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("original"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	for i := 1; i <= 12; i++ {
		if err := backupAndWrite(env, path, []byte(fmt.Sprintf("current-%d", i)), 0o600); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := restoreBackup(env, path); err != nil {
		t.Fatalf("restore: %v", err)
	}
	assertFileContents(t, path, []byte("current-11"))
	assertFileContents(t, path+".bak", []byte("current-10"))
}

func TestRestoreBackupRejectsArchivedSymlinkBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("seed current: %v", err)
	}
	if err := os.WriteFile(path+".bak", []byte("pre-upgrade"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}
	archive := path + ".bak.archived-2026-05-17T16:53:00.000000000Z"
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), archive); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	rememberArchivedBackup(env, path+".bak", archive)
	err := restoreBackup(env, path)
	if err == nil || !strings.Contains(err.Error(), "archived backup") {
		t.Fatalf("expected archived symlink rejection, got %v", err)
	}
	assertFileContents(t, path, []byte("pre-upgrade"))
	if _, err := os.Lstat(path + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".bak should have been promoted before archive rejection, stat err=%v", err)
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
