// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hostileEnv is a developer machine's environment: a real profile, real XDG
// locations, and credentials. None of it may reach the proxy child.
func hostileEnv(root string) []string {
	return []string{
		"PATH=/usr/bin:/home/dev/bin",
		"HOME=" + filepath.Join(root, "hostile-home"),
		"XDG_CONFIG_HOME=" + filepath.Join(root, "hostile-xdg-config"),
		"XDG_DATA_HOME=" + filepath.Join(root, "hostile-xdg-data"),
		"XDG_CACHE_HOME=" + filepath.Join(root, "hostile-xdg-cache"),
		"XDG_STATE_HOME=" + filepath.Join(root, "hostile-xdg-state"),
		"XDG_RUNTIME_DIR=" + filepath.Join(root, "hostile-xdg-runtime"),
		"XDG_CONFIG_DIRS=" + filepath.Join(root, "hostile-xdg-config-dirs"),
		"XDG_DATA_DIRS=" + filepath.Join(root, "hostile-xdg-data-dirs"),
		"XDG_SESSION_TYPE=wayland",
		"TMPDIR=" + filepath.Join(root, "hostile-tmp"),
		"PIPELOCK_HOME=" + filepath.Join(root, "hostile-pipelock-home"),
		"OPENAI_" + "API_KEY=" + "hostile-canary-" + "api-key",
		"GITHUB_" + "TOKEN=" + "hostile-canary-" + "token",
		"AWS_SECRET_" + "ACCESS_KEY=" + "hostile-canary-" + "aws",
		"HTTPS_PROXY=http://user:hostile-canary-proxy-password@proxy.example:3128",
		"NO_PROXY=127.0.0.1",
		"TZ=UTC",
		"GOMAXPROCS=4",
	}
}

func TestChildEnvIsScrubbed(t *testing.T) {
	root := t.TempDir()
	dirs := newRunDirs(filepath.Join(root, "run"))
	env, rep := buildChildEnv(hostileEnv(root), dirs)

	got := map[string]string{}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		if _, dup := got[name]; dup {
			t.Fatalf("%s set twice: the host value could win", name)
		}
		got[name] = value
	}
	// Only the allowlist and the pinned variables exist.
	pinned := dirs.pinned()
	for name := range got {
		if _, ok := pinned[name]; ok {
			continue
		}
		allowed := false
		for _, a := range passthroughEnv {
			allowed = allowed || a == name
		}
		if !allowed {
			t.Fatalf("%s leaked into the child environment", name)
		}
	}
	for _, name := range []string{"OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "PIPELOCK_HOME", "XDG_SESSION_TYPE"} {
		if _, ok := got[name]; ok {
			t.Fatalf("%s leaked", name)
		}
	}
	// Every per-user location is a fresh directory inside the run directory.
	for name, value := range pinned {
		if got[name] != value || !strings.HasPrefix(value, dirs.root+string(filepath.Separator)) {
			t.Fatalf("%s = %q, want a path inside the run directory", name, got[name])
		}
	}
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_DIRS", "XDG_DATA_DIRS", "TMPDIR"} {
		if _, ok := pinned[name]; !ok {
			t.Fatalf("%s is not pinned", name)
		}
	}
	// The scheduler and routing inputs that are meant to pass through do.
	if got["GOMAXPROCS"] != "4" || got["TZ"] != "UTC" || got["NO_PROXY"] != "127.0.0.1" || got["PATH"] == "" {
		t.Fatalf("allowlisted variables did not pass through: %v", got)
	}

	// The recorded report names the allowlist and leaks no value.
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, secret := range []string{"hostile-canary", "/home/dev/bin", "user:"} {
		if strings.Contains(text, secret) {
			t.Fatalf("env report leaks %q: %s", secret, text)
		}
	}
	if len(rep.Allowlist) != len(passthroughEnv) || rep.DroppedCount < 5 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.Passed["TZ"] != "UTC" || !strings.HasPrefix(rep.Passed["PATH"], "sha256:") || !strings.HasPrefix(rep.Passed["HTTPS_PROXY"], "sha256:") {
		t.Fatalf("passed = %v", rep.Passed)
	}
}

func TestRunDirsAreFreshAndEmpty(t *testing.T) {
	dirs := newRunDirs(filepath.Join(t.TempDir(), "run"))
	if err := dirs.create(); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{dirs.home, dirs.xdgConfig, dirs.xdgData, dirs.xdgCache, dirs.xdgState, dirs.xdgRuntime, dirs.xdgConfigDirs, dirs.xdgDataDirs, dirs.tmp, dirs.rules} {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("%s: %v entries=%d, want an existing empty directory", dir, err, len(entries))
		}
	}
	if info, err := os.Stat(dirs.xdgRuntime); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime dir mode = %v (%v), want 0700", info.Mode().Perm(), err)
	}
	// A directory that already exists could carry state from an earlier run.
	if err := dirs.create(); err == nil {
		t.Fatal("create reused an existing run directory")
	}
}

func TestPrepareRulesEmpty(t *testing.T) {
	dirs := newRunDirs(filepath.Join(t.TempDir(), "run"))
	if err := dirs.create(); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []string{"", rulesEmpty} {
		rep, err := prepareRules(spec, dirs)
		if err != nil || rep.Mode != rulesEmpty || len(rep.Files) != 0 || rep.Dir != "rules" {
			t.Fatalf("prepareRules(%q) = %+v, %v", spec, rep, err)
		}
	}
	if entries, _ := os.ReadDir(dirs.rules); len(entries) != 0 {
		t.Fatalf("empty mode left %d entries", len(entries))
	}
}

func TestPrepareRulesDirectoryIsCopiedAndHashed(t *testing.T) {
	src := t.TempDir()
	bundle := filepath.Join(src, "community")
	if err := os.MkdirAll(bundle, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"bundle.yaml": "name: community\n", "bundle.yaml.sig": "sig"} {
		if err := os.WriteFile(filepath.Join(bundle, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dirs := newRunDirs(filepath.Join(t.TempDir(), "run"))
	if err := dirs.create(); err != nil {
		t.Fatal(err)
	}
	rep, err := prepareRules(src, dirs)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mode != "dir" || rep.Source == "" || len(rep.Files) != 2 {
		t.Fatalf("report = %+v", rep)
	}
	want := map[string]string{"community/bundle.yaml": "name: community\n", "community/bundle.yaml.sig": "sig"}
	for _, f := range rep.Files {
		content, ok := want[f.Path]
		if !ok {
			t.Fatalf("unexpected file %s", f.Path)
		}
		// The digest must match the source content, computed here without
		// the code under test, and the copy must hold the same bytes.
		sum := sha256.Sum256([]byte(content))
		if f.SHA256 != hex.EncodeToString(sum[:]) || f.Size != int64(len(content)) {
			t.Fatalf("%s: recorded %s/%d", f.Path, f.SHA256, f.Size)
		}
		raw, readErr := os.ReadFile(filepath.Join(dirs.rules, filepath.FromSlash(f.Path)))
		if readErr != nil || string(raw) != content {
			t.Fatalf("%s was not copied faithfully: %v", f.Path, readErr)
		}
	}
	// The source is never the directory the proxy loads from.
	if entries, _ := os.ReadDir(bundle); len(entries) != 2 {
		t.Fatalf("source directory was modified: %d entries", len(entries))
	}
}

func TestPrepareRulesRefusesUnsafeInput(t *testing.T) {
	dirs := newRunDirs(filepath.Join(t.TempDir(), "run"))
	if err := dirs.create(); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRules(filepath.Join(t.TempDir(), "missing"), dirs); err == nil {
		t.Fatal("a missing rules directory was accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRules(file, dirs); err == nil {
		t.Fatal("a regular file was accepted as a rules directory")
	}
	src := t.TempDir()
	if err := os.Symlink("/etc/hostname", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRules(src, dirs); err == nil {
		t.Fatal("a symlink inside the rules directory was followed")
	}
}

func TestApplyConfigPinsRulesAndPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "run")
	dirs := newRunDirs(root)
	for _, tt := range []struct {
		mode              string
		enabled, required bool
	}{{modeOff, false, false}, {modeBest, true, false}, {modeRequired, true, true}} {
		t.Run(tt.mode, func(t *testing.T) {
			out, err := applyConfig([]byte(fakeConfig), configParams{mode: tt.mode, chains: 3, dirs: dirs})
			if err != nil {
				t.Fatal(err)
			}
			text := string(out)
			for _, want := range []string{"rules_dir: " + dirs.rules, "receipt_chains: 3", "quarantine_dir: " + filepath.Join(dirs.tmp, "quarantine")} {
				if !strings.Contains(text, want) {
					t.Fatalf("effective config lacks %q:\n%s", want, text)
				}
			}
			if strings.Contains(text, "/tmp/pipelock-quarantine") {
				t.Fatal("the shared default quarantine path survived")
			}
			wantEnabled := "enabled: " + map[bool]string{true: "true", false: "false"}[tt.enabled]
			wantRequired := "require_receipts: " + map[bool]string{true: "true", false: "false"}[tt.required]
			if !strings.Contains(text, wantEnabled) || !strings.Contains(text, wantRequired) {
				t.Fatalf("mode %s: want %q and %q in\n%s", tt.mode, wantEnabled, wantRequired, text)
			}
		})
	}
	if _, err := applyConfig([]byte("a: b\n"), configParams{mode: modeOff, chains: 1, dirs: dirs}); err == nil {
		t.Fatal("a config without the expected sections was accepted")
	}
}

func TestDescribeConfigHashesAndFlagsExternalPaths(t *testing.T) {
	build := func(root string) configReport {
		dirs := newRunDirs(root)
		out, err := applyConfig([]byte(fakeConfig), configParams{mode: modeBest, chains: 1, dirs: dirs})
		if err != nil {
			t.Fatal(err)
		}
		rep, err := describeConfig(filepath.Join(root, "pipelock.yaml"), out, root)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	a, b := build("/work/run-a"), build("/elsewhere/run-b")
	if a.SHA256 == b.SHA256 {
		t.Fatal("exact hashes should differ across run directories")
	}
	if a.CanonicalSHA256 != b.CanonicalSHA256 {
		t.Fatal("canonical hash should not depend on where the run directory is")
	}
	if len(a.ExternalPaths) != 0 || strings.Contains(a.YAML, "/work/run-a") || !strings.Contains(a.YAML, "<RUN_DIR>") {
		t.Fatalf("report = %+v", a)
	}

	leaky := "flight_recorder:\n  dir: /var/lib/host/recorder\nbehavioral_baseline:\n  profile_dir: /home/dev/.pipelock\npath_prefixes:\n  path_prefix: /document/d/\n"
	rep, err := describeConfig("pipelock.yaml", []byte(leaky), "/work/run-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ExternalPaths) != 2 {
		t.Fatalf("external paths = %v, want the two host directories and not the URL path prefix", rep.ExternalPaths)
	}
}

func TestHarnessSourceHash(t *testing.T) {
	a, err := harnessSourceSHA256()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := harnessSourceSHA256()
	if len(a) != 64 || a != b {
		t.Fatalf("source hash = %q then %q", a, b)
	}
}

func TestHostFacts(t *testing.T) {
	rep := describeHost([]string{"GOMAXPROCS=3", "PATH=x"}, t.TempDir())
	if rep.ChildGOMAXPROCS != "3" || rep.NumCPU < 1 || rep.OutputFSType == "" || rep.CgroupCPUQuota == "" {
		t.Fatalf("host = %+v", rep)
	}
	if describeHost(nil, t.TempDir()).ChildGOMAXPROCS != "unset" {
		t.Fatal("unset GOMAXPROCS should be reported as unset")
	}
}

func TestHoldLockSerializesRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bench.lock")
	release, err := holdLock(path)
	if err != nil {
		t.Skipf("locking unsupported here: %v", err)
	}
	acquired := make(chan struct{})
	go func() {
		second, lockErr := holdLock(path)
		if lockErr == nil {
			close(acquired)
			second()
		}
	}()
	select {
	case <-acquired:
		t.Fatal("a second run took the lock while the first still held it")
	case <-time.After(150 * time.Millisecond):
	}
	release()
	select {
	case <-acquired:
	case <-time.After(10 * time.Second):
		t.Fatal("the lock was not released")
	}
}

func TestParseFlags(t *testing.T) {
	good := []string{"--binary", os.Args[0], "--out", filepath.Join(t.TempDir(), "o"), "--requests", "10"}
	opt, modes, lock, err := parseFlags(good)
	if err != nil || opt.requests != 10 || opt.rules != rulesEmpty || opt.warmup != 1000 || len(modes) != 3 || lock != "" {
		t.Fatalf("parseFlags = %+v %v %q %v", opt, modes, lock, err)
	}
	for _, bad := range [][]string{
		{"--binary", os.Args[0]},
		append(append([]string{}, good...), "--modes", "sideways"),
		append(append([]string{}, good...), "--chains", "33"),
		append(append([]string{}, good...), "--window", "0s"),
		append(append([]string{}, good...), "--warmup", "-1"),
		{"--binary", filepath.Join(t.TempDir(), "absent"), "--out", t.TempDir()},
	} {
		if _, _, _, err := parseFlags(bad); err == nil {
			t.Fatalf("parseFlags(%v) accepted invalid input", bad)
		}
	}
}
