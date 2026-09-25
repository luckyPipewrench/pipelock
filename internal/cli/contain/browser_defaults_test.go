// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/browserdefaults"
)

type ownCall struct {
	path     string
	uid, gid int
}

// browserDefaultsEnv returns a fake env whose lchown calls are recorded, plus
// the config and record paths.
func browserDefaultsEnv(t *testing.T) (*installEnv, *[]ownCall, string, string) {
	t.Helper()
	env, _, _ := newFakeEnv(t)
	var calls []ownCall
	env.lchown = func(path string, uid, gid int) error {
		calls = append(calls, ownCall{filepath.Clean(path), uid, gid})
		return nil
	}
	env.chown = func(path string, _, _ int) error {
		t.Fatalf("agent-browser defaults used symlink-following chown on %s", path)
		return nil
	}
	prior := agentBrowserFchown
	agentBrowserFchown = func(f *os.File, uid, gid int) error {
		path := f.Name()
		if !filepath.IsAbs(path) {
			path = filepath.Join(agentHomeDir(env), path)
		}
		return env.lchown(path, uid, gid)
	}
	t.Cleanup(func() { agentBrowserFchown = prior })
	return env, &calls, agentBrowserConfigPath(env), agentBrowserDefaultsRecordPath(env)
}

func writeAgentBrowserConfigFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readArgs(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	obj, err := browserdefaults.Parse(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	args, err := browserdefaults.Args(obj)
	if err != nil {
		t.Fatalf("args: %v", err)
	}
	return args
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s should not exist: %v", path, err)
	}
}

func TestStepWriteAgentBrowserDefaults_FreshInstall(t *testing.T) {
	env, calls, path, record := browserDefaultsEnv(t)
	s := stepWriteAgentBrowserDefaults()

	applied, err := s.apply(context.Background(), env)
	if err != nil || !applied {
		t.Fatalf("apply: applied=%v err=%v", applied, err)
	}
	if got := readArgs(t, path); got != browserdefaults.Flag {
		t.Fatalf("args %q", got)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != modeAgentConfig {
		t.Fatalf("config mode %o, want %o", info.Mode().Perm(), modeAgentConfig)
	}
	for _, want := range []string{agentHomeDir(env), filepath.Dir(path), path} {
		if !slices.Contains(*calls, ownCall{filepath.Clean(want), 987, 987}) {
			t.Errorf("expected agent-owned %s; lchown calls %v", want, *calls)
		}
	}
	// Record is root-side, not in the agent home, and binds the path.
	if strings.HasPrefix(record, agentHomeDir(env)) {
		t.Fatalf("record %s lives in the agent home", record)
	}
	rinfo, err := os.Lstat(record)
	if err != nil {
		t.Fatalf("record missing: %v", err)
	}
	if rinfo.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %o", rinfo.Mode().Perm())
	}
	data, _ := os.ReadFile(filepath.Clean(record))
	rec, err := browserdefaults.DecodeRecord(data)
	if err != nil || !rec.Created || rec.Path != path {
		t.Fatalf("record %+v err=%v", rec, err)
	}

	// Rerun is idempotent: nothing written, record untouched.
	before, _ := os.ReadFile(filepath.Clean(path))
	applied, err = s.apply(context.Background(), env)
	if err != nil || applied {
		t.Fatalf("rerun: applied=%v err=%v", applied, err)
	}
	after, _ := os.ReadFile(filepath.Clean(path))
	if string(before) != string(after) {
		t.Fatalf("rerun changed config")
	}

	// Rollback deletes a file Pipelock created and nothing else touched.
	if err := removeAgentBrowserDefaults(env); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	assertAbsent(t, path)
	assertAbsent(t, record)
	// Rollback again is a no-op.
	if err := removeAgentBrowserDefaults(env); err != nil {
		t.Fatalf("second rollback: %v", err)
	}
}

func TestStepWriteAgentBrowserDefaults_ExistingArgs(t *testing.T) {
	for _, tc := range []struct{ name, args string }{
		{"comma", "--lang=en-US,--window-size=1280,800"},
		{"newline", "--lang=en-US\n--mute-audio"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, path, record := browserDefaultsEnv(t)
			body := `{"headed": true, "args": ` + jsonString(tc.args) + `}`
			writeAgentBrowserConfigFixture(t, path, body)

			if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err != nil {
				t.Fatalf("apply: %v", err)
			}
			got := readArgs(t, path)
			if got != tc.args+","+browserdefaults.Flag {
				t.Fatalf("args %q", got)
			}
			data, _ := os.ReadFile(filepath.Clean(path))
			if !strings.Contains(string(data), `"headed": true`) {
				t.Fatalf("other key dropped: %s", data)
			}

			if err := removeAgentBrowserDefaults(env); err != nil {
				t.Fatalf("rollback: %v", err)
			}
			if got := readArgs(t, path); got != tc.args {
				t.Fatalf("restored args %q, want %q", got, tc.args)
			}
			assertAbsent(t, record)
		})
	}
}

func jsonString(s string) string {
	return `"` + strings.ReplaceAll(s, "\n", `\n`) + `"`
}

func TestStepWriteAgentBrowserDefaults_AlreadyPresentIsLeftAlone(t *testing.T) {
	env, _, path, record := browserDefaultsEnv(t)
	body := `{"args": "--a,` + browserdefaults.Flag + `"}`
	writeAgentBrowserConfigFixture(t, path, body)

	applied, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env)
	if err != nil || applied {
		t.Fatalf("apply: applied=%v err=%v", applied, err)
	}
	assertAbsent(t, record)
	// With no record Pipelock does not own the flag, so rollback leaves it.
	if err := removeAgentBrowserDefaults(env); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	data, _ := os.ReadFile(filepath.Clean(path))
	if string(data) != body {
		t.Fatalf("config changed: %s", data)
	}
}

func TestStepWriteAgentBrowserDefaults_RefusesInvalidConfig(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"malformed JSON", `{"args": `, "malformed JSON"},
		{"non-string args", `{"args": ["--a"]}`, "args must be a string"},
		{"null args", `{"args": null}`, "args must be a string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, calls, path, record := browserDefaultsEnv(t)
			writeAgentBrowserConfigFixture(t, path, tc.body)
			applied, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env)
			if err == nil || applied || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("apply: applied=%v err=%v", applied, err)
			}
			data, _ := os.ReadFile(filepath.Clean(path))
			if string(data) != tc.body {
				t.Fatalf("config changed: %s", data)
			}
			assertAbsent(t, record)
			assertAbsent(t, path+".bak")
			if len(*calls) != 0 {
				t.Fatalf("refused config still chowned: %v", *calls)
			}
		})
	}
}

// failOnWrite makes any privileged write fail the test: a symlink must be
// refused while reading, before the record or the config is written.
func failOnWrite(t *testing.T, env *installEnv) {
	t.Helper()
	env.writeFile = func(p string, _ []byte, _ os.FileMode) error {
		t.Fatalf("write attempted to %s before the symlink was refused", p)
		return nil
	}
}

func TestStepWriteAgentBrowserDefaults_RefusesSymlinks(t *testing.T) {
	const targetBody = `{"args": "--target"}`
	t.Run("config file", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		if err := os.WriteFile(target, []byte(targetBody), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		failOnWrite(t, env)
		if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("expected symlink refusal, got %v", err)
		}
		if data, _ := os.ReadFile(filepath.Clean(target)); string(data) != targetBody {
			t.Fatalf("symlink target modified: %s", data)
		}
		if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("symlink replaced: %v", err)
		}
		assertAbsent(t, record)
	})
	t.Run("agent-browser dir", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		targetDir := t.TempDir()
		target := filepath.Join(targetDir, "config.json")
		// Malformed on purpose: a read that followed the link would surface as
		// a parse error rather than the symlink refusal asserted below.
		const dirTargetBody = `{"args": `
		if err := os.WriteFile(target, []byte(dirTargetBody), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(agentHomeDir(env), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(targetDir, filepath.Dir(path)); err != nil {
			t.Fatal(err)
		}
		failOnWrite(t, env)
		if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("expected symlink refusal, got %v", err)
		}
		if data, _ := os.ReadFile(filepath.Clean(target)); string(data) != dirTargetBody {
			t.Fatalf("symlink target modified: %s", data)
		}
		entries, _ := os.ReadDir(targetDir)
		if len(entries) != 1 {
			t.Fatalf("files written through symlinked dir: %v", entries)
		}
		assertAbsent(t, record)
	})
	t.Run("rollback refuses a symlink swapped in after install", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		body := `{"args": "` + browserdefaults.Flag + `"}`
		if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := removeAgentBrowserDefaults(env); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("expected symlink refusal, got %v", err)
		}
		if data, _ := os.ReadFile(filepath.Clean(target)); string(data) != body {
			t.Fatalf("symlink target modified: %s", data)
		}
		// Record kept so a later rollback can retry.
		if _, err := os.Lstat(record); err != nil {
			t.Fatalf("record removed on refused rollback: %v", err)
		}
	})
}

func TestStepWriteAgentBrowserDefaults_RefusesDirectorySwap(t *testing.T) {
	// A normal install is the positive control for the same path and operation.
	control, _, controlPath, _ := browserDefaultsEnv(t)
	if applied, err := stepWriteAgentBrowserDefaults().apply(context.Background(), control); err != nil || !applied {
		t.Fatalf("control install: applied=%v err=%v", applied, err)
	}
	if got := readArgs(t, controlPath); got != browserdefaults.Flag {
		t.Fatalf("control args %q", got)
	}

	env, _, path, record := browserDefaultsEnv(t)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	priorChown := agentBrowserFchown
	outsideChown := false
	agentBrowserFchown = func(f *os.File, uid, gid int) error {
		opened, openErr := f.Stat()
		outsideInfo, outsideErr := os.Stat(outside)
		if openErr == nil && outsideErr == nil && os.SameFile(opened, outsideInfo) {
			outsideChown = true
		}
		return priorChown(f, uid, gid)
	}
	t.Cleanup(func() { agentBrowserFchown = priorChown })
	prior := agentBrowserLstat
	checks := 0
	agentBrowserLstat = func(root *os.Root, name string) (os.FileInfo, error) {
		info, err := prior(root, name)
		if name == agentBrowserDir && err == nil {
			checks++
			if checks == 2 {
				if err := os.Rename(dir, dir+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, dir); err != nil {
					t.Fatal(err)
				}
			}
		}
		return info, err
	}
	t.Cleanup(func() { agentBrowserLstat = prior })
	if applied, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err == nil || applied {
		t.Fatalf("swapped directory accepted: applied=%v err=%v", applied, err)
	}
	if checks < 2 {
		t.Fatalf("swap did not run: %d checks", checks)
	}
	if info, err := os.Lstat(dir); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("directory was not swapped: %v", err)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("outside directory modified: entries=%v err=%v", entries, err)
	}
	if outsideChown {
		t.Fatal("outside directory was chowned")
	}
	assertAbsent(t, record)
}

func TestRemoveAgentBrowserDefaults_DuplicateRetainsRecord(t *testing.T) {
	env, _, path, record := browserDefaultsEnv(t)
	if applied, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err != nil || !applied {
		t.Fatalf("install: applied=%v err=%v", applied, err)
	}
	// A single recorded flag is the positive control for normal removal.
	control, _, controlPath, controlRecord := browserDefaultsEnv(t)
	if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), control); err != nil {
		t.Fatal(err)
	}
	if err := removeAgentBrowserDefaults(control); err != nil {
		t.Fatalf("control rollback: %v", err)
	}
	assertAbsent(t, controlPath)
	assertAbsent(t, controlRecord)

	body := `{"args":"` + browserdefaults.Flag + `,` + browserdefaults.Flag + `"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeRecord, err := os.ReadFile(filepath.Clean(record))
	if err != nil {
		t.Fatal(err)
	}
	if err := removeAgentBrowserDefaults(env); err == nil || !strings.Contains(err.Error(), "manual") {
		t.Fatalf("expected manual resolution error, got %v", err)
	}
	if got, err := os.ReadFile(filepath.Clean(path)); err != nil || string(got) != body {
		t.Fatalf("duplicate config changed: body=%s err=%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Clean(record)); err != nil || string(got) != string(beforeRecord) {
		t.Fatalf("ownership record changed: body=%s err=%v", got, err)
	}
}

func TestStepWriteAgentBrowserDefaults_FailureRestores(t *testing.T) {
	const original = `{"args": "--keep"}`
	t.Run("config write fails", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		writeAgentBrowserConfigFixture(t, path, original)
		priorWrite := agentBrowserWrite
		agentBrowserWrite = func(_ *os.File, _ []byte) (int, error) { return 0, errors.New("disk full") }
		t.Cleanup(func() { agentBrowserWrite = priorWrite })
		if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "disk full") {
			t.Fatalf("expected write failure, got %v", err)
		}
		if data, _ := os.ReadFile(filepath.Clean(path)); string(data) != original {
			t.Fatalf("original not restored: %s", data)
		}
		assertAbsent(t, record)
	})
	t.Run("chown fails after write", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		writeAgentBrowserConfigFixture(t, path, original)
		env.lchown = func(p string, _, _ int) error {
			if filepath.Clean(p) == path {
				return errors.New("ro fs")
			}
			return nil
		}
		if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "ro fs") {
			t.Fatalf("expected chown failure, got %v", err)
		}
		if data, _ := os.ReadFile(filepath.Clean(path)); string(data) != original {
			t.Fatalf("original not restored: %s", data)
		}
		assertAbsent(t, record)
	})
	t.Run("record write fails", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		writeAgentBrowserConfigFixture(t, path, original)
		realWrite := env.writeFile
		env.writeFile = func(p string, data []byte, mode os.FileMode) error {
			if filepath.Clean(p) == record {
				return errors.New("no space")
			}
			return realWrite(p, data, mode)
		}
		if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err == nil {
			t.Fatal("expected record failure")
		}
		if data, _ := os.ReadFile(filepath.Clean(path)); string(data) != original {
			t.Fatalf("config touched: %s", data)
		}
	})
	t.Run("undo after a later step fails", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		writeAgentBrowserConfigFixture(t, path, original)
		s := stepWriteAgentBrowserDefaults()
		if _, err := s.apply(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		if err := s.undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
		if data, _ := os.ReadFile(filepath.Clean(path)); string(data) != original {
			t.Fatalf("original not restored: %s", data)
		}
		assertAbsent(t, record)
	})
	t.Run("undo restores a previous record", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		s := stepWriteAgentBrowserDefaults()
		if _, err := s.apply(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		prev, _ := os.ReadFile(filepath.Clean(record))
		// The agent strips the flag; a rerun re-adds it with a fresh record.
		writeAgentBrowserConfigFixture(t, path, `{"args": "--mine"}`)
		if applied, err := s.apply(context.Background(), env); err != nil || !applied {
			t.Fatalf("rerun: applied=%v err=%v", applied, err)
		}
		fresh, _ := os.ReadFile(filepath.Clean(record))
		if string(fresh) == string(prev) {
			t.Fatal("stale record not replaced")
		}
		if err := s.undo(context.Background(), env); err != nil {
			t.Fatalf("undo: %v", err)
		}
		if got, _ := os.ReadFile(filepath.Clean(record)); string(got) != string(prev) {
			t.Fatalf("previous record not restored: %s", got)
		}
		if got := readArgs(t, path); got != "--mine" {
			t.Fatalf("args %q", got)
		}
	})
}

func TestRemoveAgentBrowserDefaults_OnlyPipelockFlag(t *testing.T) {
	env, calls, path, record := browserDefaultsEnv(t)
	writeAgentBrowserConfigFixture(t, path, `{"args": "--a"}`)
	if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	// The agent edits the file after install.
	writeAgentBrowserConfigFixture(t, path, `{"args": "--a,`+browserdefaults.Flag+`,--later", "headed": true}`)
	*calls = nil
	if err := removeAgentBrowserDefaults(env); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := readArgs(t, path); got != "--a,--later" {
		t.Fatalf("args %q", got)
	}
	data, _ := os.ReadFile(filepath.Clean(path))
	if !strings.Contains(string(data), "headed") {
		t.Fatalf("agent key dropped: %s", data)
	}
	if !slices.Contains(*calls, ownCall{path, 987, 987}) {
		t.Fatalf("rewritten config not returned to the agent: %v", *calls)
	}
	info, _ := os.Lstat(path)
	if info.Mode().Perm() != modeAgentConfig {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	assertAbsent(t, record)
}

func TestRemoveAgentBrowserDefaults_RecordGuards(t *testing.T) {
	t.Run("path mismatch", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		body := `{"args": "` + browserdefaults.Flag + `"}`
		writeAgentBrowserConfigFixture(t, path, body)
		rec := browserdefaults.Record{Created: true, Path: "/elsewhere/config.json"}
		if err := writeAgentBrowserDefaultsRecord(env, rec.Marshal()); err != nil {
			t.Fatal(err)
		}
		if err := removeAgentBrowserDefaults(env); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("expected refusal, got %v", err)
		}
		if data, _ := os.ReadFile(filepath.Clean(path)); string(data) != body {
			t.Fatalf("config changed: %s", data)
		}
		if _, err := os.Lstat(record); err != nil {
			t.Fatalf("record removed: %v", err)
		}
	})
	t.Run("malformed record", func(t *testing.T) {
		env, _, path, _ := browserDefaultsEnv(t)
		body := `{"args": "` + browserdefaults.Flag + `"}`
		writeAgentBrowserConfigFixture(t, path, body)
		if err := writeAgentBrowserDefaultsRecord(env, []byte(`{"created": null}`)); err != nil {
			t.Fatal(err)
		}
		if err := removeAgentBrowserDefaults(env); err == nil {
			t.Fatal("expected malformed record refusal")
		}
		if data, _ := os.ReadFile(filepath.Clean(path)); string(data) != body {
			t.Fatalf("config changed: %s", data)
		}
	})
	t.Run("config gone", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := removeAgentBrowserDefaults(env); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		assertAbsent(t, record)
	})
	t.Run("malformed config keeps record", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		if _, err := stepWriteAgentBrowserDefaults().apply(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		writeAgentBrowserConfigFixture(t, path, `{`)
		if err := removeAgentBrowserDefaults(env); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("expected malformed refusal, got %v", err)
		}
		if _, err := os.Lstat(record); err != nil {
			t.Fatalf("record removed: %v", err)
		}
	})
}

func TestAgentBrowserDefaults_Wiring(t *testing.T) {
	names := func(steps []step) []string {
		out := make([]string, 0, len(steps))
		for _, s := range steps {
			out = append(out, s.name)
		}
		return out
	}
	install := names(installSteps(installOpts{}))
	i := slices.Index(install, "write-agent-browser-defaults")
	if i < 1 || install[i-1] != "write-agent-tool-configs" {
		t.Fatalf("install step not after agent tool configs: %v", install)
	}
	rollback := names(rollbackActions(rollbackOpts{}))
	if !slices.Contains(rollback, "remove-agent-browser-defaults") {
		t.Fatalf("rollback action missing: %v", rollback)
	}
	// The removal must run before the config dir removal deletes the record:
	// runUndo walks in reverse, so it needs the higher index.
	cfgDir := slices.Index(rollback, "remove-dir-config")
	if cfgDir < 0 || slices.Index(rollback, "remove-agent-browser-defaults") < cfgDir {
		t.Fatalf("removal would run after the config dir is removed: %v", rollback)
	}
}

func TestAgentBrowserDefaults_ErrorPaths(t *testing.T) {
	ctx := context.Background()
	t.Run("config is a directory", func(t *testing.T) {
		env, _, path, _ := browserDefaultsEnv(t)
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := stepWriteAgentBrowserDefaults().apply(ctx, env); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("config stat error", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		priorLstat := agentBrowserLstat
		agentBrowserLstat = func(root *os.Root, name string) (os.FileInfo, error) {
			if name == agentBrowserFile {
				return nil, os.ErrPermission
			}
			return priorLstat(root, name)
		}
		t.Cleanup(func() { agentBrowserLstat = priorLstat })
		if _, err := stepWriteAgentBrowserDefaults().apply(ctx, env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("agent user missing", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		env.agentUserName = "nobody-here"
		if _, err := stepWriteAgentBrowserDefaults().apply(ctx, env); err == nil || !strings.Contains(err.Error(), "resolve") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("record unreadable", func(t *testing.T) {
		env, _, _, record := browserDefaultsEnv(t)
		env.readFile = func(p string) ([]byte, error) {
			if filepath.Clean(p) == record {
				return nil, os.ErrPermission
			}
			return os.ReadFile(filepath.Clean(p))
		}
		if _, err := stepWriteAgentBrowserDefaults().apply(ctx, env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("install got %v", err)
		}
		if err := removeAgentBrowserDefaults(env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("rollback got %v", err)
		}
	})
	t.Run("record dir cannot be created", func(t *testing.T) {
		env, _, path, _ := browserDefaultsEnv(t)
		realMkdir := env.mkdirAll
		env.mkdirAll = func(p string, mode os.FileMode) error {
			if filepath.Clean(p) == filepath.Join(env.configDir, "contain") {
				return os.ErrPermission
			}
			return realMkdir(p, mode)
		}
		if _, err := stepWriteAgentBrowserDefaults().apply(ctx, env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("got %v", err)
		}
		// Nothing was written into the agent home.
		assertAbsent(t, path)
	})
	t.Run("undo reports record restore failure", func(t *testing.T) {
		env, _, _, record := browserDefaultsEnv(t)
		s := stepWriteAgentBrowserDefaults()
		if _, err := s.apply(ctx, env); err != nil {
			t.Fatal(err)
		}
		env.removeFile = func(p string) error {
			if filepath.Clean(p) == record {
				return os.ErrPermission
			}
			return os.Remove(p)
		}
		if err := s.undo(ctx, env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("rollback action runs removal", func(t *testing.T) {
		env, _, path, record := browserDefaultsEnv(t)
		if _, err := stepWriteAgentBrowserDefaults().apply(ctx, env); err != nil {
			t.Fatal(err)
		}
		if err := actionRemoveAgentBrowserDefaults().undo(ctx, env); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		assertAbsent(t, path)
		assertAbsent(t, record)
	})
	rollbackFailure := func(t *testing.T, mutate func(env *installEnv, path string)) {
		t.Helper()
		env, _, path, record := browserDefaultsEnv(t)
		writeAgentBrowserConfigFixture(t, path, `{"args": "--a"}`)
		if _, err := stepWriteAgentBrowserDefaults().apply(ctx, env); err != nil {
			t.Fatal(err)
		}
		mutate(env, path)
		if err := removeAgentBrowserDefaults(env); err == nil {
			t.Fatal("expected rollback failure")
		}
		if _, err := os.Lstat(record); err != nil {
			t.Fatalf("record removed on failed rollback: %v", err)
		}
	}
	t.Run("rollback write fails", func(t *testing.T) {
		rollbackFailure(t, func(env *installEnv, path string) {
			priorWrite := agentBrowserWrite
			agentBrowserWrite = func(_ *os.File, _ []byte) (int, error) { return 0, os.ErrPermission }
			t.Cleanup(func() { agentBrowserWrite = priorWrite })
		})
	})
	t.Run("rollback chown fails", func(t *testing.T) {
		rollbackFailure(t, func(env *installEnv, path string) {
			env.lchown = func(p string, _, _ int) error {
				if filepath.Clean(p) == path {
					return os.ErrPermission
				}
				return nil
			}
		})
	})
	t.Run("rollback user missing", func(t *testing.T) {
		rollbackFailure(t, func(env *installEnv, _ string) { env.agentUserName = "nobody-here" })
	})
	t.Run("rollback remove fails", func(t *testing.T) {
		env, _, _, record := browserDefaultsEnv(t)
		if _, err := stepWriteAgentBrowserDefaults().apply(ctx, env); err != nil {
			t.Fatal(err)
		}
		priorRemove := agentBrowserRemove
		agentBrowserRemove = func(root *os.Root, name string) error {
			if name == agentBrowserFile {
				return os.ErrPermission
			}
			return priorRemove(root, name)
		}
		t.Cleanup(func() { agentBrowserRemove = priorRemove })
		if err := removeAgentBrowserDefaults(env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("got %v", err)
		}
		if _, err := os.Lstat(record); err != nil {
			t.Fatalf("record removed on failed rollback: %v", err)
		}
	})
}
