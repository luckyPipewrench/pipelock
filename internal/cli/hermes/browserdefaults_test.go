// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserDefaultsInstallRollback(t *testing.T) {
	for _, tc := range []struct {
		name, initial string
		wantError     bool
	}{
		{"absent", "", false},
		{"empty", " ", false},
		{"other keys", `{"headed":true}`, false},
		{"existing args", `{"args":"--no-sandbox,--disable-dev-shm-usage"}`, false},
		{"already set", `{"args":"--disable-blink-features=AutomationControlled"}`, false},
		{"malformed", `{`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path, _ := browserPaths(home)
			if tc.name != "absent" {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tc.initial), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := installBrowserDefaults(home)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				data, _ := os.ReadFile(filepath.Clean(path))
				if string(data) != tc.initial {
					t.Fatal("changed malformed config")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if state, _ := verifyBrowserDefaults(home); state != "present" {
				t.Fatalf("state %s", state)
			}
			if err := installBrowserDefaults(home); err != nil {
				t.Fatal(err)
			}
			obj, _, err := readBrowserConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			args, _ := browserArgs(obj)
			if strings.Count(args, browserFlag) != 1 {
				t.Fatalf("duplicate flag: %q", args)
			}
			if err := rollbackBrowserDefaults(home); err != nil {
				t.Fatal(err)
			}
			if tc.name == "absent" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("file remains: %v", err)
				}
				return
			}
			if tc.name == "already set" {
				obj, _, _ := readBrowserConfig(path)
				args, _ := browserArgs(obj)
				if !hasBrowserFlag(args) {
					t.Fatal("removed operator flag")
				}
				return
			}
			obj, _, err = readBrowserConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			args, _ = browserArgs(obj)
			if hasBrowserFlag(args) {
				t.Fatal("flag remains")
			}
			if tc.name == "existing args" && args != "--no-sandbox,--disable-dev-shm-usage" {
				t.Fatalf("operator args lost: %q", args)
			}
			if tc.name == "other keys" && string(obj["headed"]) != "true" {
				t.Fatal("operator key lost")
			}
		})
	}
}

func TestBrowserDefaultsSymlinkAndOverride(t *testing.T) {
	home := t.TempDir()
	path, _ := browserPaths(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "target")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := installBrowserDefaults(home); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := installBrowserDefaults(home); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_BROWSER_ARGS", "--no-sandbox")
	if state, _ := verifyBrowserDefaults(home); state != "overridden" {
		t.Fatalf("state %s", state)
	}
}

func TestBrowserDefaultsRollbackNewlineArgs(t *testing.T) {
	home := t.TempDir()
	path, _ := browserPaths(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"args":"--no-sandbox\n--lang=en-US"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installBrowserDefaults(home); err != nil {
		t.Fatal(err)
	}
	obj, _, err := readBrowserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if args, _ := browserArgs(obj); !hasBrowserFlag(args) {
		t.Fatalf("install did not add flag: %q", args)
	}
	if err := rollbackBrowserDefaults(home); err != nil {
		t.Fatal(err)
	}
	obj, _, err = readBrowserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := browserArgs(obj)
	if hasBrowserFlag(args) {
		t.Fatalf("flag remains after rollback: %q", args)
	}
	if args != "--no-sandbox\n--lang=en-US" {
		t.Fatalf("operator args not restored byte for byte: %q", args)
	}
}

func TestBrowserDefaultsRollbackCreatedLeavesNoBackup(t *testing.T) {
	home := t.TempDir()
	path, state := browserPaths(home)
	if err := installBrowserDefaults(home); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("install did not create config: %v", err)
	}
	if err := rollbackBrowserDefaults(home); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("rollback left files behind: %v", names)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("ownership record remains: %v", err)
	}
}

func TestBrowserDefaultsVerifyStates(t *testing.T) {
	for _, tc := range []struct {
		name, content, want string
	}{
		{"absent", "", "missing"},
		{"no flag", `{"args":"--no-sandbox"}`, "missing"},
		{"malformed", `{`, "invalid"},
		{"args not string", `{"args":["--x"]}`, "invalid"},
		{"present", `{"args":"--disable-blink-features=AutomationControlled"}`, "present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AGENT_BROWSER_ARGS", "")
			home := t.TempDir()
			path, _ := browserPaths(home)
			if tc.name != "absent" {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, remedy := verifyBrowserDefaults(home)
			if got != tc.want {
				t.Fatalf("state = %q, want %q", got, tc.want)
			}
			if tc.want == "invalid" && !strings.Contains(remedy, path) {
				t.Fatalf("invalid remedy must name the file: %q", remedy)
			}
		})
	}
}

func TestBrowserDefaultsRollbackAfterOperatorReformat(t *testing.T) {
	home := t.TempDir()
	path, _ := browserPaths(home)
	if err := installBrowserDefaults(home); err != nil {
		t.Fatal(err)
	}
	// The operator later reformats args one per line, keeping our flag.
	reformatted := `{"args":"--lang=en-US\n` + browserFlag + `"}`
	if err := os.WriteFile(path, []byte(reformatted), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rollbackBrowserDefaults(home); err != nil {
		t.Fatal(err)
	}
	obj, _, err := readBrowserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := browserArgs(obj)
	if hasBrowserFlag(args) {
		t.Fatalf("flag remains after rollback: %q", args)
	}
	if args != "--lang=en-US" {
		t.Fatalf("operator arg lost: %q", args)
	}
}

func writeBrowserTestFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserDefaultsInstallRefusals(t *testing.T) {
	t.Run("args not a string", func(t *testing.T) {
		home := t.TempDir()
		path, _ := browserPaths(home)
		writeBrowserTestFile(t, path, `{"args":["--x"]}`, 0o600)
		if err := installBrowserDefaults(home); err == nil || !strings.Contains(err.Error(), "args must be a string") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("stale ownership record", func(t *testing.T) {
		home := t.TempDir()
		_, state := browserPaths(home)
		writeBrowserTestFile(t, state, `{"created":true,"original_args":""}`, 0o600)
		if err := installBrowserDefaults(home); err == nil || !strings.Contains(err.Error(), "stale ownership record") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("malformed ownership record", func(t *testing.T) {
		home := t.TempDir()
		_, state := browserPaths(home)
		writeBrowserTestFile(t, state, `{`, 0o600)
		if err := installBrowserDefaults(home); err == nil {
			t.Fatal("accepted malformed ownership record")
		}
	})
	t.Run("config path under a file", func(t *testing.T) {
		home := t.TempDir()
		writeBrowserTestFile(t, filepath.Join(home, ".agent-browser"), "not a dir", 0o600)
		if err := installBrowserDefaults(home); err == nil {
			t.Fatal("accepted config path whose parent is a file")
		}
	})
	t.Run("state dir is a file", func(t *testing.T) {
		home := t.TempDir()
		writeBrowserTestFile(t, filepath.Join(home, ".hermes"), "not a dir", 0o600)
		if err := installBrowserDefaults(home); err == nil {
			t.Fatal("accepted state path whose parent is a file")
		}
	})
}

func TestBrowserDefaultsFilesystemFailures(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failures cannot be forced as root")
	}
	t.Run("unreadable config", func(t *testing.T) {
		home := t.TempDir()
		path, _ := browserPaths(home)
		writeBrowserTestFile(t, path, `{}`, 0o000)
		if err := installBrowserDefaults(home); err == nil {
			t.Fatal("accepted unreadable config")
		}
	})
}

func TestBrowserDefaultsRollbackRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, record, config, wantErr string
	}{
		{"created not bool", `{"created":"yes","original_args":""}`, "", "malformed ownership record"},
		{"original not string", `{"created":false,"original_args":1}`, "", "malformed ownership record"},
		{"malformed config", `{"created":false,"original_args":""}`, `{`, "malformed JSON"},
		{"config args not string", `{"created":false,"original_args":""}`, `{"args":1}`, "args must be a string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path, state := browserPaths(home)
			writeBrowserTestFile(t, state, tc.record, 0o600)
			if tc.config != "" {
				writeBrowserTestFile(t, path, tc.config, 0o600)
			}
			err := rollbackBrowserDefaults(home)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if _, statErr := os.Stat(state); statErr != nil {
				t.Fatalf("ownership record removed despite refusal: %v", statErr)
			}
		})
	}
}

// The operator removed their own args after install but left ours: rollback
// removes only Pipelock's flag and does not resurrect what the operator removed.
func TestBrowserDefaultsRollbackKeepsOperatorRemoval(t *testing.T) {
	home := t.TempDir()
	path, _ := browserPaths(home)
	writeBrowserTestFile(t, path, `{"args":"--lang=en-US"}`, 0o600)
	if err := installBrowserDefaults(home); err != nil {
		t.Fatal(err)
	}
	writeBrowserTestFile(t, path, `{"args":"`+browserFlag+`"}`, 0o600)
	if err := rollbackBrowserDefaults(home); err != nil {
		t.Fatal(err)
	}
	obj, _, err := readBrowserConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := obj["args"]; present {
		args, _ := browserArgs(obj)
		t.Fatalf("args = %q, want the key removed", args)
	}
}

// A custom Hermes config path must not steer where browser defaults land:
// agent-browser reads the Hermes user's home, not the config's grandparent.
func TestRunInstall_BrowserDefaultsUseResolvedHomeNotConfigPath(t *testing.T) {
	home := t.TempDir()
	elsewhere := t.TempDir()
	opts := fullOpts(elsewhere)
	opts.HomeDir = home
	opts.HermesConfig = filepath.Join(elsewhere, "etc", "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(opts.HermesConfig), 0o750); err != nil {
		t.Fatal(err)
	}
	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	want, _ := browserPaths(home)
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("browser defaults not in resolved home: %v", err)
	}
	wrong, _ := browserPaths(filepath.Dir(filepath.Dir(opts.HermesConfig)))
	if _, err := os.Stat(wrong); !os.IsNotExist(err) {
		t.Fatalf("browser defaults written next to the config path: %v", err)
	}
}

func TestRunInstall_BrowserDefaultsFailureNamesEscape(t *testing.T) {
	home := t.TempDir()
	opts := fullOpts(t.TempDir())
	opts.HomeDir = home
	path, _ := browserPaths(home)
	writeBrowserTestFile(t, path, `{`, 0o600)
	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runInstall(cmd, opts)
	if err == nil || !strings.Contains(err.Error(), "--no-browser-defaults") {
		t.Fatalf("err = %v, want the --no-browser-defaults escape named", err)
	}
	opts.NoBrowserDefaults = true
	if err := runInstall(cmd, opts); err != nil {
		t.Fatalf("install with --no-browser-defaults: %v", err)
	}
}

func TestRunRollback_BrowserDefaultsFailureSurfaces(t *testing.T) {
	home := t.TempDir()
	_, state := browserPaths(home)
	writeBrowserTestFile(t, state, `{"created":"yes","original_args":""}`, 0o600)
	tmp := t.TempDir()
	ropts := &rollbackOptions{HomeDir: home, PluginRoot: filepath.Join(tmp, "plugins", "pipelock"), HermesConfig: filepath.Join(tmp, "config.yaml")}
	rcmd := rollbackCmd()
	rcmd.SetOut(&bytes.Buffer{})
	rcmd.SetErr(&bytes.Buffer{})
	if err := runRollback(rcmd, ropts); err == nil || !strings.Contains(err.Error(), "malformed ownership record") {
		t.Fatalf("err = %v", err)
	}
}

func TestBrowserHomeResolution(t *testing.T) {
	if got, err := browserHome("/explicit"); err != nil || got != "/explicit" {
		t.Fatalf("explicit home = %q, %v", got, err)
	}
	prev := userHomeDir
	t.Cleanup(func() { userHomeDir = prev })
	userHomeDir = func() (string, error) { return "", os.ErrNotExist }
	if _, err := browserHome(""); err == nil {
		t.Fatal("missing home accepted")
	}
	userHomeDir = func() (string, error) { return "", nil }
	if _, err := browserHome(""); err == nil {
		t.Fatal("empty home accepted")
	}
}

// A failed integration install must not leave browser defaults behind.
func TestRunInstall_FailedInstallLeavesBrowserConfigUntouched(t *testing.T) {
	tmp := t.TempDir()
	conflict := filepath.Join(tmp, "blocker")
	writeBrowserTestFile(t, conflict, "x", 0o600)
	opts := &installOptions{Mode: ModeFull, HomeDir: tmp, PluginRoot: filepath.Join(conflict, "child"), HermesConfig: filepath.Join(tmp, "config.yaml")}
	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := runInstall(cmd, opts); err == nil {
		t.Fatal("install succeeded with a blocked plugin root")
	}
	path, state := browserPaths(tmp)
	for _, p := range []string{path, state} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("failed install left %s behind: %v", p, err)
		}
	}
}

// With no resolvable home and no --home, every command names the remedy
// instead of guessing a directory to write into.
func TestBrowserDefaultsUnresolvableHomeNamesRemedy(t *testing.T) {
	prev := userHomeDir
	t.Cleanup(func() { userHomeDir = prev })
	userHomeDir = func() (string, error) { return "", os.ErrNotExist }
	tmp := t.TempDir()
	plugin := filepath.Join(tmp, "plugins", "pipelock")
	cfg := filepath.Join(tmp, "config.yaml")

	cmd := installCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runInstall(cmd, &installOptions{Mode: ModeFull, PluginRoot: plugin, HermesConfig: cfg})
	if err == nil || !strings.Contains(err.Error(), "pass --home or --no-browser-defaults") {
		t.Fatalf("install err = %v", err)
	}
	if _, statErr := os.Stat(plugin); !os.IsNotExist(statErr) {
		t.Fatalf("install changed the plugin root before refusing: %v", statErr)
	}

	rcmd := rollbackCmd()
	rcmd.SetOut(&bytes.Buffer{})
	rcmd.SetErr(&bytes.Buffer{})
	if err := runRollback(rcmd, &rollbackOptions{PluginRoot: plugin, HermesConfig: cfg}); err == nil || !strings.Contains(err.Error(), "resolve home") {
		t.Fatalf("rollback err = %v", err)
	}

	report := buildVerifyReport(&installOptions{PluginRoot: plugin, HermesConfig: cfg})
	if report.BrowserDefaults != "unknown" || !strings.Contains(report.BrowserRemedy, "pass --home") {
		t.Fatalf("verify = %q / %q", report.BrowserDefaults, report.BrowserRemedy)
	}
}
