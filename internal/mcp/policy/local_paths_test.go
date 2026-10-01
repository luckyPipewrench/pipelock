// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testShellProfileRule = "Shell Profile Modification"
	testKeyReadRule      = "Credential File Access"
	testPersistenceRule  = "Persistence Path Write"
	testPatchTool        = "apply_patch"
	testWriteTool        = "write_file"
	testReadTool         = "read_file"
)

// localPathFixture is a disposable home directory and a workspace beside it.
type localPathFixture struct {
	home string
	ws   string
}

func newLocalPathFixture(t *testing.T) localPathFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixtures need POSIX link semantics")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := localPathFixture{home: filepath.Join(root, "home"), ws: filepath.Join(root, "home", "ws")}
	if err := os.MkdirAll(f.ws, 0o750); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f localPathFixture) write(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("baseline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f localPathFixture) link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

func (f localPathFixture) policy(enabled bool) *Config {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	if enabled {
		pc.localPaths = newLocalPathIdentity([]string{f.home}, f.ws)
	}
	return pc
}

func checkPath(pc *Config, tool, key, value string) Verdict {
	raw, _ := json.Marshal(map[string]string{key: value})
	return pc.CheckToolCallWithArgs(tool, []string{value}, raw)
}

func TestLocalPathIdentity_ResolvesAliasesToProtectedFiles(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, f localPathFixture) string // returns the submitted value
		tool     string
		key      string
		wantRule string
	}{
		{
			name: "symlink to protected file",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".profile"))
				f.link(t, filepath.Join(f.home, ".profile"), filepath.Join(f.ws, "notes.txt"))
				return filepath.Join(f.ws, "notes.txt")
			},
			tool: testWriteTool, key: "path", wantRule: testShellProfileRule,
		},
		{
			name: "relative symlink resolved against the working directory",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".bashrc"))
				f.link(t, "../.bashrc", filepath.Join(f.ws, "notes.txt"))
				return "notes.txt"
			},
			tool: testWriteTool, key: "path", wantRule: testShellProfileRule,
		},
		{
			name: "protected name is a symlink to the submitted file",
			setup: func(t *testing.T, f localPathFixture) string {
				backing := filepath.Join(f.ws, "dotfiles", "profile")
				f.write(t, backing)
				f.link(t, backing, filepath.Join(f.home, ".profile"))
				return backing
			},
			tool: testWriteTool, key: "path", wantRule: testShellProfileRule,
		},
		{
			name: "hard link to protected file",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".zshrc"))
				if err := os.Link(filepath.Join(f.home, ".zshrc"), filepath.Join(f.ws, "h")); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(f.ws, "h")
			},
			tool: testWriteTool, key: "path", wantRule: testShellProfileRule,
		},
		{
			name: "dangling symlink to a protected file not yet created",
			setup: func(t *testing.T, f localPathFixture) string {
				f.link(t, filepath.Join(f.home, ".zprofile"), filepath.Join(f.ws, "new.txt"))
				return filepath.Join(f.ws, "new.txt")
			},
			tool: testWriteTool, key: "path", wantRule: testShellProfileRule,
		},
		{
			name: "new file under a symlinked protected directory",
			setup: func(t *testing.T, f localPathFixture) string {
				if err := os.MkdirAll(filepath.Join(f.home, ".ssh"), 0o750); err != nil {
					t.Fatal(err)
				}
				f.link(t, filepath.Join(f.home, ".ssh"), filepath.Join(f.ws, "keys"))
				return "keys/id_ed25519"
			},
			tool: testReadTool, key: "path", wantRule: testKeyReadRule,
		},
		{
			name: "protected directory is a symlink to the submitted directory",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.ws, "keys", "id_rsa"))
				f.link(t, filepath.Join(f.ws, "keys"), filepath.Join(f.home, ".ssh"))
				return filepath.Join(f.ws, "keys", "id_rsa")
			},
			tool: testReadTool, key: "path", wantRule: testKeyReadRule,
		},
		{
			name: "tilde path through a link",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".bash_profile"))
				f.link(t, filepath.Join(f.home, ".bash_profile"), filepath.Join(f.home, "plain"))
				return "~/plain"
			},
			tool: testWriteTool, key: "path", wantRule: testShellProfileRule,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalPathFixture(t)
			value := tc.setup(t, f)

			// Positive control: the submitted text alone does not name the file.
			if v := checkPath(f.policy(false), tc.tool, tc.key, value); slices.Contains(v.Rules, tc.wantRule) {
				t.Fatalf("fixture is not an alias: %q already matches %s by text", value, tc.wantRule)
			}
			v := checkPath(f.policy(true), tc.tool, tc.key, value)
			if !slices.Contains(v.Rules, tc.wantRule) {
				t.Fatalf("local path identity did not match %s for %q: %+v", tc.wantRule, value, v)
			}
		})
	}
}

func TestLocalPathIdentity_ZDOTDIRStartupFileIsLink(t *testing.T) {
	f := newLocalPathFixture(t)
	zdot := filepath.Join(f.home, ".config", "zsh")
	if err := os.MkdirAll(zdot, 0o750); err != nil {
		t.Fatal(err)
	}
	backing := filepath.Join(f.ws, "zshrc")
	f.write(t, backing)
	f.link(t, backing, filepath.Join(zdot, ".zshrc"))

	if v := checkPath(f.policy(true), testWriteTool, "path", backing); slices.Contains(v.Rules, testShellProfileRule) {
		t.Fatalf("fixture matched without ZDOTDIR: %+v", v)
	}
	t.Setenv("ZDOTDIR", zdot)
	t.Setenv("HOME", f.home)
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	pc.EnableLocalPathIdentity()
	if v := checkPath(pc, testWriteTool, "path", backing); !slices.Contains(v.Rules, testShellProfileRule) {
		t.Fatalf("ZDOTDIR startup file behind a link was not matched: %+v", v)
	}
}

func TestLocalPathIdentity_PatchTargetAlias(t *testing.T) {
	f := newLocalPathFixture(t)
	f.write(t, filepath.Join(f.home, ".bashrc"))
	f.link(t, filepath.Join(f.home, ".bashrc"), filepath.Join(f.ws, "notes.txt"))
	patch := "--- a/notes.txt\n+++ b/notes.txt\n@@ -1 +1 @@\n-baseline\n+changed\n"

	if v := f.policy(false).CheckToolCall(testPatchTool, []string{patch}); slices.Contains(v.Rules, testShellProfileRule) {
		t.Fatalf("patch fixture matched by text alone: %+v", v)
	}
	if v := f.policy(true).CheckToolCall(testPatchTool, []string{patch}); !slices.Contains(v.Rules, testShellProfileRule) {
		t.Fatalf("patch through an alias was not matched: %+v", v)
	}
}

func TestLocalPathIdentity_KeyScopedRule(t *testing.T) {
	f := newLocalPathFixture(t)
	f.write(t, filepath.Join(f.ws, "guarded-target"))
	f.link(t, filepath.Join(f.ws, "guarded-target"), filepath.Join(f.ws, "innocent"))
	const ruleName = "Guarded Destination"
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{
		Name: ruleName, ToolPattern: `^copy_file$`, ArgKey: `^destination$`, ArgPattern: `guarded-target`,
	}}})
	pc.localPaths = newLocalPathIdentity([]string{f.home}, f.ws)

	raw := json.RawMessage(`{"source":"a","destination":"innocent"}`)
	v := pc.CheckToolCallWithArgs("copy_file", []string{"a", "innocent"}, raw)
	if !slices.Contains(v.Rules, ruleName) {
		t.Fatalf("key-scoped value was not resolved: %+v", v)
	}
	raw = json.RawMessage(`{"source":"innocent","destination":"b"}`)
	if v := pc.CheckToolCallWithArgs("copy_file", []string{"innocent", "b"}, raw); v.Matched {
		t.Fatalf("resolution leaked outside the scoped key: %+v", v)
	}
}

func TestLocalPathIdentity_OrdinaryValuesUnchanged(t *testing.T) {
	f := newLocalPathFixture(t)
	f.write(t, filepath.Join(f.home, ".profile"))
	f.write(t, filepath.Join(f.ws, "plain.txt"))
	loopA, loopB := filepath.Join(f.ws, "loop-a"), filepath.Join(f.ws, "loop-b")
	f.link(t, loopB, loopA)
	f.link(t, loopA, loopB)
	l := newLocalPathIdentity([]string{f.home}, f.ws)

	for _, values := range [][]string{
		{filepath.Join(f.ws, "plain.txt")},
		{"hello", "rm -rf /tmp/x", "https://api.vendor.example/.profile"},
		{"line one\nline two", ""},
		{loopA},
		{filepath.Join(f.ws, "missing-dir", "x")},
	} {
		if got := l.expand(values); !slices.Equal(got, values) {
			t.Errorf("expand(%q) = %q, want unchanged", values, got)
		}
	}
	if got := l.expand([]string{"plain.txt"}); !slices.Equal(got, []string{"plain.txt", filepath.Join(f.ws, "plain.txt")}) {
		t.Errorf("existing relative name did not resolve under its base: %q", got)
	}
	if v := checkPath(f.policy(true), testWriteTool, "path", filepath.Join(f.ws, "plain.txt")); v.Matched {
		t.Fatalf("ordinary workspace write matched: %+v", v)
	}
}

func TestLocalPathIdentity_ResolvedPathDoesNotReplaceSubmitted(t *testing.T) {
	f := newLocalPathFixture(t)
	// The submitted protected name must still match even when it resolves to an
	// ordinary-looking backing file.
	backing := filepath.Join(f.ws, "backing")
	f.write(t, backing)
	f.link(t, backing, filepath.Join(f.home, ".profile"))
	if v := checkPath(f.policy(true), testWriteTool, "path", filepath.Join(f.home, ".profile")); !slices.Contains(v.Rules, testShellProfileRule) {
		t.Fatalf("submitted protected name lost after resolution: %+v", v)
	}
}

func TestLocalPathIdentity_NilAndDisabled(t *testing.T) {
	var pc *Config
	pc.EnableLocalPathIdentity()
	var l *localPathIdentity
	in := []string{"/etc/profile"}
	if got := l.expand(in); !slices.Equal(got, in) {
		t.Fatalf("nil identity changed values: %q", got)
	}
	enabled := New(config.MCPToolPolicy{Enabled: true, Rules: DefaultToolPolicyRules()})
	enabled.EnableLocalPathIdentity()
	if enabled.localPaths == nil {
		t.Fatal("EnableLocalPathIdentity did not install a resolver")
	}
	if got := newLocalPathIdentity(nil, "").expand([]string{"~/x", "rel"}); !slices.Equal(got, []string{"~/x", "rel"}) {
		t.Fatalf("identity without home or cwd resolved relative values: %q", got)
	}
}

func TestShellLinkCommandsToProtectedPaths(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	cases := []struct {
		cmd      string
		wantRule string // empty = must not match either rule
	}{
		{cmd: "ln -s /home/u/.bashrc /work/notes.txt", wantRule: "Shell Profile Write via Command"},
		{cmd: "ln -s ~/.profile notes && echo x > notes", wantRule: "Shell Profile Write via Command"},
		{cmd: "ln -sf /etc/profile /work/p", wantRule: "Shell Profile Write via Command"},
		{cmd: "ln -sf /dev/null /var/lib/pipelock/receipts.jsonl", wantRule: "Audit Log Tampering"},
		{cmd: "ln -s /var/log/app/current.log ./app.log", wantRule: "Audit Log Tampering"},
		{cmd: "link /home/u/.bashrc notes.txt", wantRule: "Shell Profile Write via Command"},
		{cmd: "cp -s /home/u/.bashrc notes.txt", wantRule: "Shell Profile Write via Command"},
		{cmd: "cp -rl /home/u/.profile notes.txt", wantRule: "Shell Profile Write via Command"},
		{cmd: "cp --symbolic-link /etc/profile p", wantRule: "Shell Profile Write via Command"},
		{cmd: "ln -s /var/log /tmp/logalias", wantRule: "Audit Log Tampering"},
		{cmd: "ln -s var/log/auth.log ./a", wantRule: "Audit Log Tampering"},
		{cmd: "cp /tmp/source ~/.profile --symbolic-link", wantRule: "Shell Profile Write via Command"},
		{cmd: "cp /tmp/source /etc/profile -s", wantRule: "Shell Profile Write via Command"},
		{cmd: "cp /tmp/source /var/log --symbolic-link", wantRule: "Audit Log Tampering"},
		{cmd: "cp ~/.bashrc backup -L"},
		{cmd: "cp -L /home/u/.bashrc backup"},
		{cmd: "ln -s /var/logs-archive x"},
		{cmd: "ln -s build/out dist"},
		{cmd: "cat ~/.bashrc; ln -s a b"},
		{cmd: "tail /var/log/syslog; ln -s a b"},
		{cmd: "ln -sf ~/dotfiles/zshrc ~/.zshrc && exec zsh", wantRule: "Shell Profile Write via Command"},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			v := pc.CheckToolCall("bash", []string{tc.cmd})
			if tc.wantRule == "" {
				for _, rule := range []string{"Shell Profile Write via Command", "Audit Log Tampering"} {
					if slices.Contains(v.Rules, rule) {
						t.Fatalf("%q matched %s", tc.cmd, rule)
					}
				}
				return
			}
			if !slices.Contains(v.Rules, tc.wantRule) {
				t.Fatalf("%q did not match %s: %+v", tc.cmd, tc.wantRule, v)
			}
		})
	}
}

func TestLocalPathIdentity_RelativeNameResolvesAgainstWriterDirectory(t *testing.T) {
	f := newLocalPathFixture(t)
	root := filepath.Join(f.home, "server-root")
	f.write(t, filepath.Join(root, ".profile"))
	f.link(t, filepath.Join(root, ".profile"), filepath.Join(root, "notes.txt"))

	// Pipelock's own directory (f.ws) holds no notes.txt; the writer resolves
	// relative names against root.
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	pc.localPaths = newLocalPathIdentity([]string{f.home}, f.ws)
	for _, value := range []string{"notes.txt", "./notes.txt"} {
		if v := checkPath(pc, testWriteTool, "path", value); slices.Contains(v.Rules, testShellProfileRule) {
			t.Fatalf("%q matched without the writer's base: %+v", value, v)
		}
	}
	pc.AddLocalPathBases(root, "relative-ignored")
	for _, value := range []string{"notes.txt", "./notes.txt"} {
		if v := checkPath(pc, testWriteTool, "path", value); !slices.Contains(v.Rules, testShellProfileRule) {
			t.Fatalf("%q not resolved against the writer's base: %+v", value, v)
		}
	}
	var nilCfg *Config
	nilCfg.AddLocalPathBases(root)
	New(config.MCPToolPolicy{Enabled: true, Rules: DefaultToolPolicyRules()}).AddLocalPathBases(root)
}

func TestLocalPathIdentity_DanglingProtectedLink(t *testing.T) {
	f := newLocalPathFixture(t)
	target := filepath.Join(f.ws, "dotfiles", "profile")
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		t.Fatal(err)
	}
	// .profile points at a file that does not exist yet; writing the target
	// creates what the startup file exposes.
	f.link(t, target, filepath.Join(f.home, ".profile"))
	if v := checkPath(f.policy(false), testWriteTool, "path", target); slices.Contains(v.Rules, testShellProfileRule) {
		t.Fatalf("fixture matched by text alone: %+v", v)
	}
	if v := checkPath(f.policy(true), testWriteTool, "path", target); !slices.Contains(v.Rules, testShellProfileRule) {
		t.Fatalf("write creating a dangling protected link's target was not matched: %+v", v)
	}
}

func TestLocalPathIdentity_DotDotAfterSymlinkedDirectory(t *testing.T) {
	f := newLocalPathFixture(t)
	// jump -> home/deep/inner. The kernel reads jump/../hit as home/deep/hit,
	// a link to .profile; a lexical cleaner reads it as the ordinary ws/hit.
	deep := filepath.Join(f.home, "deep")
	if err := os.MkdirAll(filepath.Join(deep, "inner"), 0o750); err != nil {
		t.Fatal(err)
	}
	f.write(t, filepath.Join(f.home, ".profile"))
	f.link(t, filepath.Join(f.home, ".profile"), filepath.Join(deep, "hit"))
	f.write(t, filepath.Join(f.ws, "hit"))
	f.link(t, filepath.Join(deep, "inner"), filepath.Join(f.ws, "jump"))
	value := f.ws + "/jump/../hit" // not filepath.Join, which would clean the .. away

	// os.Stat goes through the kernel, so it is the oracle for what an open of
	// value reaches.
	opened, err := os.Stat(value)
	profile, perr := os.Stat(filepath.Join(f.home, ".profile"))
	if err != nil || perr != nil || !os.SameFile(opened, profile) {
		t.Fatalf("fixture: kernel does not open .profile through %q (%v, %v)", value, err, perr)
	}
	if v := checkPath(f.policy(true), testWriteTool, "path", value); !slices.Contains(v.Rules, testShellProfileRule) {
		t.Fatalf("kernel view of .. through a symlinked directory was not matched: %+v", v)
	}
}

func TestResolveLocalPath_Edges(t *testing.T) {
	f := newLocalPathFixture(t)
	if got, ok := resolveLocalPath(filepath.Join(f.ws, "missing", "x")); ok {
		t.Errorf("path under a missing directory resolved to %q", got)
	}
	if got, ok := resolveLocalPath(f.ws + "/missing/.."); ok {
		t.Errorf("dot-dot under a missing directory resolved to %q", got)
	}
	if got, ok := resolveLocalPath("relative/path"); ok {
		t.Errorf("relative path resolved to %q", got)
	}
	f.write(t, filepath.Join(f.ws, "file"))
	if got, ok := resolveLocalPath(filepath.Join(f.ws, "file", "child")); ok {
		t.Errorf("path through a regular file resolved to %q", got)
	}
	if got, ok := resolveLocalPath(f.ws + "/./sub/"); !ok || got != filepath.Join(f.ws, "sub") {
		t.Errorf("trailing separator and dot: got %q, %v", got, ok)
	}
	if got := withPatchPrefixStripped([]string{"plain"}); !slices.Equal(got, []string{"plain"}) {
		t.Errorf("unprefixed patch target changed: %q", got)
	}
}

func TestLocalPathIdentity_NewBareNameInProtectedBase(t *testing.T) {
	f := newLocalPathFixture(t)
	ssh := filepath.Join(f.home, ".ssh")
	if err := os.MkdirAll(ssh, 0o750); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(f.ws, "root")
	f.link(t, ssh, root)

	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	pc.localPaths = newLocalPathIdentity([]string{f.home}, f.ws)
	if v := checkPath(pc, testReadTool, "path", "authorized_keys"); slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("matched without the protected base: %+v", v)
	}
	pc.AddLocalPathBases(root)
	if v := checkPath(pc, testReadTool, "path", "authorized_keys"); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("new bare name under a base linked to ~/.ssh was not matched: %+v", v)
	}
	// An ordinary base still ignores a bare word that names nothing.
	if got := newLocalPathIdentity([]string{f.home}, f.ws).expand([]string{"hello"}); !slices.Equal(got, []string{"hello"}) {
		t.Fatalf("bare word under an ordinary base resolved: %q", got)
	}
}

// TestResolveLocalPath_PlatformRoot runs on every platform, including Windows
// drive-letter roots, with no links involved.
func TestResolveLocalPath_PlatformRoot(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "file"), filepath.ToSlash(filepath.Join(dir, "file"))} {
		got, ok := resolveLocalPath(path)
		if !ok || got != filepath.Join(dir, "file") {
			t.Errorf("resolveLocalPath(%q) = %q, %v; want %q", path, got, ok, filepath.Join(dir, "file"))
		}
	}
	if got, ok := resolveLocalPath(filepath.Join(dir, "new")); !ok || got != filepath.Join(dir, "new") {
		t.Errorf("new file: %q, %v", got, ok)
	}
	root, rest := splitVolumeRoot(dir)
	if root != filepath.VolumeName(dir)+string(filepath.Separator) || len(rest) == 0 {
		t.Errorf("splitVolumeRoot(%q) = %q, %q", dir, root, rest)
	}
}

func TestLinkTargetStart(t *testing.T) {
	sep := string(filepath.Separator)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	volume := filepath.VolumeName(dir)

	start, parts := linkTargetStart(dir, "child"+sep+"leaf")
	if start != dir || !slices.Equal(parts, []string{"child", "leaf"}) {
		t.Errorf("relative target: %q, %q", start, parts)
	}
	start, parts = linkTargetStart(dir, dir+sep+"leaf")
	if wantRoot, wantParts := splitVolumeRoot(dir + sep + "leaf"); start != wantRoot || !slices.Equal(parts, wantParts) {
		t.Errorf("absolute target: %q, %q", start, parts)
	}
	// A separator-rooted target with no drive starts at the link's own root.
	// On POSIX this is simply absolute; on Windows it is the drive-less form.
	start, parts = linkTargetStart(dir, sep+"Users"+sep+"x")
	if start != volume+sep || !slices.Contains(parts, "Users") || parts[len(parts)-1] != "x" {
		t.Errorf("root-relative target: %q, %q", start, parts)
	}
}

func hardLink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(newname), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(oldname, newname); err != nil {
		t.Fatal(err)
	}
}

func TestLocalPathIdentity_HardLinkIntoProtectedDirectory(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, f localPathFixture) string
		tool     string
		key      string
		wantRule string // empty means no rule may match
	}{
		{
			name: "hard link to a private key inside the SSH directory",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".ssh", "id_ed25519"))
				hardLink(t, filepath.Join(f.home, ".ssh", "id_ed25519"), filepath.Join(f.ws, "notes.txt"))
				return filepath.Join(f.ws, "notes.txt")
			},
			tool: testReadTool, key: "path", wantRule: testKeyReadRule,
		},
		{
			name: "relative hard link to a private key inside the SSH directory",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".ssh", "id_rsa"))
				hardLink(t, filepath.Join(f.home, ".ssh", "id_rsa"), filepath.Join(f.ws, "k"))
				return "k"
			},
			tool: testReadTool, key: "path", wantRule: testKeyReadRule,
		},
		{
			name: "hard link to a user unit file",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".config", "systemd", "user", "x.service"))
				hardLink(t, filepath.Join(f.home, ".config", "systemd", "user", "x.service"), filepath.Join(f.ws, "svc"))
				return filepath.Join(f.ws, "svc")
			},
			tool: testWriteTool, key: "path", wantRule: testPersistenceRule,
		},
		{
			name: "hard link to a public key stays readable",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".ssh", "id_ed25519.pub"))
				hardLink(t, filepath.Join(f.home, ".ssh", "id_ed25519.pub"), filepath.Join(f.ws, "pub.txt"))
				return filepath.Join(f.ws, "pub.txt")
			},
			tool: testReadTool, key: "path",
		},
		{
			name: "linked file unrelated to the protected directory",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".ssh", "id_ed25519"))
				f.write(t, filepath.Join(f.ws, "a.txt"))
				hardLink(t, filepath.Join(f.ws, "a.txt"), filepath.Join(f.ws, "b.txt"))
				return filepath.Join(f.ws, "b.txt")
			},
			tool: testReadTool, key: "path",
		},
		{
			name: "file with the same content as a key is not the key",
			setup: func(t *testing.T, f localPathFixture) string {
				f.write(t, filepath.Join(f.home, ".ssh", "id_ed25519"))
				f.write(t, filepath.Join(f.ws, "copy.txt"))
				return filepath.Join(f.ws, "copy.txt")
			},
			tool: testReadTool, key: "path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalPathFixture(t)
			value := tc.setup(t, f)

			if tc.wantRule == "" {
				v := checkPath(f.policy(true), tc.tool, tc.key, value)
				if slices.Contains(v.Rules, testKeyReadRule) || slices.Contains(v.Rules, testPersistenceRule) {
					t.Fatalf("%q must not be matched as a protected file: %+v", value, v)
				}
				return
			}
			// Positive control: the submitted text alone does not name the file.
			if v := checkPath(f.policy(false), tc.tool, tc.key, value); slices.Contains(v.Rules, tc.wantRule) {
				t.Fatalf("fixture is not an alias: %q already matches %s by text", value, tc.wantRule)
			}
			v := checkPath(f.policy(true), tc.tool, tc.key, value)
			if !slices.Contains(v.Rules, tc.wantRule) {
				t.Fatalf("hard link into a protected directory not matched as %s for %q: %+v", tc.wantRule, value, v)
			}
		})
	}
}

func TestLocalPathIdentity_HardLinkScanFailsClosed(t *testing.T) {
	t.Run("directory over the entry bound", func(t *testing.T) {
		f := newLocalPathFixture(t)
		for _, name := range []string{"id_a", "id_b", "id_c"} {
			f.write(t, filepath.Join(f.home, ".ssh", name))
		}
		f.write(t, filepath.Join(f.ws, "a.txt"))
		hardLink(t, filepath.Join(f.ws, "a.txt"), filepath.Join(f.ws, "b.txt"))
		value := filepath.Join(f.ws, "b.txt")

		// Within the bound the scan completes and the unrelated file is clear.
		if v := checkPath(f.policy(true), testReadTool, "path", value); slices.Contains(v.Rules, testKeyReadRule) {
			t.Fatalf("unrelated linked file matched within the bound: %+v", v)
		}
		old := localPathMaxDirEntries
		localPathMaxDirEntries = 2
		t.Cleanup(func() { localPathMaxDirEntries = old })
		if v := checkPath(f.policy(true), testReadTool, "path", value); !slices.Contains(v.Rules, testKeyReadRule) {
			t.Fatalf("a directory over the entry bound must be treated as holding the file: %+v", v)
		}
	})

	t.Run("unreadable directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads any directory")
		}
		f := newLocalPathFixture(t)
		f.write(t, filepath.Join(f.home, ".ssh", "id_ed25519"))
		f.write(t, filepath.Join(f.ws, "a.txt"))
		hardLink(t, filepath.Join(f.ws, "a.txt"), filepath.Join(f.ws, "b.txt"))
		f.write(t, filepath.Join(f.ws, "solo.txt"))
		ssh := filepath.Join(f.home, ".ssh")
		if err := os.Chmod(ssh, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(ssh, 0o700) }) //nolint:gosec // a directory needs search permission back so cleanup can remove it

		// The directory is on the same filesystem, so it could hold the file and
		// cannot be listed to say otherwise. This user owns both; ownership does
		// not change the answer.
		if v := checkPath(f.policy(true), testReadTool, "path", filepath.Join(f.ws, "b.txt")); !slices.Contains(v.Rules, testKeyReadRule) {
			t.Fatalf("an unreadable protected directory on the same device must fail closed: %+v", v)
		}
		// A file with a single link cannot be a hard link, so it never reads the directory.
		if v := checkPath(f.policy(true), testReadTool, "path", filepath.Join(f.ws, "solo.txt")); slices.Contains(v.Rules, testKeyReadRule) {
			t.Fatalf("a single-link file must not consult the directory: %+v", v)
		}
	})

	t.Run("absent directory holds no link", func(t *testing.T) {
		f := newLocalPathFixture(t)
		f.write(t, filepath.Join(f.ws, "a.txt"))
		hardLink(t, filepath.Join(f.ws, "a.txt"), filepath.Join(f.ws, "b.txt"))
		if v := checkPath(f.policy(true), testReadTool, "path", filepath.Join(f.ws, "b.txt")); slices.Contains(v.Rules, testKeyReadRule) {
			t.Fatalf("no .ssh directory exists, nothing to match: %+v", v)
		}
	})
}
