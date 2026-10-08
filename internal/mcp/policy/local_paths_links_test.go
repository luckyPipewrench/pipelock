// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func setDifferentDevice(t *testing.T, fn func(a, b os.FileInfo) bool) {
	t.Helper()
	old := differentDevice
	differentDevice = fn
	t.Cleanup(func() { differentDevice = old })
}

func chmodForTest(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Restore the original mode so cleanup can remove the directory.
	original := info.Mode().Perm()
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, original) })
}

// TestLocalPathIdentity_UnreadableOwnDirectoryFailsClosed is the case an owner
// based allowance got wrong: the user owns the protected directory and the key
// in it, cannot list it, and a hard link to the key must still be refused.
func TestLocalPathIdentity_UnreadableOwnDirectoryFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	f := newLocalPathFixture(t)
	key := filepath.Join(f.home, ".ssh", "id_ed25519")
	f.write(t, key)
	hardLink(t, key, filepath.Join(f.ws, "notes.txt"))
	chmodForTest(t, filepath.Dir(key), 0o300)
	if v := checkPath(f.policy(true), testReadTool, "path", filepath.Join(f.ws, "notes.txt")); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("hard link to a key in an own, unlistable SSH directory was not matched: %+v", v)
	}
}

func TestLocalPathIdentity_HardLinkAcrossDevicesIsNotHeld(t *testing.T) {
	f := newLocalPathFixture(t)
	key := filepath.Join(f.home, ".ssh", "id_ed25519")
	f.write(t, key)
	hardLink(t, key, filepath.Join(f.ws, "notes.txt"))
	value := filepath.Join(f.ws, "notes.txt")

	// Positive control: on one device the link is found.
	if v := checkPath(f.policy(true), testReadTool, "path", value); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("control: same-device hard link not matched: %+v", v)
	}
	// A file on another device than the directory cannot be linked into it, so
	// the directory is not even read.
	setDifferentDevice(t, func(_, _ os.FileInfo) bool { return true })
	if v := checkPath(f.policy(true), testReadTool, "path", value); slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("a file on another device was matched as held by the directory: %+v", v)
	}
	if os.Geteuid() == 0 {
		return
	}
	// The unlistable directory fails closed only when the device matches.
	chmodForTest(t, filepath.Dir(key), 0o000)
	if v := checkPath(f.policy(true), testReadTool, "path", value); slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("an unlistable directory on another device must not refuse the file: %+v", v)
	}
	setDifferentDevice(t, func(_, _ os.FileInfo) bool { return false })
	if v := checkPath(f.policy(true), testReadTool, "path", value); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("an unlistable directory on the same device must refuse the file: %+v", v)
	}
}

func TestLocalPathIdentity_HardLinkScanCoversSubtree(t *testing.T) {
	cases := []struct {
		name     string
		linked   string // path under the fixture home
		tool     string
		wantRule string
	}{
		{"systemd drop-in", filepath.Join(".config", "systemd", "user", "x.service.d", "o.conf"), testWriteTool, testPersistenceRule},
		{"systemd wants entry two levels down", filepath.Join(".config", "systemd", "user", "default.target.wants", "d", "x.service"), testWriteTool, testPersistenceRule},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalPathFixture(t)
			target := filepath.Join(f.home, tc.linked)
			f.write(t, target)
			hardLink(t, target, filepath.Join(f.ws, "alias"))
			value := filepath.Join(f.ws, "alias")
			if v := checkPath(f.policy(false), tc.tool, "path", value); slices.Contains(v.Rules, tc.wantRule) {
				t.Fatalf("fixture is not an alias: %q already matches %s", value, tc.wantRule)
			}
			if v := checkPath(f.policy(true), tc.tool, "path", value); !slices.Contains(v.Rules, tc.wantRule) {
				t.Fatalf("nested hard link not matched as %s: %+v", tc.wantRule, v)
			}
		})
	}
}

func TestLocalPathIdentity_HardLinkScanSubtreeBounds(t *testing.T) {
	newFixture := func(t *testing.T) (f localPathFixture, value string) {
		f = newLocalPathFixture(t)
		f.write(t, filepath.Join(f.ws, "a.txt"))
		hardLink(t, filepath.Join(f.ws, "a.txt"), filepath.Join(f.ws, "b.txt"))
		return f, filepath.Join(f.ws, "b.txt")
	}
	ssh := func(f localPathFixture, parts ...string) string {
		return filepath.Join(append([]string{f.home, ".ssh"}, parts...)...)
	}
	matched := func(f localPathFixture, value string) bool {
		return slices.Contains(checkPath(f.policy(true), testReadTool, "path", value).Rules, testKeyReadRule)
	}

	t.Run("one entry bound across the whole walk", func(t *testing.T) {
		f, value := newFixture(t)
		f.write(t, ssh(f, "d1", "f1"))
		f.write(t, ssh(f, "d2", "f2"))
		f.write(t, ssh(f, "d3", "f3"))
		// 3 directories and 3 files: 6 entries in total, none of them above 2 per level.
		if matched(f, value) {
			t.Fatal("control: unrelated file matched within the bound")
		}
		old := localPathMaxDirEntries
		t.Cleanup(func() { localPathMaxDirEntries = old })
		localPathMaxDirEntries = 5
		if !matched(f, value) {
			t.Fatal("a tree over the total entry bound must be treated as holding the file")
		}
		localPathMaxDirEntries = 6
		if matched(f, value) {
			t.Fatal("a tree exactly at the bound must complete")
		}
	})

	t.Run("symlinked directory is not followed", func(t *testing.T) {
		f, value := newFixture(t)
		f.write(t, ssh(f, "keep"))
		f.link(t, f.ws, ssh(f, "id_link"))
		if matched(f, value) {
			t.Fatal("a symlink inside the protected directory was followed")
		}
	})

	t.Run("unreadable subdirectory on the same device", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads any directory")
		}
		f, value := newFixture(t)
		f.write(t, ssh(f, "sub", "f"))
		if matched(f, value) {
			t.Fatal("control: unrelated file matched")
		}
		chmodForTest(t, ssh(f, "sub"), 0o000)
		if !matched(f, value) {
			t.Fatal("an unreadable same-device subdirectory must fail closed")
		}
		// The same subdirectory on another device cannot hold the file.
		setDifferentDevice(t, func(_, b os.FileInfo) bool { return b.Name() == "sub" })
		if matched(f, value) {
			t.Fatal("a subtree on another device must be skipped")
		}
	})
}

func TestLocalPathIdentity_HomesFromEnvironmentAndAccountDatabase(t *testing.T) {
	f := newLocalPathFixture(t)
	other := t.TempDir()
	key := filepath.Join(f.home, ".ssh", "id_ed25519")
	f.write(t, key)
	hardLink(t, key, filepath.Join(f.ws, "notes.txt"))
	value := filepath.Join(f.ws, "notes.txt")
	t.Setenv("HOME", other)
	t.Setenv("ZDOTDIR", "")
	old := accountHomeDir
	t.Cleanup(func() { accountHomeDir = old })

	enable := func() *Config {
		pc := f.policy(false)
		pc.EnableLocalPathIdentity()
		return pc
	}
	// Control: with the account database naming no usable home, only $HOME is
	// protected, so the fixture home's key is not found.
	accountHomeDir = func() (string, error) { return "", errors.New("no account entry") }
	if v := checkPath(enable(), testReadTool, "path", value); slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("control: matched without the account home: %+v", v)
	}
	accountHomeDir = func() (string, error) { return f.home, nil }
	if v := checkPath(enable(), testReadTool, "path", value); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("hard link into the account home's SSH directory not matched when $HOME differs: %+v", v)
	}
	// A tilde names each home.
	l := newLocalPathIdentity(CredentialHomes(nil), f.ws)
	got := l.paths("~/x", func(string) bool { return false })
	if !slices.Equal(got, []string{other + "/x", f.home + "/x"}) {
		t.Fatalf("~ expanded to %q", got)
	}
}

// splitPolicyAlternatives splits a regular expression on the | operators that
// are not inside a group or a character class.
func splitPolicyAlternatives(t *testing.T, pattern string) []string {
	t.Helper()
	var parts []string
	depth, start := 0, 0
	inClass := false
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '|' && depth == 0:
			parts = append(parts, pattern[start:i])
			start = i + 1
		}
	}
	if depth != 0 || inClass {
		t.Fatalf("unbalanced pattern %q", pattern)
	}
	return append(parts, pattern[start:])
}

// literalGroupPattern matches an innermost non-capturing group whose members
// are all plain literals: letters, digits, `_`, `-`, `/` and an escaped dot. A
// group with an anchor, a class or an escape such as `\s` is not a list of
// locations and is left alone.
var literalGroupPattern = regexp.MustCompile(`\(\?:((?:[A-Za-z0-9_/\-]|\\\.)+(?:\|(?:[A-Za-z0-9_/\-]|\\\.)+)+)\)`)

// expandLiteralGroups returns the concrete alternatives alt stands for, with
// every literal group replaced by each of its members in turn, so that
// `/etc/cron\.(?:d|daily)/` yields `/etc/cron\.d/` and `/etc/cron\.daily/`.
func expandLiteralGroups(alt string) []string {
	loc := literalGroupPattern.FindStringSubmatchIndex(alt)
	if loc == nil {
		return []string{alt}
	}
	var out []string
	for _, member := range strings.Split(alt[loc[2]:loc[3]], "|") {
		out = append(out, expandLiteralGroups(alt[:loc[0]]+member+alt[loc[1]:])...)
	}
	return out
}

// TestExpandLiteralGroups pins the expansion the parity test depends on, so a
// change to it cannot quietly shrink what is checked.
func TestExpandLiteralGroups(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`plain`, []string{`plain`}},
		{`/etc/cron\.(?:d|daily|hourly)/`, []string{`/etc/cron\.d/`, `/etc/cron\.daily/`, `/etc/cron\.hourly/`}},
		{`/Library/Launch(?:Daemons|Agents)/`, []string{`/Library/LaunchDaemons/`, `/Library/LaunchAgents/`}},
		{`(?:^|[\s/])(?:var/log|var/lib/pipelock)(?:/|$)`, []string{`(?:^|[\s/])var/log(?:/|$)`, `(?:^|[\s/])var/lib/pipelock(?:/|$)`}},
		{`(?:a|b)(?:c|d)`, []string{`ac`, `ad`, `bc`, `bd`}},
		{`x(?:id_[a-z]*|authorized)`, []string{`x(?:id_[a-z]*|authorized)`}},
	}
	for _, tc := range cases {
		if got := expandLiteralGroups(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("expandLiteralGroups(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The shipped patterns expand to every location the parity test must see.
	var all []string
	for _, alt := range splitPolicyAlternatives(t, persistencePathPattern) {
		all = append(all, expandLiteralGroups(alt)...)
	}
	for _, want := range []string{`/etc/cron\.daily/`, `/etc/cron\.monthly/`, `/Library/LaunchDaemons/`} {
		if !slices.Contains(all, want) {
			t.Errorf("persistence pattern did not expand to %q: %q", want, all)
		}
	}
}

// localProtectedExemptRuleLocations are alternatives of the shipped path
// patterns that the resolver's location lists deliberately do not carry, each
// with the reason. A location a rule gains must be listed in
// localProtectedHomePaths or localProtectedSystemPaths, or be added here.
var localProtectedExemptRuleLocations = map[string]string{}

// TestLocalProtectedPathsMatchRulePatterns keeps localProtectedHomePaths and
// localProtectedSystemPaths in step with the shipped credential, persistence,
// shell-profile and audit-log patterns in both directions: every alternative of
// those patterns, each member of a grouped alternation taken on its own, is
// covered by a listed location or exempted with a reason, and
// every listed location is named by at least one alternative.
func TestLocalProtectedPathsMatchRulePatterns(t *testing.T) {
	var alternatives []string
	for _, pattern := range []string{persistencePathPattern, shellProfilePathPattern, auditLogPathPattern, sensitiveFilePathPattern, credentialWritePathPattern} {
		for _, alt := range splitPolicyAlternatives(t, pattern) {
			alternatives = append(alternatives, expandLiteralGroups(alt)...)
		}
	}
	res := make(map[string]*regexp.Regexp, len(alternatives))
	for _, alt := range alternatives {
		res[alt] = regexp.MustCompile("(?i)" + alt)
	}
	// A listed location is named by an alternative when the location, a file
	// below it, or a key below it matches.
	probes := func(path string) []string {
		return []string{path, path + "/x", path + "/id_rsa"}
	}
	named := func(re *regexp.Regexp, path string) bool {
		for _, probe := range probes(path) {
			if re.MatchString(probe) {
				return true
			}
		}
		return false
	}
	var locations []string
	for _, rel := range localProtectedHomePaths {
		locations = append(locations, "/home/u/"+rel)
	}
	locations = append(locations, localProtectedSystemPaths...)

	// Rule to list.
	for _, alt := range alternatives {
		covered := false
		for _, location := range locations {
			if named(res[alt], location) {
				covered = true
			}
		}
		_, exempt := localProtectedExemptRuleLocations[alt]
		switch {
		case covered && exempt:
			t.Errorf("alternative %q is covered by the location lists and also exempted; drop the exemption", alt)
		case !covered && !exempt:
			t.Errorf("the shipped path patterns name %q but localProtectedHomePaths and localProtectedSystemPaths do not cover it; add the location or an exemption with a reason", alt)
		}
	}
	for alt, reason := range localProtectedExemptRuleLocations {
		if !slices.Contains(alternatives, alt) {
			t.Errorf("exemption %q no longer matches any alternative; remove it", alt)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("exemption %q has no reason", alt)
		}
	}
	// List to rule.
	for _, location := range locations {
		found := false
		for _, alt := range alternatives {
			if named(res[alt], location) {
				found = true
			}
		}
		if !found {
			t.Errorf("listed location %q is not named by any shipped path pattern; remove it or add the pattern", location)
		}
	}
	// The zsh startup files are home files the shell-profile rule names.
	shell := regexp.MustCompile("(?i)" + shellProfilePathPattern)
	for _, name := range localProtectedZshFiles {
		if !shell.MatchString("/home/u/" + name) {
			t.Errorf("zsh startup file %q is not named by the shell-profile pattern", name)
		}
		if !slices.Contains(localProtectedHomePaths, name) {
			t.Errorf("zsh startup file %q is missing from localProtectedHomePaths", name)
		}
	}
}

func setEntryInfo(t *testing.T, fn func(fs.DirEntry) (fs.FileInfo, error)) {
	t.Helper()
	old := entryInfo
	entryInfo = fn
	t.Cleanup(func() { entryInfo = old })
}

func multiValueVerdict(pc *Config, tool string, values []string) Verdict {
	args := make(map[string][]string, 1)
	args["paths"] = values
	raw, _ := json.Marshal(args)
	return pc.CheckToolCallWithArgs(tool, values, raw)
}

// TestLocalPathIdentity_HardLinkWalkErrorBranchesFailClosed drives each
// entry-metadata error branch of the walk: a regular file and a directory whose
// metadata cannot be read leave the answer unknown, so an unrelated file is
// refused; an entry that vanished since the listing is skipped.
func TestLocalPathIdentity_HardLinkWalkErrorBranchesFailClosed(t *testing.T) {
	newFixture := func(t *testing.T) (f localPathFixture, value string) {
		f = newLocalPathFixture(t)
		f.write(t, filepath.Join(f.ws, "a.txt"))
		hardLink(t, filepath.Join(f.ws, "a.txt"), filepath.Join(f.ws, "b.txt"))
		f.write(t, filepath.Join(f.home, ".ssh", "known_hosts"))
		f.write(t, filepath.Join(f.home, ".ssh", "sub", "inner"))
		return f, filepath.Join(f.ws, "b.txt")
	}
	matched := func(f localPathFixture, value string) bool {
		return slices.Contains(checkPath(f.policy(true), testReadTool, "path", value).Rules, testKeyReadRule)
	}
	failFor := func(name string, err error) func(fs.DirEntry) (fs.FileInfo, error) {
		return func(e fs.DirEntry) (fs.FileInfo, error) {
			if e.Name() == name {
				return nil, err
			}
			return e.Info()
		}
	}
	denied := &fs.PathError{Op: "lstat", Path: "x", Err: fs.ErrPermission}
	gone := &fs.PathError{Op: "lstat", Path: "x", Err: fs.ErrNotExist}

	f, value := newFixture(t)
	if matched(f, value) {
		t.Fatal("control: unrelated file matched with working metadata reads")
	}
	cases := []struct {
		name  string
		entry string
		err   error
		want  bool
	}{
		{"regular file metadata error", "known_hosts", denied, true},
		{"directory metadata error", "sub", denied, true},
		{"regular file vanished", "known_hosts", gone, false},
		{"directory vanished", "sub", gone, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEntryInfo(t, failFor(tc.entry, tc.err))
			if got := matched(f, value); got != tc.want {
				t.Fatalf("matched=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestLocalPathIdentity_HardLinkWalkOncePerCall proves the walk of a protected
// directory is shared by every value of one call, and that sharing does not
// lose a match among them.
func TestLocalPathIdentity_HardLinkWalkOncePerCall(t *testing.T) {
	f := newLocalPathFixture(t)
	f.write(t, filepath.Join(f.ws, "other"))
	key := filepath.Join(f.home, ".ssh", "id_ed25519")
	f.write(t, key)
	f.write(t, filepath.Join(f.home, ".ssh", "sub", "x"))
	const n = 200
	values := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		link := filepath.Join(f.ws, "link"+strconv.Itoa(i))
		hardLink(t, filepath.Join(f.ws, "other"), link)
		values = append(values, link)
	}
	pc := f.policy(true)

	reads := map[string]int{}
	old := hardLinkDirRead
	hardLinkDirRead = func(dir string) { reads[dir]++ }
	t.Cleanup(func() { hardLinkDirRead = old })

	if v := multiValueVerdict(pc, testReadTool, values); slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("control: unrelated links matched: %+v", v)
	}
	ssh := filepath.Join(f.home, ".ssh")
	for _, dir := range []string{ssh, filepath.Join(ssh, "sub")} {
		if reads[dir] != 1 {
			t.Fatalf("%s was read %d times for %d values, want once", dir, reads[dir], n)
		}
	}
	for dir, count := range reads {
		if strings.HasPrefix(dir, f.home) && count != 1 {
			t.Fatalf("%s read %d times, want once", dir, count)
		}
	}

	// A value that is a link to the key, among the unrelated ones, is found.
	late := filepath.Join(f.ws, "late")
	hardLink(t, key, late)
	clear(reads)
	if v := multiValueVerdict(pc, testReadTool, append(values, late)); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("the link to the key among %d values was not matched: %+v", n, v)
	}
	if reads[ssh] != 1 {
		t.Fatalf("%s read %d times, want once", ssh, reads[ssh])
	}

	// An unknown answer is cached too, and still refuses every value.
	setEntryInfo(t, func(e fs.DirEntry) (fs.FileInfo, error) {
		if e.Name() == "x" {
			return nil, fs.ErrPermission
		}
		return e.Info()
	})
	clear(reads)
	if v := multiValueVerdict(pc, testReadTool, values); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("an unknown walk must refuse the values: %+v", v)
	}
	if reads[ssh] != 1 || reads[filepath.Join(ssh, "sub")] != 1 {
		t.Fatalf("unknown walk repeated: %v", reads)
	}
}

// BenchmarkHardLinkManyValues compares one call carrying many multi-link path
// values with the cost of walking per value, as the earlier code did.
func BenchmarkHardLinkManyValues(b *testing.B) {
	root, err := filepath.EvalSymlinks(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	home := filepath.Join(root, "home")
	ws := filepath.Join(home, "ws")
	for _, d := range []string{ws, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			b.Fatal(err)
		}
	}
	for i := 0; i < 400; i++ {
		if err := os.WriteFile(filepath.Join(home, ".ssh", "f"+strconv.Itoa(i)), nil, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ws, "o"), nil, 0o600); err != nil {
		b.Fatal(err)
	}
	values := make([]string, 300)
	for i := range values {
		values[i] = filepath.Join(ws, "l"+strconv.Itoa(i))
		if err := os.Link(filepath.Join(ws, "o"), values[i]); err != nil {
			b.Fatal(err)
		}
	}
	l := newLocalPathIdentity([]string{home}, ws)
	b.Run("per call cache", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			l.expand(values)
		}
	})
	b.Run("walk per value", func(b *testing.B) {
		candidates := l.protectedCandidates()
		for i := 0; i < b.N; i++ {
			for _, v := range values {
				protectedAliases(v, candidates, nil)
			}
		}
	})
}
