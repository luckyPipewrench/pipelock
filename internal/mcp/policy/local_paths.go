// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"strings"
)

// Tool policy matches the path text a caller submits. A filesystem backend
// acts on the file that text resolves to, and the two differ whenever a link is
// involved:
//
//   - a submitted name is a symlink, or sits under a symlinked directory, that
//     resolves to a protected file;
//   - a protected name is itself a symlink to a file the caller may name
//     directly, as a dotfile manager arranges a home directory;
//   - a submitted name is a hard link to a protected file.
//
// When the process that performs the operation shares Pipelock's filesystem, as
// a local stdio MCP server or an agent hook does, the policy also matches the
// resolved path and the well-known protected location that shares the target's
// file identity. The resolved strings are added to the submitted ones, never
// substituted for them, so a path that cannot be resolved is matched exactly as
// before. Resolution happens at decision time: a link created or swapped between
// the decision and the operation is not seen. Kernel file-access controls (the
// sandbox workspace) remain the boundary for that.

const (
	// localPathMaxLen skips values longer than the platform path limit; no
	// filesystem call can name them.
	localPathMaxLen = 4096
	// localPathMaxHops bounds symlink following, matching the Linux kernel's
	// own limit on nested links (MAXSYMLINKS).
	localPathMaxHops = 40
)

// There is deliberately no per-call cap on how many values are resolved. A cap
// is a bypass: padding a call with that many real paths would leave the value
// that matters unresolved. The work is bounded by the size of the message.

// localProtectedHomePaths and localProtectedSystemPaths are the concrete
// locations named by the built-in protected path patterns (shell profiles,
// credentials, persistence directories, audit namespaces). A target that shares
// file identity with one of them, or lies under one of the directories, is also
// matched under the protected spelling. Keep this list in step with
// shellProfilePathPattern, sensitiveFilePathPattern, persistencePathPattern and
// auditLogPathPattern.
var (
	localProtectedHomePaths = []string{
		".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".bash_logout",
		".ssh", ".aws/credentials", ".netrc", ".env",
		".config/systemd/user", "Library/LaunchAgents",
	}
	// localProtectedZshFiles are the zsh startup files shellProfilePathPattern
	// names, looked up under ZDOTDIR when it relocates them.
	localProtectedZshFiles    = []string{".zshrc", ".zprofile", ".zshenv"}
	localProtectedSystemPaths = []string{
		"/etc/profile", "/etc/shadow", "/etc/crontab",
		"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
		"/var/spool/cron", "/etc/init.d", "/etc/systemd", "/lib/systemd", "/usr/lib/systemd",
		"/Library/LaunchDaemons", "/Library/LaunchAgents",
		"/var/log", "/var/lib/pipelock",
	}
)

// localPathIdentity resolves submitted path values against the local
// filesystem. The zero value is unusable; build one with newLocalPathIdentity.
type localPathIdentity struct {
	home string
	cwd  string
	// zdotdir is where zsh reads its startup files when ZDOTDIR is set.
	zdotdir string
}

// EnableLocalPathIdentity makes the policy also match what submitted paths
// resolve to on this host. Call it only where the process performing the
// operation shares Pipelock's filesystem view, before the Config is shared. It
// is a no-op on a nil Config.
func (pc *Config) EnableLocalPathIdentity() {
	if pc == nil {
		return
	}
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	pc.localPaths = newLocalPathIdentity(home, cwd)
	if zdotdir := os.Getenv("ZDOTDIR"); filepath.IsAbs(zdotdir) {
		pc.localPaths.zdotdir = filepath.Clean(zdotdir)
	}
}

func newLocalPathIdentity(home, cwd string) *localPathIdentity {
	return &localPathIdentity{home: filepath.Clean(home), cwd: filepath.Clean(cwd)}
}

// localProtectedCandidate is one protected location and its current file
// identity.
type localProtectedCandidate struct {
	path string
	info os.FileInfo
}

// expand returns values plus, for each value that names a local path, the
// resolved path and any protected spelling that shares its identity. It returns
// values unchanged when nothing resolves differently.
func (l *localPathIdentity) expand(values []string) []string {
	if l == nil || len(values) == 0 {
		return values
	}
	var extra []string
	var candidates []localProtectedCandidate
	candidatesLoaded := false
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		extra = append(extra, s)
	}
	for _, value := range values {
		abs, ok := l.absolute(value)
		if !ok {
			continue
		}
		resolved, ok := resolveLocalPath(abs)
		if !ok {
			continue
		}
		if resolved != abs {
			add(resolved)
		}
		if !candidatesLoaded {
			candidates = l.protectedCandidates()
			candidatesLoaded = true
		}
		for _, alias := range protectedAliases(resolved, candidates) {
			add(alias)
		}
	}
	if len(extra) == 0 {
		return values
	}
	out := make([]string, 0, len(values)+len(extra))
	out = append(out, values...)
	return append(out, extra...)
}

// absolute returns value as a clean absolute path when it is shaped like a
// filesystem path, or false for anything else (command text, URLs, content).
func (l *localPathIdentity) absolute(value string) (string, bool) {
	if value == "" || len(value) > localPathMaxLen || strings.ContainsAny(value, "\x00\n\r") ||
		strings.Contains(value, "://") {
		return "", false
	}
	switch {
	case value == "~" || strings.HasPrefix(value, "~/"):
		if l.home == "" || l.home == "." {
			return "", false
		}
		value = filepath.Join(l.home, strings.TrimPrefix(value, "~"))
	case filepath.IsAbs(value):
	default:
		if l.cwd == "" || l.cwd == "." {
			return "", false
		}
		// A bare word is far more often content than a file name. Treat it as a
		// path only when it names something that exists; a relative value with a
		// separator is treated as a path either way, so a new file under a linked
		// directory is still resolved.
		joined := filepath.Join(l.cwd, value)
		if !strings.ContainsRune(value, filepath.Separator) {
			if _, err := os.Lstat(joined); err != nil {
				return "", false
			}
		}
		value = joined
	}
	return filepath.Clean(value), true
}

// resolveLocalPath follows symlinks in path, including a dangling final link,
// and returns the location an operation on path would reach. A path that does
// not exist resolves through its parent directory, because a write creates it
// there. It returns false when no location can be established.
func resolveLocalPath(path string) (string, bool) {
	for hop := 0; hop < localPathMaxHops; hop++ {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			return resolved, true
		}
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return "", false
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(path), target)
			}
			path = filepath.Clean(target)
			continue
		}
		if err == nil || !os.IsNotExist(err) {
			return "", false
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return "", false
		}
		return filepath.Join(parent, filepath.Base(path)), true
	}
	return "", false
}

// protectedCandidates stats every protected location that exists now. Stat
// follows links, so a protected name that is itself a symlink carries the
// identity of the file it points to.
func (l *localPathIdentity) protectedCandidates() []localProtectedCandidate {
	paths := make([]string, 0, len(localProtectedHomePaths)+len(localProtectedSystemPaths))
	if l.home != "" && l.home != "." {
		for _, rel := range localProtectedHomePaths {
			paths = append(paths, filepath.Join(l.home, rel))
		}
	}
	if l.zdotdir != "" {
		for _, name := range localProtectedZshFiles {
			paths = append(paths, filepath.Join(l.zdotdir, name))
		}
	}
	paths = append(paths, localProtectedSystemPaths...)
	candidates := make([]localProtectedCandidate, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		candidates = append(candidates, localProtectedCandidate{path: path, info: info})
	}
	return candidates
}

// protectedAliases returns the protected spelling of resolved when resolved,
// or one of its ancestor directories, is the same file as a protected location.
func protectedAliases(resolved string, candidates []localProtectedCandidate) []string {
	if len(candidates) == 0 {
		return nil
	}
	var aliases []string
	current := resolved
	suffix := ""
	for {
		if info, err := os.Stat(current); err == nil {
			for _, candidate := range candidates {
				if os.SameFile(info, candidate.info) {
					aliases = append(aliases, candidate.path+suffix)
				}
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return aliases
		}
		suffix = string(filepath.Separator) + filepath.Base(current) + suffix
		current = parent
	}
}

// withPatchPrefixStripped adds the form of each git-style `a/` or `b/` patch
// target that an applier writes after stripping that component (`-p1`), so the
// resolver looks up the file the patch actually changes. Unprefixed targets
// pass through unchanged.
func withPatchPrefixStripped(targets []string) []string {
	out := targets
	for _, target := range targets {
		for _, prefix := range []string{"a/", "b/"} {
			if rest, ok := strings.CutPrefix(target, prefix); ok && rest != "" {
				if len(out) == len(targets) {
					out = append([]string(nil), targets...)
				}
				out = append(out, rest)
			}
		}
	}
	return out
}
