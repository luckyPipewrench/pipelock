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
//   - a protected name is itself a symlink, possibly not yet pointing at an
//     existing file, to a location the caller may name directly, as a dotfile
//     manager arranges a home directory;
//   - a submitted name is a hard link to a protected file;
//   - a relative name is resolved by the writer against its own directory, not
//     against Pipelock's.
//
// When the process that performs the operation shares Pipelock's filesystem, as
// a local stdio MCP server or an agent hook does, the policy also matches the
// resolved path and the protected spelling of any well-known protected location
// it reaches. The resolved strings are added to the submitted ones, never
// substituted for them, so a path that cannot be resolved is matched exactly as
// before. Resolution happens at decision time: a link created or swapped between
// the decision and the operation is not seen. Kernel file-access controls (the
// sandbox workspace) remain the boundary for that. Shell command text is not
// resolved; it is matched as text.

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
// credentials, persistence directories, audit namespaces). A target that
// reaches one of them, or lies under one of the directories, is also matched
// under the protected spelling. Keep this list in step with
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
// filesystem. Build one with newLocalPathIdentity.
type localPathIdentity struct {
	home string
	// zdotdir is where zsh reads its startup files when ZDOTDIR is set.
	zdotdir string
	// bases are the directories a relative value may be resolved against:
	// Pipelock's own working directory and each directory the writer is known
	// to resolve relative names in.
	bases []string
}

// EnableLocalPathIdentity makes the policy also match what submitted paths
// resolve to on this host. Relative values are resolved against the working
// directory and each of bases. Call it only where the process performing the
// operation shares Pipelock's filesystem view, before the Config is shared. It
// is a no-op on a nil Config.
func (pc *Config) EnableLocalPathIdentity(bases ...string) {
	if pc == nil {
		return
	}
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	pc.localPaths = newLocalPathIdentity(home, append([]string{cwd}, bases...)...)
	if zdotdir := os.Getenv("ZDOTDIR"); filepath.IsAbs(zdotdir) {
		pc.localPaths.zdotdir = filepath.Clean(zdotdir)
	}
}

// AddLocalPathBases adds directories a relative value may be resolved against.
// It is a no-op unless local path identity is enabled. Call it before the
// Config is shared.
func (pc *Config) AddLocalPathBases(bases ...string) {
	if pc == nil || pc.localPaths == nil {
		return
	}
	pc.localPaths.addBases(bases...)
}

func newLocalPathIdentity(home string, bases ...string) *localPathIdentity {
	l := &localPathIdentity{}
	if filepath.IsAbs(home) {
		l.home = filepath.Clean(home)
	}
	l.addBases(bases...)
	return l
}

func (l *localPathIdentity) addBases(bases ...string) {
	for _, base := range bases {
		if !filepath.IsAbs(base) {
			continue
		}
		base = filepath.Clean(base)
		duplicate := false
		for _, existing := range l.bases {
			if existing == base {
				duplicate = true
				break
			}
		}
		if !duplicate {
			l.bases = append(l.bases, base)
		}
	}
}

// localProtectedCandidate is one protected location, the location it resolves
// to (which may not exist yet), and its identity when it does exist.
type localProtectedCandidate struct {
	path   string
	target string
	info   os.FileInfo
}

// expand returns values plus, for each value that names a local path, the
// resolved paths and the protected spelling of any protected location they
// reach. It returns values unchanged when nothing new is found.
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
		for _, path := range l.paths(value) {
			for _, resolved := range resolveLocalPathViews(path) {
				add(resolved)
				if !candidatesLoaded {
					candidates = l.protectedCandidates()
					candidatesLoaded = true
				}
				for _, alias := range protectedAliases(resolved, candidates) {
					add(alias)
				}
			}
		}
	}
	if len(extra) == 0 {
		return values
	}
	out := make([]string, 0, len(values)+len(extra))
	out = append(out, values...)
	return append(out, extra...)
}

// paths returns the absolute spellings value may name, or none when it is not
// shaped like a filesystem path (command text, URLs, multi-line content). The
// spellings are not cleaned: `..` after a symlinked directory means something
// different to the kernel than to a lexical cleaner, and both are resolved.
func (l *localPathIdentity) paths(value string) []string {
	if value == "" || len(value) > localPathMaxLen || strings.ContainsAny(value, "\x00\n\r") ||
		strings.Contains(value, "://") {
		return nil
	}
	switch {
	case value == "~" || strings.HasPrefix(value, "~/"):
		if l.home == "" {
			return nil
		}
		return []string{l.home + value[1:]}
	case filepath.IsAbs(value):
		return []string{value}
	}
	// A bare word is far more often content than a file name, so it counts only
	// where it names something that exists. A relative value with a separator
	// counts under every base, so a new file under a linked directory is still
	// resolved.
	bare := !strings.ContainsRune(value, filepath.Separator)
	var out []string
	for _, base := range l.bases {
		joined := base + string(filepath.Separator) + value
		if bare {
			if _, err := os.Lstat(joined); err != nil {
				continue
			}
		}
		out = append(out, joined)
	}
	return out
}

// resolveLocalPathViews resolves path the way the kernel does, following each
// link before any `..` after it, and the way a writer that cleans the path text
// first does. Both are returned when they differ.
func resolveLocalPathViews(path string) []string {
	var out []string
	if kernel, ok := resolveLocalPath(path); ok {
		out = append(out, kernel)
	}
	if lexical, ok := resolveLocalPath(filepath.Clean(path)); ok && (len(out) == 0 || lexical != out[0]) {
		out = append(out, lexical)
	}
	return out
}

// resolveLocalPath resolves an absolute path one component at a time, the way
// the kernel does for open: each symlink is followed where it appears, so a
// later `..` climbs from the link's target rather than from the link's text.
// A dangling final link is followed to its target. A final component that does
// not exist resolves in its (resolved) parent directory, because a write creates
// it there. It returns false when no location can be established: a missing or
// non-directory intermediate component, a link loop, or a relative path.
//
// filepath.EvalSymlinks is not used because it cleans `..` lexically before
// following links, which is exactly the disagreement this function exists to
// resolve.
func resolveLocalPath(path string) (string, bool) {
	if !filepath.IsAbs(path) {
		return "", false
	}
	sep := string(filepath.Separator)
	current := sep
	rest := strings.Split(path, sep)
	hops := 0
	for len(rest) > 0 {
		component := rest[0]
		rest = rest[1:]
		switch component {
		case "", ".":
			continue
		case "..":
			// current is already free of links, so its lexical parent is the
			// kernel's parent.
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, component)
		info, err := os.Lstat(next)
		if err != nil {
			if os.IsNotExist(err) && !hasRealComponent(rest) {
				return next, true
			}
			return "", false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			hops++
			if hops > localPathMaxHops {
				return "", false
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", false
			}
			if filepath.IsAbs(target) {
				current = sep
			}
			rest = append(strings.Split(target, sep), rest...)
			continue
		}
		if hasRealComponent(rest) && !info.IsDir() {
			return "", false
		}
		current = next
	}
	return current, true
}

// hasRealComponent reports whether components still name something to walk
// into, ignoring empty and `.` components left by repeated or trailing
// separators.
func hasRealComponent(components []string) bool {
	for _, component := range components {
		if component != "" && component != "." {
			return true
		}
	}
	return false
}

// protectedCandidates resolves every protected location. A protected name that
// is a symlink records where it points even when that target does not exist
// yet, since a write there creates the file the protected name exposes.
func (l *localPathIdentity) protectedCandidates() []localProtectedCandidate {
	paths := make([]string, 0, len(localProtectedHomePaths)+len(localProtectedZshFiles)+len(localProtectedSystemPaths))
	if l.home != "" {
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
		candidate := localProtectedCandidate{path: path}
		if info, err := os.Stat(path); err == nil {
			candidate.info = info
		}
		if _, err := os.Lstat(path); err == nil {
			if target, ok := resolveLocalPath(path); ok {
				candidate.target = target
			}
		}
		if candidate.info == nil && candidate.target == "" {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

// protectedAliases returns the protected spelling of resolved when it is, or
// lies under, the location a protected name resolves to, or when it is a hard
// link to a protected file.
func protectedAliases(resolved string, candidates []localProtectedCandidate) []string {
	if len(candidates) == 0 {
		return nil
	}
	var aliases []string
	var info os.FileInfo
	statDone := false
	for _, candidate := range candidates {
		if candidate.target != "" {
			if resolved == candidate.target {
				aliases = append(aliases, candidate.path)
				continue
			}
			if rest, ok := strings.CutPrefix(resolved, candidate.target+string(filepath.Separator)); ok {
				aliases = append(aliases, candidate.path+string(filepath.Separator)+rest)
				continue
			}
		}
		if candidate.info == nil || candidate.info.IsDir() {
			continue
		}
		if !statDone {
			info, _ = os.Stat(resolved)
			statDone = true
		}
		if info != nil && os.SameFile(info, candidate.info) {
			aliases = append(aliases, candidate.path)
		}
	}
	return aliases
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
