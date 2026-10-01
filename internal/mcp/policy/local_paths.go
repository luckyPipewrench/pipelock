// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
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
	// homes are the home directories whose protected locations are matched: the
	// one the environment names and the one the account database records.
	homes []string
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
	cwd, _ := os.Getwd()
	pc.localPaths = newLocalPathIdentity(CredentialHomes(nil), append([]string{cwd}, bases...)...)
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

func newLocalPathIdentity(homes []string, bases ...string) *localPathIdentity {
	l := &localPathIdentity{}
	for _, home := range homes {
		if filepath.IsAbs(home) {
			if home = filepath.Clean(home); !slices.Contains(l.homes, home) {
				l.homes = append(l.homes, home)
			}
		}
	}
	l.addBases(bases...)
	return l
}

// accountHomeDir returns the home directory the operating system records for
// the user this process runs as. It is a variable so tests can supply one.
var accountHomeDir = func() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// CredentialHomes returns every distinct absolute home directory whose
// protected locations must be guarded: the one named by the environment and the
// one the account database records for the current user. $HOME is set by
// whoever launched the process, so on its own it can point away from the real
// home. A value that is not absolute names no location and is ignored. None is
// returned when neither source yields a usable directory. account supplies the
// account database's answer; nil uses the operating system's.
func CredentialHomes(account func() (string, error)) []string {
	if account == nil {
		account = accountHomeDir
	}
	var homes []string
	add := func(home string) {
		if home == "" || !filepath.IsAbs(home) {
			return
		}
		home = filepath.Clean(home)
		if !slices.Contains(homes, home) {
			homes = append(homes, home)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(home)
	}
	if home, err := account(); err == nil {
		add(home)
	}
	return homes
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
	out, _ := l.expandNoted(values)
	return out
}

// expandNoted is expand plus the operator-facing notes for every protected
// directory whose hard-link walk was inconclusive, so a block caused by the
// fail-closed rule can say so instead of showing only the rule it matched.
func (l *localPathIdentity) expandNoted(values []string) ([]string, []string) {
	if l == nil || len(values) == 0 {
		return values, nil
	}
	var extra []string
	var candidates []localProtectedCandidate
	candidatesLoaded := false
	// One walk of each protected directory serves every value in this call.
	links := newHardLinkIndexes()
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
	loadCandidates := func() []localProtectedCandidate {
		if !candidatesLoaded {
			candidates = l.protectedCandidates()
			candidatesLoaded = true
		}
		return candidates
	}
	// A base that is itself a protected location, or lies under one, makes any
	// bare name a protected path, including one the call is about to create.
	var protectedBases map[string]bool
	baseIsProtected := func(base string) bool {
		if protectedBases == nil {
			protectedBases = make(map[string]bool, len(l.bases))
			for _, b := range l.bases {
				resolved, ok := resolveLocalPath(b)
				protectedBases[b] = ok && len(protectedAliases(resolved, loadCandidates(), links)) > 0
			}
		}
		return protectedBases[base]
	}
	for _, value := range values {
		for _, path := range l.paths(value, baseIsProtected) {
			for _, resolved := range resolveLocalPathViews(path) {
				add(resolved)
				for _, alias := range protectedAliases(resolved, loadCandidates(), links) {
					add(alias)
				}
			}
		}
	}
	if len(extra) == 0 {
		return values, links.notes
	}
	out := append([]string(nil), values...)
	return append(out, extra...), links.notes
}

// paths returns the absolute spellings value may name, or none when it is not
// shaped like a filesystem path (command text, URLs, multi-line content). The
// spellings are not cleaned: `..` after a symlinked directory means something
// different to the kernel than to a lexical cleaner, and both are resolved.
func (l *localPathIdentity) paths(value string, baseIsProtected func(string) bool) []string {
	if value == "" || len(value) > localPathMaxLen || strings.ContainsAny(value, "\x00\n\r") ||
		strings.Contains(value, "://") {
		return nil
	}
	switch {
	case value == "~" || strings.HasPrefix(value, "~/"):
		out := make([]string, 0, len(l.homes))
		for _, home := range l.homes {
			out = append(out, home+value[1:])
		}
		return out
	case filepath.IsAbs(value):
		return []string{value}
	}
	// A bare word is far more often content than a file name, so it counts only
	// where it names something that exists, or where its base is itself a
	// protected location and any name there is protected. A relative value with
	// a separator counts under every base, so a new file under a linked
	// directory is still resolved.
	bare := !strings.ContainsAny(value, "/"+string(filepath.Separator))
	var out []string
	for _, base := range l.bases {
		joined := base + string(filepath.Separator) + value
		if bare {
			if _, err := os.Lstat(joined); err != nil && !baseIsProtected(base) {
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
	current, rest := splitVolumeRoot(path)
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
			var targetRest []string
			current, targetRest = linkTargetStart(current, target)
			rest = append(targetRest, rest...)
			continue
		}
		if hasRealComponent(rest) && !info.IsDir() {
			return "", false
		}
		current = next
	}
	return current, true
}

// linkTargetStart returns the directory a symlink target is walked from and
// the target's components. An absolute target starts at its own root. A
// Windows target rooted at a separator but carrying no drive (`\Users\x`) is
// not absolute to filepath.IsAbs, yet names the root of the link's own drive,
// so it starts there. Any other target is relative to the link's directory.
func linkTargetStart(linkDir, target string) (string, []string) {
	target = filepath.FromSlash(target)
	sep := string(filepath.Separator)
	switch {
	case filepath.IsAbs(target):
		return splitVolumeRoot(target)
	case strings.HasPrefix(target, sep):
		return filepath.VolumeName(linkDir) + sep, strings.Split(target, sep)
	default:
		return linkDir, strings.Split(target, sep)
	}
}

// splitVolumeRoot returns the root of an absolute path, including a Windows
// drive letter or UNC share, and the components that follow it. Forward
// slashes are accepted as separators, as Windows itself accepts them.
func splitVolumeRoot(path string) (root string, components []string) {
	path = filepath.FromSlash(path)
	volume := filepath.VolumeName(path)
	sep := string(filepath.Separator)
	return volume + sep, strings.Split(path[len(volume):], sep)
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
	paths := make([]string, 0, len(l.homes)*len(localProtectedHomePaths)+len(localProtectedZshFiles)+len(localProtectedSystemPaths))
	for _, home := range l.homes {
		for _, rel := range localProtectedHomePaths {
			paths = append(paths, filepath.Join(home, rel))
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
// link to a protected file. links caches the walk of each protected directory
// for the caller's lifetime; nil walks afresh.
func protectedAliases(resolved string, candidates []localProtectedCandidate, links *hardLinkIndexes) []string {
	if len(candidates) == 0 {
		return nil
	}
	if links == nil {
		links = newHardLinkIndexes()
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
		if candidate.info == nil {
			continue
		}
		if !statDone {
			info, _ = os.Stat(resolved)
			statDone = true
		}
		if info == nil {
			continue
		}
		if candidate.info.IsDir() {
			// A hard link to a file anywhere inside a protected directory tree
			// is the same file under another name. Only a regular file with
			// another link can be one, so everything else skips the scan.
			if info.Mode().IsRegular() && mayHaveOtherLinks(info) {
				aliases = append(aliases, links.aliases(candidate.path, resolved, info, candidate.info)...)
			}
			continue
		}
		if os.SameFile(info, candidate.info) {
			aliases = append(aliases, candidate.path)
		}
	}
	return aliases
}

// localPathMaxDirEntries bounds how many entries are examined across the whole
// walk of one protected directory. A tree with more entries than this is
// treated as holding the file, never as not holding it. It is a variable so
// tests can reach the bound without creating thousands of files.
var localPathMaxDirEntries = 8192

// differentDevice is a variable so tests can place a fixture on another
// filesystem, which they cannot create without root.
var differentDevice = onDifferentDevice

// entryInfo reads an entry's metadata. It is a variable so tests can make it
// fail.
var entryInfo = func(entry fs.DirEntry) (fs.FileInfo, error) { return entry.Info() }

// hardLinkDirRead is called once for each directory the walk opens. It is a
// variable so tests can count reads.
var hardLinkDirRead = func(string) {}

// fileKey identifies a file by device and inode where the platform exposes
// them.
type fileKey struct{ dev, ino uint64 }

type indexedFile struct {
	info os.FileInfo
	path string
}

// hardLinkIndex is the result of one walk of a protected directory tree: every
// regular file in it, or the fact that the answer is unknown.
type hardLinkIndex struct {
	known     bool
	remaining int
	byKey     map[fileKey][]string
	// unkeyed holds files whose identity the platform does not expose as a key;
	// all holds every file, for a target that has no key either.
	unkeyed []indexedFile
	all     []indexedFile
	// cause says why the answer is unknown; it is empty when known.
	cause string
}

// hardLinkIndexes caches one hardLinkIndex per protected directory and device
// for the lifetime of a policy decision, so each directory is walked at most
// once however many path values the call carries.
type hardLinkIndexes struct {
	byDir map[hardLinkIndexKey]*hardLinkIndex
	// notes holds one operator-facing line per protected directory whose walk
	// was inconclusive and made a file match as a possible hard link.
	notes []string
}

// Causes of an inconclusive hard-link walk.
const (
	hardLinkCauseUnlistable = "could not be listed"
	hardLinkCauseBound      = "holds more entries than the walk examines"
)

type hardLinkIndexKey struct {
	dir string
	dev uint64
}

func newHardLinkIndexes() *hardLinkIndexes {
	return &hardLinkIndexes{byDir: make(map[hardLinkIndexKey]*hardLinkIndex)}
}

// aliases returns the protected spelling of resolved when it is the same file
// (device and inode) as an entry anywhere under dir, or when that cannot be
// established.
//
// A hard link cannot cross filesystems, so a file on another device than dir
// is not held by it and the directory is not read. Otherwise the tree under dir
// is walked once, without following symlinks and skipping subtrees on another
// device, examining at most localPathMaxDirEntries entries in total. It fails
// closed: a directory on the same device that cannot be read, or more entries
// than the bound, yields a protected spelling for file, because the answer is
// unknown. Who owns the file or the directory does not change that: a user can
// own a directory they cannot list, and root can link a user's file into one.
// A directory that does not exist holds no link.
func (h *hardLinkIndexes) aliases(dir, resolved string, info, dirInfo os.FileInfo) []string {
	if dirInfo != nil && differentDevice(info, dirInfo) {
		return nil
	}
	dir = filepath.Clean(dir)
	key := hardLinkIndexKey{dir: dir}
	if id, ok := fileID(dirInfo); ok {
		key.dev = id.dev
	}
	idx, ok := h.byDir[key]
	if !ok {
		idx = &hardLinkIndex{remaining: localPathMaxDirEntries, byKey: make(map[fileKey][]string)}
		idx.known = idx.walk(dir, dirInfo)
		h.byDir[key] = idx
	}
	if !idx.known {
		h.noteInconclusive(dir, idx.cause)
		return unknownHardLinkAliases(dir, resolved)
	}
	return idx.lookup(info)
}

// noteInconclusive records, once per directory, that a file could not be ruled
// out as a hard link into dir.
func (h *hardLinkIndexes) noteInconclusive(dir, cause string) {
	note := fmt.Sprintf("a file with more than one link could not be ruled out as a hard link into protected directory %s because that directory %s; "+
		"check that Pipelock can list it, or that the file has only one link (stat -c %%h FILE)", dir, cause)
	if slices.Contains(h.notes, note) {
		return
	}
	h.notes = append(h.notes, note)
}

func (x *hardLinkIndex) lookup(target os.FileInfo) []string {
	if id, ok := fileID(target); ok {
		out := slices.Clone(x.byKey[id])
		for _, f := range x.unkeyed {
			if os.SameFile(target, f.info) {
				out = append(out, f.path)
			}
		}
		return out
	}
	var out []string
	for _, f := range x.all {
		if os.SameFile(target, f.info) {
			out = append(out, f.path)
		}
	}
	return out
}

func (x *hardLinkIndex) record(path string, info os.FileInfo) {
	f := indexedFile{info: info, path: path}
	x.all = append(x.all, f)
	if id, ok := fileID(info); ok {
		x.byKey[id] = append(x.byKey[id], path)
		return
	}
	x.unkeyed = append(x.unkeyed, f)
}

// walk indexes dir and the directories below it. It returns false when the
// answer is unknown.
func (x *hardLinkIndex) walk(dir string, dirInfo os.FileInfo) bool {
	hardLinkDirRead(dir)
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return true
		}
		x.cause = hardLinkCauseUnlistable
		return false
	}
	entries, err := f.ReadDir(x.remaining + 1)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		x.cause = hardLinkCauseUnlistable
		return false
	}
	if len(entries) > x.remaining {
		x.cause = hardLinkCauseBound
		return false
	}
	x.remaining -= len(entries)
	for _, entry := range entries {
		switch {
		case entry.Type().IsRegular():
			info, err := entryInfo(entry)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue // removed since the listing
				}
				x.cause = hardLinkCauseUnlistable
				return false
			}
			x.record(filepath.Join(dir, entry.Name()), info)
		case entry.IsDir():
			info, err := entryInfo(entry)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				x.cause = hardLinkCauseUnlistable
				return false
			}
			if dirInfo != nil && differentDevice(dirInfo, info) {
				continue
			}
			if !x.walk(filepath.Join(dir, entry.Name()), dirInfo) {
				return false
			}
		}
	}
	return true
}

// unknownHardLinkAliases is the fail-closed spelling for a file that may be a
// hard link into dir: the file's own name under dir, plus, for an SSH
// directory, a private key name and the authorized-keys name, since only
// those names are protected there.
func unknownHardLinkAliases(dir, resolved string) []string {
	aliases := []string{filepath.Join(dir, filepath.Base(resolved))}
	if filepath.Base(dir) == ".ssh" {
		// A rule may name either protected kind on its own, so the unknown
		// file stands for both.
		aliases = append(aliases, filepath.Join(dir, "id_rsa"), filepath.Join(dir, "authorized_keys"))
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
