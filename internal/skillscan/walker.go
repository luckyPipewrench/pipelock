// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package skillscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const (
	skillFileName       = "SKILL.md"
	defaultLockFileName = "pipelock-skill-lock.yaml"

	// maxScanFileBytes bounds how large a single skill or referenced file may
	// be before it is skipped (with a reported finding) instead of read into
	// memory and line-scanned. Skill files are documentation-sized; a file
	// past this limit is pathological and reading it unbounded is a DoS vector.
	maxScanFileBytes = 2 << 20 // 2 MiB
)

var referencedPathPattern = regexp.MustCompile("(?:^|[[:space:]\"'`])((?:\\.{1,2}/)?[A-Za-z0-9_./-]+\\.(?:sh|bash|zsh|py|js|ts|mjs|go|rb|pl|yaml|yml|json|toml))")

// referencedRelativePattern catches a referenced file that carries no
// recognized extension, such as a `./bootstrap` launcher. It requires an
// explicit ./ or ../ marker so ordinary prose naming a bare word cannot
// promote that word to a referenced file; the containment and existence
// checks in loadReferencedFiles then bound it further.
var referencedRelativePattern = regexp.MustCompile("(?:^|[[:space:]\"'`])(\\.{1,2}/[A-Za-z0-9_.][A-Za-z0-9_./-]*)")

// referenceTrailingPunctuation is trimmed from a matched relative path so a
// reference at the end of a sentence resolves to the file rather than to the
// filename plus the sentence's punctuation.
const referenceTrailingPunctuation = ".,;:!?)]}'\""

type fileContent struct {
	path    string
	relPath string
	lines   []string
}

type skillInput struct {
	id        string
	path      string
	root      string
	content   []byte
	info      os.FileInfo
	files     []fileContent
	refFiles  []ReferencedFile
	scanFiles []string
	oversize  []string

	// uninspectable records paths that exist but were not read, so refusing or
	// failing to inspect content cannot present as a clean skill. Oversize
	// files already report this way; see FindingOversize.
	uninspectable []uninspectableRef
}

func DefaultLockFile() string {
	return defaultLockFileName
}

func DefaultPaths() []string {
	home, homeErr := os.UserHomeDir()
	var candidates []string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "claude", "skills"))
	}
	if homeErr == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".claude", "skills"),
			filepath.Join(home, ".claude", "agents"),
			filepath.Join(home, ".codex", "agents"),
		)
	}
	return existingPaths(candidates)
}

func existingPaths(paths []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, p := range paths {
		clean := filepath.Clean(p)
		if _, ok := seen[clean]; ok {
			continue
		}
		if _, err := os.Lstat(clean); err == nil {
			out = append(out, clean)
			seen[clean] = struct{}{}
		}
	}
	return out
}

func discoverSkills(paths []string) ([]skillInput, error) {
	if len(paths) == 0 {
		paths = DefaultPaths()
	}
	var skillPaths []string
	seen := map[string]struct{}{}
	add := func(path string) {
		clean := filepath.Clean(path)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		skillPaths = append(skillPaths, clean)
	}
	for _, root := range paths {
		clean := filepath.Clean(root)
		info, err := os.Lstat(clean)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", clean, err)
		}
		if !info.IsDir() {
			add(clean)
			continue
		}
		if _, err := os.Lstat(filepath.Join(clean, skillFileName)); err == nil {
			add(filepath.Join(clean, skillFileName))
			continue
		}
		if isCodexAgentsDir(clean) {
			if err := addMarkdownFiles(clean, add); err != nil {
				return nil, err
			}
			continue
		}
		if err := filepath.WalkDir(clean, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("walk %s: %w", path, err)
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() == skillFileName || (isCodexAgentsDir(filepath.Dir(path)) && strings.EqualFold(filepath.Ext(path), ".md")) {
				add(path)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	sort.Strings(skillPaths)

	inputs := make([]skillInput, 0, len(skillPaths))
	usedIDs := map[string]int{}
	for _, path := range skillPaths {
		input, err := loadSkill(path)
		if err != nil {
			return nil, err
		}
		baseID := input.id
		if n := usedIDs[baseID]; n > 0 {
			input.id = fmt.Sprintf("%s-%d", baseID, n+1)
		}
		usedIDs[baseID]++
		inputs = append(inputs, input)
	}
	return inputs, nil
}

func addMarkdownFiles(root string, add func(string)) error {
	entries, err := os.ReadDir(filepath.Clean(root))
	if err != nil {
		return fmt.Errorf("read dir %s: %w", root, err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
			continue
		}
		add(filepath.Join(root, entry.Name()))
	}
	return nil
}

func isCodexAgentsDir(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return strings.HasSuffix(clean, "/.codex/agents") || clean == ".codex/agents"
}

func loadSkill(path string) (skillInput, error) {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		return skillInput{}, fmt.Errorf("stat %s: %w", clean, err)
	}
	if !info.Mode().IsRegular() {
		return skillInput{}, fmt.Errorf("%s is not a regular file", clean)
	}
	root := filepath.Dir(clean)
	id := strings.TrimSuffix(filepath.Base(clean), filepath.Ext(clean))
	if filepath.Base(clean) == skillFileName {
		id = filepath.Base(root)
	}
	input := skillInput{id: id, path: clean, root: root, info: info}
	// An oversize skill file is skipped (not read or line-scanned) and reported;
	// referenced dirs (scripts/bin/hooks) are still discovered since they do not
	// depend on the skill body.
	if info.Size() > maxScanFileBytes {
		input.oversize = append(input.oversize, clean)
		if err := input.loadReferencedFiles(); err != nil {
			return skillInput{}, err
		}
		return input, nil
	}
	data, grew, refusedSkill, err := readScanFile(clean, info)
	if err != nil {
		return skillInput{}, fmt.Errorf("read %s: %w", clean, err)
	}
	if refusedSkill != "" {
		// The skill file itself IS the inventory. Refusing to read it is not a
		// partial result to step over, so it stops this skill rather than
		// yielding an entry that reads as an inspected skill with no content.
		return skillInput{}, fmt.Errorf("read %s: %s", clean, refusedSkill)
	}
	if grew {
		input.oversize = append(input.oversize, clean)
		if err := input.loadReferencedFiles(); err != nil {
			return skillInput{}, err
		}
		return input, nil
	}
	input.content = data
	input.scanFiles = []string{clean}
	input.files = []fileContent{{
		path:    clean,
		relPath: filepath.Base(clean),
		lines:   splitLines(string(data)),
	}}
	if err := input.loadReferencedFiles(); err != nil {
		return skillInput{}, err
	}
	return input, nil
}

// markUninspectable records a referenced dependency the scanner refused to read.
// Both refusals route here - a path that is not a regular file, and a path whose
// identity changed under an open descriptor - so a dependency we decline to
// inspect never presents as clean, which is how oversize files already behave.
func (s *skillInput) markUninspectable(path, reason string) {
	s.uninspectable = append(s.uninspectable, uninspectableRef{
		path:   filepath.Clean(path),
		reason: reason,
	})
}

func (s *skillInput) loadReferencedFiles() error {
	refs := referencedFilesFromSkill(s.root, string(s.content))
	for rel := range referencedDirs(s.root) {
		refs[rel] = struct{}{}
	}
	var rels []string
	for rel := range refs {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		path := filepath.Join(s.root, filepath.FromSlash(rel))
		info, err := os.Lstat(filepath.Clean(path))
		if err != nil {
			continue
		}
		if info.IsDir() {
			// A referenced directory is not an uninspected dependency: the
			// scripts, bin and hooks directories are walked deliberately by
			// referencedDirs, and prose pointing at a documentation directory
			// must not gate a scan.
			continue
		}
		// Every way of refusing to inspect a dependency converges on one
		// disposition below. The path exists but is not a regular file, or the
		// bytes opened were not the file that was checked. A dependency we
		// refuse to read must not present as clean, which is how oversize files
		// already behave. A failed Lstat above is deliberately NOT recorded: a
		// named path that does not exist is prose or a stale doc reference, not
		// an uninspected dependency, and reporting it would flag ordinary
		// writing.
		refused := ""
		if !info.Mode().IsRegular() {
			refused = "not a regular file; a symlink is not followed because its target can leave the skill directory"
		}
		var (
			data []byte
			grew bool
		)
		if refused == "" {
			if info.Size() > maxScanFileBytes {
				s.oversize = append(s.oversize, filepath.Clean(path))
				continue
			}
			data, grew, refused, err = readScanFile(filepath.Clean(path), info)
			if err != nil {
				return fmt.Errorf("read referenced file %s: %w", path, err)
			}
		}
		if refused != "" {
			s.markUninspectable(path, refused)
			continue
		}
		if grew {
			s.oversize = append(s.oversize, filepath.Clean(path))
			continue
		}
		s.refFiles = append(s.refFiles, ReferencedFile{
			Path:   rel,
			SHA256: sha256Hex(data),
			Mode:   modeString(info.Mode()),
		})
		s.scanFiles = append(s.scanFiles, filepath.Clean(path))
		s.files = append(s.files, fileContent{
			path:    filepath.Clean(path),
			relPath: rel,
			lines:   splitLines(string(data)),
		})
	}
	return nil
}

func referencedFilesFromSkill(root, content string) map[string]struct{} {
	refs := map[string]struct{}{}
	for _, pattern := range []*regexp.Regexp{referencedPathPattern, referencedRelativePattern} {
		// Both patterns carry exactly one capture group, so every match has the
		// full text at 0 and the path at 1.
		for _, match := range pattern.FindAllStringSubmatch(content, -1) {
			for _, candidate := range referenceCandidates(root, match[1]) {
				refs[candidate] = struct{}{}
			}
		}
	}
	return refs
}

// referenceCandidates resolves one matched reference to the relative path worth
// scanning, or nothing. The exact match is tried FIRST, because a trailing dot
// and a leading dot are both legal in a filename: "./bootstrap." and
// "./.bootstrap" name real files, and trimming or rejecting them dropped those
// files from the scanned set, the referenced set and the lock. Punctuation
// trimming is only a fallback for a reference that ends a sentence, and applies
// solely when the exact candidate does not resolve inside the skill.
func referenceCandidates(root, match string) []string {
	if rel, ok := resolvedInsideSkill(root, match); ok {
		return []string{rel}
	}
	if trimmed := strings.TrimRight(match, referenceTrailingPunctuation); trimmed != match {
		if rel, ok := resolvedInsideSkill(root, trimmed); ok {
			return []string{rel}
		}
	}
	// Neither form exists on disk. Keep the exact match so a broken reference is
	// recorded as named, rather than silently rewritten to another path.
	if rel, ok := containedRelativePath(root, match); ok {
		return []string{rel}
	}
	return nil
}

// resolvedInsideSkill returns the contained relative path when a candidate names
// something that exists within the skill directory. It uses Lstat, so a symlink
// counts as existing without being followed here; whether it may be READ is
// decided later.
func resolvedInsideSkill(root, candidate string) (string, bool) {
	rel, ok := containedRelativePath(root, candidate)
	if !ok {
		return "", false
	}
	if _, err := os.Lstat(filepath.Clean(filepath.Join(root, filepath.FromSlash(rel)))); err != nil {
		return "", false
	}
	return rel, true
}

func referencedDirs(root string) map[string]struct{} {
	refs := map[string]struct{}{}
	for _, dirName := range []string{"scripts", "bin", "hooks"} {
		dir := filepath.Join(root, dirName)
		info, err := os.Lstat(filepath.Clean(dir))
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, ok := containedRelativePath(root, path)
			if ok {
				refs[rel] = struct{}{}
			}
			return nil
		})
	}
	return refs
}

func containedRelativePath(root, candidate string) (string, bool) {
	absRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", false
	}
	path := filepath.Clean(candidate)
	if !filepath.IsAbs(path) {
		path = filepath.Join(absRoot, path)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(absRoot, absPath)
	// Reject traversal on a path COMPONENT boundary, not on a string prefix. A
	// filename may legitimately begin with two dots, so "..bootstrap" is a
	// contained file while ".." and "../x" are escapes. The prefix form treated
	// the filename as traversal and dropped it from the scan and the lock.
	if err != nil || rel == "." || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	if !parentChainContained(absRoot, absPath) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// parentChainContained re-checks containment after resolving symlinks in the
// candidate PARENT chain.
//
// The comparison above is lexical: it treats a path as text and never asks
// whether a component of it is a symlink. A skill referencing "payload/data.sh"
// where "payload" links to a directory outside the skill passes that check and
// is read, so containment is satisfied by a path that does not stay inside the
// skill.
//
// Only the parent chain is resolved, deliberately. Resolving the FINAL
// component too would reject a symlinked reference here, which reads as
// stricter but is worse: that case is currently recorded as an uninspectable
// dependency, and rejecting it at containment would delete the finding instead
// of reporting it.
//
// An unresolvable root or parent keeps the lexical answer. That is not a hole:
// a parent that cannot be resolved cannot be opened either, so no bytes are
// read, and the read itself is now bound to the validated inode.
func parentChainContained(absRoot, absPath string) bool {
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return true
	}
	realParent, err := filepath.EvalSymlinks(filepath.Dir(absPath))
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(realRoot, realParent)
	if err != nil {
		return false
	}
	// rel == "." is contained here: the parent IS the skill root.
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// readScanFile reads path, refusing to return bytes from anything other than
// the regular file described by want.
//
// Validating with Lstat and then reading with os.Open are two operations on a
// PATH, and os.Open follows symlinks. A path replaced with a symlink in the
// window between them is read through, so the scanner would inspect content
// outside the skill directory while its own contract says a symlink is never
// followed. Re-stat the OPEN DESCRIPTOR instead: that names the inode actually
// being read and cannot be re-pointed underneath us.
func readScanFile(path string, want os.FileInfo) (data []byte, grew bool, refused string, err error) {
	// securefile owns the platform matrix for a nonblocking open and is already
	// exercised against a real FIFO. Reuse it rather than adding a second matrix
	// here that drifts from that one.
	//
	// Its final-component behavior is NOT uniform, so the descriptor check below
	// is what carries this guarantee rather than the open. On Unix the open also
	// carries O_NOFOLLOW, which narrows the window further: a path swapped to a
	// symlink fails to open rather than opening the wrong file. On Windows a
	// final symlink inside the root is followed, and the identity comparison is
	// then the only thing standing between us and reading its target. Do not
	// remove that comparison on the grounds that the open is no-follow.
	f, err := securefile.OpenRegularNonblocking(filepath.Clean(path))
	if err != nil {
		// Every open failure is a refusal rather than a broken scan. Lstat has
		// already said this is a regular file, so failing to open it means it
		// changed underneath us or cannot be reached: unreadable permissions, a
		// path swapped to a symlink that O_NOFOLLOW then rejects, a device or
		// FIFO, the file being removed, or a platform that provides no secure
		// open at all. Each one is this single dependency cannot be inspected,
		// and aborting on any of them hands anyone who can write a skill
		// directory a way to stop the scan of every OTHER skill.
		//
		// Refusing does not make an unopenable file quiet. Each one becomes a
		// high-severity uninspectable finding naming the path and the reason,
		// so a platform that can open nothing fails loudly per file rather than
		// silently, and no unread path presents as clean.
		return nil, false, "could not be opened for inspection, so its content is unknown", nil
	}
	defer func() { _ = f.Close() }()
	got, statErr := f.Stat()
	if statErr != nil {
		return nil, false, "", statErr
	}
	if !got.Mode().IsRegular() || !os.SameFile(want, got) {
		return nil, false, "changed identity between validation and read; the bytes opened were not the regular file that was checked", nil
	}
	body, readErr := io.ReadAll(io.LimitReader(f, maxScanFileBytes+1))
	if readErr != nil {
		return nil, false, "", readErr
	}
	if len(body) > maxScanFileBytes {
		return nil, true, "", nil
	}
	return body, false, "", nil
}

func splitLines(content string) []string {
	// Normalize CRLF and bare-CR line endings to LF first. CommonMark treats
	// \r, \n, and \r\n all as line endings; splitting on \n alone would leave a
	// bare-CR file as a single line and defeat fence detection.
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	lines := strings.Split(content, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func modeString(mode os.FileMode) string {
	return fmt.Sprintf("0o%03o", mode.Perm())
}
