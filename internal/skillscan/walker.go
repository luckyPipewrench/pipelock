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
	data, grew, err := readScanFile(clean)
	if err != nil {
		return skillInput{}, fmt.Errorf("read %s: %w", clean, err)
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
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Size() > maxScanFileBytes {
			s.oversize = append(s.oversize, filepath.Clean(path))
			continue
		}
		data, grew, err := readScanFile(filepath.Clean(path))
		if err != nil {
			return fmt.Errorf("read referenced file %s: %w", path, err)
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
	for _, match := range referencedPathPattern.FindAllStringSubmatch(content, -1) {
		if len(match) < 2 {
			continue
		}
		rel, ok := containedRelativePath(root, match[1])
		if ok {
			refs[rel] = struct{}{}
		}
	}
	return refs
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
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func readScanFile(path string) ([]byte, bool, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxScanFileBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxScanFileBytes {
		return nil, true, nil
	}
	return data, false, nil
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
