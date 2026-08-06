// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EvidenceRun is one independently chained evidence-file directory below an
// operator-supplied evidence root. ID is empty for the legacy flat layout and
// otherwise is a slash-separated path relative to the root.
type EvidenceRun struct {
	ID  string
	Dir string
}

// DiscoverEvidenceRuns finds every evidence-file directory under root without
// following symlinks. A directory that contains evidence files is a run
// boundary: descendants are not merged into its chain. Any unreadable path or
// symlink fails closed so missing evidence cannot look absent.
func DiscoverEvidenceRuns(root string) ([]EvidenceRun, error) {
	cleanRoot := filepath.Clean(root)
	info, err := os.Stat(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("stat evidence root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("evidence root %q is not a directory", root)
	}

	runs := make([]EvidenceRun, 0)
	err = filepath.WalkDir(cleanRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("read evidence path %q: %w", path, walkErr)
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refuse symlink in evidence root: %q", path)
		}
		if !entry.IsDir() {
			return nil
		}
		hasEvidence, readErr := directoryHasEvidenceFiles(path)
		if readErr != nil {
			return fmt.Errorf("read evidence directory %q: %w", path, readErr)
		}
		if !hasEvidence {
			return nil
		}
		rel, relErr := filepath.Rel(cleanRoot, path)
		if relErr != nil {
			return fmt.Errorf("resolve evidence run %q: %w", path, relErr)
		}
		id := ""
		if rel != "." {
			id = filepath.ToSlash(rel)
		}
		runs = append(runs, EvidenceRun{ID: id, Dir: path})
		// A legacy root can coexist with migrated runs during rollout. Keep
		// walking below that root, but never merge a nested run with a child.
		if path == cleanRoot {
			return nil
		}
		return filepath.SkipDir
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].ID < runs[j].ID })
	return runs, nil
}

func directoryHasEvidenceFiles(dir string) (bool, error) {
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Type()&fs.ModeSymlink != 0 {
			return false, fmt.Errorf("refuse symlink in evidence directory: %q", filepath.Join(dir, entry.Name()))
		}
		if entry.IsDir() {
			continue
		}
		if _, _, ok := ParseEvidenceFilename(entry.Name()); ok {
			return true, nil
		}
		if isEvidenceRawSidecar(entry.Name()) {
			return true, nil
		}
	}
	return false, nil
}

func isEvidenceRawSidecar(name string) bool {
	if !strings.HasSuffix(name, ".raw.enc") {
		return false
	}
	base := strings.TrimSuffix(name, ".raw.enc") + ".jsonl"
	_, _, ok := ParseEvidenceFilename(base)
	return ok
}

// ResolveEvidenceRun returns the one run a single-chain reader may consume.
// An empty runID preserves legacy behavior when exactly one run exists. It
// refuses an ambiguous root rather than joining independent chains.
func ResolveEvidenceRun(root, runID string) (EvidenceRun, error) {
	runs, err := DiscoverEvidenceRuns(root)
	if err != nil {
		return EvidenceRun{}, err
	}
	if runID != "" {
		cleanID, cleanErr := cleanEvidenceRunID(runID)
		if cleanErr != nil {
			return EvidenceRun{}, cleanErr
		}
		for _, run := range runs {
			if run.ID == cleanID {
				return run, nil
			}
		}
		return EvidenceRun{}, fmt.Errorf("evidence run %q not found", runID)
	}
	if len(runs) == 0 {
		return EvidenceRun{Dir: filepath.Clean(root)}, nil
	}
	if len(runs) == 1 {
		return runs[0], nil
	}
	ids := make([]string, 0, len(runs))
	for _, run := range runs {
		if run.ID == "" {
			ids = append(ids, ".")
			continue
		}
		ids = append(ids, run.ID)
	}
	return EvidenceRun{}, fmt.Errorf("multiple evidence runs found (%s); select one run", strings.Join(ids, ", "))
}

func cleanEvidenceRunID(runID string) (string, error) {
	if filepath.IsAbs(runID) {
		return "", errors.New("evidence run must be relative to the evidence root")
	}
	clean := filepath.Clean(runID)
	if clean == "." || clean == "" || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("evidence run must name a descendant directory")
	}
	return filepath.ToSlash(clean), nil
}
