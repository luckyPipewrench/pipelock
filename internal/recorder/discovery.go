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

// EvidenceLocation identifies an evidence-file directory below an
// operator-supplied evidence root. ID is empty for the legacy flat layout and
// otherwise is a slash-separated path relative to the root.
type EvidenceLocation struct {
	ID  string
	Dir string
}

// DiscoverEvidenceLocations finds evidence-file directories under root without
// following symlinks. Each location holds its immediate evidence files. Any
// unreadable path or symlink fails closed so missing evidence cannot look
// absent.
func DiscoverEvidenceLocations(root string) ([]EvidenceLocation, error) {
	cleanRoot := filepath.Clean(root)
	info, err := os.Lstat(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("stat evidence root: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("refuse symlink as evidence root: %q", root)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("evidence root %q is not a directory", root)
	}

	locations := make([]EvidenceLocation, 0)
	err = filepath.WalkDir(cleanRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("read evidence path %q: %w", path, walkErr)
		}
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("stat evidence path %q: %w", path, infoErr)
		}
		if entryInfo.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refuse symlink in evidence root: %q", path)
		}
		if !entryInfo.IsDir() {
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
			return fmt.Errorf("resolve evidence location %q: %w", path, relErr)
		}
		id := ""
		if rel != "." {
			id = filepath.ToSlash(rel)
		}
		locations = append(locations, EvidenceLocation{ID: id, Dir: path})
		// A directory containing evidence is a location, not a chain boundary.
		// Descendants can hold independent evidence files and must be discovered
		// so a reader never mistakes a partial traversal for complete evidence.
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(locations, func(i, j int) bool { return locations[i].ID < locations[j].ID })
	return locations, nil
}

func directoryHasEvidenceFiles(dir string) (bool, error) {
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			return false, infoErr
		}
		if entryInfo.Mode()&fs.ModeSymlink != 0 {
			return false, fmt.Errorf("refuse symlink in evidence directory: %q", filepath.Join(dir, entry.Name()))
		}
		if entryInfo.IsDir() {
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

// ResolveEvidenceLocation returns the evidence-file location a reader may
// consume. An empty locationID preserves legacy behavior when exactly one
// location exists. It refuses an ambiguous root rather than silently choosing
// a location.
func ResolveEvidenceLocation(root, locationID string) (EvidenceLocation, error) {
	locations, err := DiscoverEvidenceLocations(root)
	if err != nil {
		return EvidenceLocation{}, err
	}
	if locationID != "" {
		cleanID, cleanErr := cleanEvidenceLocationID(locationID)
		if cleanErr != nil {
			return EvidenceLocation{}, cleanErr
		}
		for _, location := range locations {
			if location.ID == cleanID {
				return location, nil
			}
		}
		return EvidenceLocation{}, fmt.Errorf("evidence location %q not found", locationID)
	}
	if len(locations) == 0 {
		return EvidenceLocation{Dir: filepath.Clean(root)}, nil
	}
	if len(locations) == 1 {
		return locations[0], nil
	}
	ids := make([]string, 0, len(locations))
	for _, location := range locations {
		if location.ID == "" {
			ids = append(ids, ".")
			continue
		}
		ids = append(ids, location.ID)
	}
	return EvidenceLocation{}, fmt.Errorf("multiple evidence locations found (%s); select one location", strings.Join(ids, ", "))
}

func cleanEvidenceLocationID(locationID string) (string, error) {
	if filepath.IsAbs(locationID) {
		return "", errors.New("evidence location must be relative to the evidence root")
	}
	if locationID == "." {
		return "", nil
	}
	clean := filepath.Clean(locationID)
	if clean == "." || clean == "" || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("evidence location must name a descendant directory")
	}
	return filepath.ToSlash(clean), nil
}
