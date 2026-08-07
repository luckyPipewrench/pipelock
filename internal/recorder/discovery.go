// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// EvidenceLocation identifies an evidence-file directory below an
// operator-supplied evidence root. ID is empty for the legacy flat layout and
// otherwise is a slash-separated path relative to the root.
type EvidenceLocation struct {
	Root string
	ID   string
	Dir  string
}

// DiscoverEvidenceLocations finds evidence-file directories under root without
// following symlinks. Each location holds its immediate evidence files. Any
// unreadable path or symlink fails closed so missing evidence cannot look
// absent.
func DiscoverEvidenceLocations(root string) ([]EvidenceLocation, error) {
	return discoverEvidenceLocations(root, nil)
}

// discoverEvidenceLocations anchors traversal to an opened root. The optional
// hook lets tests replace the pathname after the handle is open.
func discoverEvidenceLocations(root string, afterRootOpen func()) ([]EvidenceLocation, error) {
	cleanRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("resolve evidence root: %w", err)
	}
	initialInfo, err := validateEvidenceRootComponents(cleanRoot)
	if err != nil {
		return nil, err
	}
	if !initialInfo.IsDir() {
		return nil, fmt.Errorf("evidence root %q is not a directory", root)
	}
	rootHandle, err := os.OpenRoot(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("open evidence root: %w", err)
	}
	defer func() { _ = rootHandle.Close() }()
	if afterRootOpen != nil {
		afterRootOpen()
	}
	info, err := validateEvidenceRootComponents(cleanRoot)
	if err != nil {
		return nil, err
	}
	rootedInfo, err := rootHandle.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("stat opened evidence root: %w", err)
	}
	if !os.SameFile(initialInfo, rootedInfo) || !os.SameFile(info, rootedInfo) {
		return nil, fmt.Errorf("evidence root changed while opening: %q", root)
	}

	locations := make([]EvidenceLocation, 0)
	rootFS := rootHandle.FS()
	err = fs.WalkDir(rootFS, ".", func(relPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("read evidence path %q: %w", relPath, walkErr)
		}
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("stat evidence path %q: %w", relPath, infoErr)
		}
		if entryInfo.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refuse symlink in evidence root: %q", relPath)
		}
		if !entryInfo.IsDir() {
			return nil
		}
		hasEvidence, readErr := directoryHasEvidenceFiles(rootFS, relPath)
		if readErr != nil {
			return fmt.Errorf("read evidence directory %q: %w", relPath, readErr)
		}
		if !hasEvidence {
			return nil
		}
		id := ""
		dir := cleanRoot
		if relPath != "." {
			id = relPath
			dir = filepath.Join(cleanRoot, filepath.FromSlash(relPath))
		}
		locations = append(locations, EvidenceLocation{Root: cleanRoot, ID: id, Dir: dir})
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

// validateEvidenceRootComponents checks from the filesystem root down so a
// symlinked ancestor is rejected before any descendant under its target is
// inspected.
func validateEvidenceRootComponents(cleanRoot string) (fs.FileInfo, error) {
	components := make([]string, 0)
	for component := cleanRoot; ; component = filepath.Dir(component) {
		components = append(components, component)
		if parent := filepath.Dir(component); parent == component {
			break
		}
	}

	var rootInfo fs.FileInfo
	for i := len(components) - 1; i >= 0; i-- {
		component := components[i]
		info, err := os.Lstat(component)
		if err != nil {
			return nil, fmt.Errorf("stat evidence root component %q: %w", component, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("refuse symlink in evidence root path: %q", component)
		}
		if component == cleanRoot {
			rootInfo = info
		}
	}
	return rootInfo, nil
}

func directoryHasEvidenceFiles(rootFS fs.FS, dir string) (bool, error) {
	entries, err := fs.ReadDir(rootFS, dir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			return false, infoErr
		}
		if entryInfo.Mode()&fs.ModeSymlink != 0 {
			return false, fmt.Errorf("refuse symlink in evidence directory: %q", path.Join(dir, entry.Name()))
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
		cleanRoot, absErr := filepath.Abs(filepath.Clean(root))
		if absErr != nil {
			return EvidenceLocation{}, fmt.Errorf("resolve evidence root: %w", absErr)
		}
		return EvidenceLocation{Root: cleanRoot, Dir: cleanRoot}, nil
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
