package integrity

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
)

// ViolationType describes what integrity violation was found.
type ViolationType string

// Violation types reported by Check.
const (
	ViolationModified ViolationType = "modified"
	ViolationAdded    ViolationType = "added"
	ViolationRemoved  ViolationType = "removed"
)

// Violation represents a single file integrity violation.
type Violation struct {
	Path     string        `json:"path"`
	Type     ViolationType `json:"type"`
	Expected string        `json:"expected,omitempty"`
	Actual   string        `json:"actual,omitempty"`
}

// alwaysExcluded are basenames that are always skipped during directory walks.
var alwaysExcluded = []string{".git", DefaultManifestFile}

// Generate walks a directory tree and produces a new manifest.
func Generate(dir string, excludes []string) (*Manifest, error) {
	if err := validateExcludes(excludes); err != nil {
		return nil, err
	}

	now := time.Now().UTC().Truncate(time.Second)
	m := &Manifest{
		Version:  ManifestVersion,
		Created:  now,
		Updated:  now,
		Files:    make(map[string]FileEntry),
		Excludes: excludes,
	}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)

		if relPath == "." {
			return nil
		}

		// Skip symlinks entirely — don't follow them.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		if d.IsDir() {
			if isExcluded(relPath, excludes) {
				return fs.SkipDir
			}
			return nil
		}

		if isExcluded(relPath, excludes) {
			return nil
		}

		entry, err := HashFile(path)
		if err != nil {
			return fmt.Errorf("hashing %s: %w", relPath, err)
		}

		m.Files[relPath] = entry
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	return m, nil
}

// Check compares the current state of a directory against a stored manifest.
// It returns any violations found (modified, added, or removed files).
func Check(dir string, manifest *Manifest) ([]Violation, error) {
	current, err := Generate(dir, manifest.Excludes)
	if err != nil {
		return nil, err
	}

	var violations []Violation

	// Check for modified and removed files.
	for path, expected := range manifest.Files {
		actual, exists := current.Files[path]
		if !exists {
			violations = append(violations, Violation{
				Path:     path,
				Type:     ViolationRemoved,
				Expected: expected.SHA256,
			})
			continue
		}

		if actual.SHA256 != expected.SHA256 {
			violations = append(violations, Violation{
				Path:     path,
				Type:     ViolationModified,
				Expected: expected.SHA256,
				Actual:   actual.SHA256,
			})
		}
	}

	// Check for added files (in current but not in manifest).
	for path, actual := range current.Files {
		if _, exists := manifest.Files[path]; !exists {
			violations = append(violations, Violation{
				Path:   path,
				Type:   ViolationAdded,
				Actual: actual.SHA256,
			})
		}
	}

	return violations, nil
}

// isExcluded checks if a relative path (file or directory) should be skipped.
func isExcluded(relPath string, excludes []string) bool {
	base := filepath.Base(relPath)

	// Always-excluded entries (matched against basename).
	for _, name := range alwaysExcluded {
		if base == name {
			return true
		}
	}

	for _, pattern := range excludes {
		if matchExclude(pattern, relPath) {
			return true
		}
	}

	return false
}

// matchExclude checks a single exclude pattern against a relative path.
// Supports:
//   - Simple globs: "*.log" matches against the basename
//   - Path globs: "dir/*.txt" matches against the full relative path
//   - Recursive: "dir/**" matches everything under dir
//   - Recursive prefix: "**/name" matches name at any depth
func matchExclude(pattern, relPath string) bool {
	// Handle "**" recursive patterns.
	if strings.Contains(pattern, "**") {
		return matchDoublestar(pattern, relPath)
	}

	// If pattern contains a slash, match against full relative path.
	if strings.Contains(pattern, "/") {
		matched, _ := filepath.Match(pattern, relPath)
		return matched
	}

	// Simple pattern: match against basename.
	matched, _ := filepath.Match(pattern, filepath.Base(relPath))
	return matched
}

// validateExcludes checks that all exclude patterns are valid globs.
func validateExcludes(excludes []string) error {
	for _, pattern := range excludes {
		// Strip ** segments — filepath.Match doesn't handle them,
		// but the remaining glob portions must be valid.
		clean := pattern
		clean = strings.ReplaceAll(clean, "**/", "")
		clean = strings.ReplaceAll(clean, "/**", "")
		clean = strings.ReplaceAll(clean, "**", "")
		if clean == "" {
			continue
		}
		if _, err := filepath.Match(clean, "test"); err != nil {
			return fmt.Errorf("invalid exclude pattern %q: %w", pattern, err)
		}
	}
	return nil
}

// matchDoublestar handles "**" glob patterns.
func matchDoublestar(pattern, relPath string) bool {
	parts := strings.SplitN(pattern, "**", 2)
	if len(parts) != 2 {
		return false
	}

	prefix := parts[0]
	suffix := strings.TrimPrefix(parts[1], "/")

	// Check prefix match.
	if prefix != "" {
		prefix = strings.TrimSuffix(prefix, "/")
		if !strings.HasPrefix(relPath, prefix+"/") && relPath != prefix {
			return false
		}
	}

	// "dir/**" with no suffix matches everything under dir.
	if suffix == "" {
		return true
	}

	// "**/pattern": check if any path segment or tail matches suffix.
	remaining := relPath
	if prefix != "" {
		remaining = strings.TrimPrefix(relPath, prefix+"/")
	}

	segments := strings.Split(remaining, "/")
	for i := range segments {
		subpath := strings.Join(segments[i:], "/")
		if matched, _ := filepath.Match(suffix, subpath); matched {
			return true
		}
		if matched, _ := filepath.Match(suffix, segments[i]); matched {
			return true
		}
	}

	return false
}
