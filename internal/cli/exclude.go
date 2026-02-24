package cli

import (
	"path"
	"strings"
)

// toSlash normalizes a path to forward slashes regardless of platform.
// Unlike filepath.ToSlash (which is a no-op on Linux), this always converts
// backslashes so that Windows-style paths from projectscan work with
// forward-slash patterns like "vendor/".
func toSlash(s string) string {
	return strings.ReplaceAll(s, "\\", "/")
}

// shouldExclude reports whether file matches any of the exclude patterns.
// Patterns support filepath.Match globs (e.g., "*.generated.go") and
// directory prefixes ending in "/" (e.g., "vendor/"). A glob is matched
// against both the full path and the basename so "*.go" matches "vendor/foo.go".
//
// Both file and patterns are normalized to forward slashes before matching
// so that patterns work consistently across platforms.
func shouldExclude(file string, patterns []string) bool {
	file = toSlash(file)

	for _, p := range patterns {
		if p == "" {
			continue
		}
		p = toSlash(p)

		// Directory prefix: "vendor/" matches "vendor/foo/bar.go"
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(file, p) {
				return true
			}
			continue
		}
		// Exact match
		if file == p {
			return true
		}
		// Glob on full path (use path.Match for forward-slash paths)
		if matched, _ := path.Match(p, file); matched {
			return true
		}
		// Glob on basename (e.g., "*.generated.go" matches "pkg/foo.generated.go")
		if matched, _ := path.Match(p, path.Base(file)); matched {
			return true
		}
	}
	return false
}
