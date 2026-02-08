package gitprotect

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ValidateBranch checks if a branch name matches any allowed pattern.
// Patterns use filepath.Match glob syntax (e.g., "feature/*", "fix/*").
// Returns nil if the branch matches at least one pattern, or an error
// describing which patterns were checked.
func ValidateBranch(branch string, allowedPatterns []string) error {
	if len(allowedPatterns) == 0 {
		return nil // no restrictions
	}

	for _, pattern := range allowedPatterns {
		matched, err := filepath.Match(pattern, branch)
		if err != nil {
			continue // skip invalid patterns
		}
		if matched {
			return nil
		}
	}

	return fmt.Errorf(
		"branch %q does not match any allowed pattern: [%s]",
		branch,
		strings.Join(allowedPatterns, ", "),
	)
}
