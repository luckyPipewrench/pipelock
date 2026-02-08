package gitprotect

import (
	"strings"
	"testing"
)

func TestValidateBranch_NoRestrictions(t *testing.T) {
	if err := ValidateBranch("anything-goes", nil); err != nil {
		t.Errorf("expected nil error with no patterns, got %v", err)
	}
	if err := ValidateBranch("anything-goes", []string{}); err != nil {
		t.Errorf("expected nil error with empty patterns, got %v", err)
	}
}

func TestValidateBranch_ExactMatch(t *testing.T) {
	err := ValidateBranch("main", []string{"main", "master"})
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidateBranch_GlobMatch(t *testing.T) {
	tests := []struct {
		branch   string
		patterns []string
		wantErr  bool
	}{
		{"feature/auth", []string{"feature/*"}, false},
		{"fix/bug-123", []string{"fix/*"}, false},
		{"main", []string{"feature/*", "fix/*", "main"}, false},
		{"hotfix/urgent", []string{"feature/*", "fix/*", "main"}, true},
		// filepath.Match doesn't support multi-level globs
		{"feature/api/auth", []string{"feature/*"}, true},
	}

	for _, tc := range tests {
		err := ValidateBranch(tc.branch, tc.patterns)
		if tc.wantErr && err == nil {
			t.Errorf("ValidateBranch(%q, %v) expected error, got nil", tc.branch, tc.patterns)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("ValidateBranch(%q, %v) unexpected error: %v", tc.branch, tc.patterns, err)
		}
	}
}

func TestValidateBranch_ErrorMessage(t *testing.T) {
	err := ValidateBranch("rogue", []string{"feature/*", "main"})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "rogue") {
		t.Errorf("error should mention branch name, got %q", msg)
	}
	if !strings.Contains(msg, "feature/*") {
		t.Errorf("error should mention patterns, got %q", msg)
	}
}

func TestValidateBranch_InvalidPatternSkipped(t *testing.T) {
	// filepath.Match returns error for patterns with unmatched '['
	err := ValidateBranch("main", []string{"[invalid", "main"})
	if err != nil {
		t.Errorf("expected nil (invalid pattern skipped, main matches), got %v", err)
	}
}
