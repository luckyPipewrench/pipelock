package gitprotect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRedTeam_GitDLPCaseSensitivity(t *testing.T) {
	// Attack: Uppercase secrets bypass git diff scanning because
	// CompileDLPPatterns doesn't add (?i) prefix like scanner.New() does.

	// Build a fake Anthropic key pattern at runtime (avoid gitleaks)
	secretLower := "sk-ant-api03-" + strings.Repeat("a", 20) //nolint:goconst // test value
	secretUpper := "SK-ANT-API03-" + strings.Repeat("A", 20) //nolint:goconst // test value

	patterns := config.Defaults().DLP.Patterns
	compiled := CompileDLPPatterns(patterns)

	// Lowercase should be caught
	foundLower := false
	for _, p := range compiled {
		if p.Re.MatchString(secretLower) {
			foundLower = true
			break
		}
	}
	if !foundLower {
		t.Fatal("lowercase secret should be caught by DLP")
	}

	// Uppercase should ALSO be caught, but currently isn't
	foundUpper := false
	for _, p := range compiled {
		if p.Re.MatchString(secretUpper) {
			foundUpper = true
			break
		}
	}
	if !foundUpper {
		t.Error("GAP: uppercase secret bypasses git DLP scanning (missing (?i) prefix)")
	}
}

func TestRedTeam_ScanDiffCaseSensitivity(t *testing.T) {
	// Build secret at runtime
	secretUpper := "SK-ANT-API03-" + strings.Repeat("A", 20) //nolint:goconst // test value

	diff := fmt.Sprintf(`diff --git a/test.txt b/test.txt
--- a/test.txt
+++ b/test.txt
@@ -1 +1,2 @@
 existing line
+api_key = %s
`, secretUpper)

	patterns := config.Defaults().DLP.Patterns
	compiled := CompileDLPPatterns(patterns)

	findings, err := ScanDiff(diff, compiled)
	if err != nil {
		t.Fatalf("ScanDiff error: %v", err)
	}

	if len(findings) == 0 {
		t.Error("GAP: uppercase secret in git diff not detected (case-sensitive DLP)")
	}
}
