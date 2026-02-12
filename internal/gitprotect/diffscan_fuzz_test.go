package gitprotect

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func FuzzParseDiff(f *testing.F) {
	// Minimal valid diff
	f.Add("diff --git a/file.go b/file.go\n--- a/file.go\n+++ b/file.go\n@@ -1,3 +1,4 @@\n context\n+added line\n context\n")

	// Multiple files
	f.Add("diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+new\ndiff --git a/b.go b/b.go\n--- a/b.go\n+++ b/b.go\n@@ -1 +1,2 @@\n+also new\n")

	// Large line numbers
	f.Add("+++ b/file.go\n@@ -999999,1 +999999,2 @@\n+secret here\n")

	// Malformed hunk header
	f.Add("+++ b/file.go\n@@ -1 +-5 @@\n+secret\n")

	// No file header (orphan lines)
	f.Add("@@ -1 +1,2 @@\n+orphan line\n")

	// Binary diff marker
	f.Add("diff --git a/img.png b/img.png\nBinary files differ\n")

	// Path traversal in filename
	f.Add("+++ b/../../../etc/passwd\n@@ -0,0 +1 @@\n+root:x:0:0\n")

	// Empty
	f.Add("")

	// Only removal lines
	f.Add("+++ b/file.go\n@@ -1,3 +1 @@\n-removed1\n-removed2\n context\n")

	// Integer overflow attempt in hunk
	f.Add("+++ b/file.go\n@@ -0,0 +99999999999999999999 @@\n+overflow\n")

	// Windows line endings
	f.Add("+++ b/file.go\r\n@@ -1 +1,2 @@\r\n+added\r\n")

	// Null byte in filename
	f.Add("+++ b/file\x00.go\n@@ -0,0 +1 @@\n+content\n")

	f.Fuzz(func(t *testing.T, diffText string) {
		result := parseDiff(diffText)

		// All line numbers must be non-negative
		for file, lines := range result {
			if file == "" {
				t.Error("empty file name in parse result")
			}
			for _, al := range lines {
				if al.lineNum < 0 {
					t.Errorf("negative line number %d in file %q", al.lineNum, file)
				}
			}
		}
	})
}

func FuzzScanDiff(f *testing.F) {
	patterns := CompileDLPPatterns(config.Defaults().DLP.Patterns)

	// Diff with secret
	f.Add("+++ b/config.go\n@@ -0,0 +1 @@\n+apiKey := \"AKIA" + "IOSFODNN7EXAMPLE\"\n") //nolint:goconst // fuzz seed

	// Clean diff
	f.Add("+++ b/safe.go\n@@ -0,0 +1 @@\n+fmt.Println(\"hello\")\n")

	// Empty
	f.Add("")

	// No added lines
	f.Add("+++ b/file.go\n@@ -1,2 +1 @@\n-removed\n context\n")

	f.Fuzz(func(t *testing.T, diffText string) {
		findings, _ := ScanDiff(diffText, patterns)

		for _, finding := range findings {
			if finding.File == "" {
				t.Error("finding with empty file")
			}
			if finding.Pattern == "" {
				t.Error("finding with empty pattern")
			}
			if finding.Severity == "" {
				t.Error("finding with empty severity")
			}
		}
	})
}
