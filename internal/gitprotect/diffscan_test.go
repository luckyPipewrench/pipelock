package gitprotect

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestParseDiff_SingleFileAdded(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
index abc1234..def5678 100644
--- a/main.go
+++ b/main.go
@@ -1,3 +1,5 @@
 package main

+import "fmt"
+
 func main() {
`
	result := parseDiff(diff)
	if len(result) != 1 {
		t.Fatalf("expected 1 file, got %d", len(result))
	}
	lines, ok := result["main.go"]
	if !ok {
		t.Fatal("expected main.go in result")
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 added lines, got %d", len(lines))
	}
	if lines[0].content != `import "fmt"` {
		t.Errorf("expected import line, got %q", lines[0].content)
	}
	if lines[0].lineNum != 3 {
		t.Errorf("expected line 3, got %d", lines[0].lineNum)
	}
}

func TestParseDiff_MultipleFiles(t *testing.T) {
	diff := `diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -1,2 +1,3 @@
 package a
+var x = 1

diff --git a/b.go b/b.go
--- a/b.go
+++ b/b.go
@@ -1,2 +1,3 @@
 package b
+var y = 2

`
	result := parseDiff(diff)
	if len(result) != 2 {
		t.Fatalf("expected 2 files, got %d", len(result))
	}
	if len(result["a.go"]) == 0 {
		t.Fatal("expected at least 1 added line in a.go")
	}
	if result["a.go"][0].content != "var x = 1" {
		t.Errorf("a.go content mismatch: %q", result["a.go"][0].content)
	}
	if len(result["b.go"]) == 0 {
		t.Fatal("expected at least 1 added line in b.go")
	}
	if result["b.go"][0].content != "var y = 2" {
		t.Errorf("b.go content mismatch: %q", result["b.go"][0].content)
	}
}

func TestParseDiff_HunkLineNumbers(t *testing.T) {
	diff := `diff --git a/x.go b/x.go
--- a/x.go
+++ b/x.go
@@ -10,3 +20,4 @@
 context line
+added at 21
+added at 22
 another context
`
	result := parseDiff(diff)
	lines := result["x.go"]
	if len(lines) != 2 {
		t.Fatalf("expected 2 added lines, got %d", len(lines))
	}
	if lines[0].lineNum != 21 {
		t.Errorf("expected line 21, got %d", lines[0].lineNum)
	}
	if lines[1].lineNum != 22 {
		t.Errorf("expected line 22, got %d", lines[1].lineNum)
	}
}

func TestParseDiff_RemovedLinesSkipped(t *testing.T) {
	diff := `diff --git a/x.go b/x.go
--- a/x.go
+++ b/x.go
@@ -1,4 +1,3 @@
 keep
-removed
+added
 end
`
	result := parseDiff(diff)
	lines := result["x.go"]
	if len(lines) != 1 {
		t.Fatalf("expected 1 added line, got %d", len(lines))
	}
	if lines[0].content != "added" {
		t.Errorf("expected 'added', got %q", lines[0].content)
	}
	// removed lines don't increment new-file counter, so "added" is at line 2
	if lines[0].lineNum != 2 {
		t.Errorf("expected line 2, got %d", lines[0].lineNum)
	}
}

func TestParseDiff_EmptyDiff(t *testing.T) {
	result := parseDiff("")
	if len(result) != 0 {
		t.Fatalf("expected 0 files, got %d", len(result))
	}
}

func TestParseDiff_NoAddedLines(t *testing.T) {
	diff := `diff --git a/x.go b/x.go
--- a/x.go
+++ b/x.go
@@ -1,3 +1,2 @@
 keep
-removed
 end
`
	result := parseDiff(diff)
	if len(result["x.go"]) != 0 {
		t.Fatalf("expected 0 added lines, got %d", len(result["x.go"]))
	}
}

func TestParseHunkNewStart(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"@@ -1,3 +1,5 @@", 1},
		{"@@ -10,5 +20,8 @@", 20},
		{"@@ -0,0 +1,100 @@", 1},
		{"@@ -5 +7 @@", 7},
		{"@@ invalid", 1}, // fallback
		{"no plus sign", 1},
	}

	for _, tc := range tests {
		got := parseHunkNewStart(tc.input)
		if got != tc.expected {
			t.Errorf("parseHunkNewStart(%q) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}

func testPatterns() []CompiledDLPPattern {
	return CompileDLPPatterns([]config.DLPPattern{
		{Name: "AWS Key", Regex: `AKIA[0-9A-Z]{16}`, Severity: "critical"},
		{Name: "GitHub Token", Regex: `gh[ps]_[A-Za-z0-9_]{36,}`, Severity: "critical"},
	})
}

// fakeKey builds a test credential at runtime to avoid gitleaks/gosec false positives.
func fakeKey(suffix string) string {
	return "AK" + "IA" + "IOSFODNN7" + suffix
}

func makeDiffWithSecret(file, line string) string {
	return fmt.Sprintf(`diff --git a/%s b/%s
--- a/%s
+++ b/%s
@@ -1,2 +1,3 @@
 package x
+%s

`, file, file, file, file, line)
}

func TestScanDiff_FindsSecret(t *testing.T) {
	key := fakeKey("EXAMPLE")
	diff := makeDiffWithSecret("config.go", `var key = "`+key+`"`)
	findings, _ := ScanDiff(diff, testPatterns())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.File != "config.go" {
		t.Errorf("expected file config.go, got %q", f.File)
	}
	if f.Line != 2 {
		t.Errorf("expected line 2, got %d", f.Line)
	}
	if f.Pattern != "AWS Key" {
		t.Errorf("expected pattern 'AWS Key', got %q", f.Pattern)
	}
	if f.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", f.Severity)
	}
	// Verify secret is redacted — content should NOT contain the original key
	if f.Content == `var key = "`+key+`"` {
		t.Error("content should be redacted but contains original secret")
	}
}

func TestScanDiff_NoFindings(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,2 +1,3 @@
 package main
+import "fmt"

`
	findings, _ := ScanDiff(diff, testPatterns())
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanDiff_EmptyDiff(t *testing.T) {
	findings, _ := ScanDiff("", testPatterns())
	if findings != nil {
		t.Fatalf("expected nil findings, got %d", len(findings))
	}
}

func TestScanDiff_EmptyPatterns(t *testing.T) {
	key := fakeKey("EXAMPLE")
	diff := makeDiffWithSecret("x.go", `var key = "`+key+`"`)
	findings, _ := ScanDiff(diff, nil)
	if findings != nil {
		t.Fatalf("expected nil findings, got %d", len(findings))
	}
}

func TestScanDiff_MultipleFiles_DeterministicOrder(t *testing.T) {
	keyZ := fakeKey("EXAMPZZ")
	keyA := fakeKey("EXAMPAA")
	diff := fmt.Sprintf(`diff --git a/z.go b/z.go
--- a/z.go
+++ b/z.go
@@ -1,2 +1,3 @@
 package z
+var z = "%s"

diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -1,2 +1,3 @@
 package a
+var a = "%s"

`, keyZ, keyA)
	findings, _ := ScanDiff(diff, testPatterns())
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	// Should be sorted by filename: a.go before z.go
	if findings[0].File != "a.go" {
		t.Errorf("expected first finding in a.go, got %q", findings[0].File)
	}
	if findings[1].File != "z.go" {
		t.Errorf("expected second finding in z.go, got %q", findings[1].File)
	}
}

func TestScanDiff_RedactsContent(t *testing.T) {
	key := fakeKey("EXAMPLE")
	diff := makeDiffWithSecret("x.go", "export AWS_KEY="+key)
	findings, _ := ScanDiff(diff, testPatterns())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Content != "export AWS_KEY=[REDACTED]" {
		t.Errorf("expected redacted content, got %q", findings[0].Content)
	}
}

func TestCompileDLPPatterns_SkipsInvalid(t *testing.T) {
	patterns := []config.DLPPattern{
		{Name: "Good", Regex: `foo`, Severity: "low"},
		{Name: "Bad", Regex: `[invalid`, Severity: "high"},
		{Name: "Also Good", Regex: `bar`, Severity: "medium"},
	}
	compiled := CompileDLPPatterns(patterns)
	if len(compiled) != 2 {
		t.Fatalf("expected 2 compiled patterns (invalid skipped), got %d", len(compiled))
	}
}

func TestFormatFindings_NoFindings(t *testing.T) {
	result := FormatFindings(nil)
	if result != "No secrets found in diff." {
		t.Errorf("unexpected output: %q", result)
	}
}

func TestFormatFindings_WithFindings(t *testing.T) {
	findings := []Finding{
		{File: "main.go", Line: 10, Pattern: "AWS Key", Severity: "critical", Content: "export AWS_KEY=[REDACTED]"},
	}
	result := FormatFindings(findings)
	if result == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(result, "Found 1 secret(s)") {
		t.Errorf("expected count in output, got %q", result)
	}
	if !strings.Contains(result, "main.go:10") {
		t.Errorf("expected file:line in output, got %q", result)
	}
}

func TestFindingsJSON_WithFindings(t *testing.T) {
	findings := []Finding{
		{File: "main.go", Line: 42, Pattern: "AWS Key", Severity: "critical", Content: "[REDACTED]"},
	}
	data, err := FindingsJSON(findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var decoded []Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded))
	}
	if decoded[0].File != "main.go" {
		t.Errorf("expected file main.go, got %q", decoded[0].File)
	}
	if decoded[0].Line != 42 {
		t.Errorf("expected line 42, got %d", decoded[0].Line)
	}
	if decoded[0].Pattern != "AWS Key" {
		t.Errorf("expected pattern 'AWS Key', got %q", decoded[0].Pattern)
	}
}

func TestFindingsJSON_Empty(t *testing.T) {
	data, err := FindingsJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "[]" {
		t.Errorf("expected [], got %q", string(data))
	}
}

func TestFindingsJSON_EmptySlice(t *testing.T) {
	data, err := FindingsJSON([]Finding{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "[]" {
		t.Errorf("expected [], got %q", string(data))
	}
}

func TestParseDiff_NoPrefixFormat(t *testing.T) {
	// git diff --no-prefix produces "+++ filename" without "b/" prefix.
	key := fakeKey("NOPREFIX")
	diff := fmt.Sprintf(`diff --git main.go main.go
--- main.go
+++ main.go
@@ -1,2 +1,3 @@
 package main
+var key = "%s"
`, key)
	findings, _ := ScanDiff(diff, testPatterns())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding with --no-prefix diff, got %d", len(findings))
	}
	if findings[0].File != "main.go" {
		t.Errorf("expected file main.go, got %q", findings[0].File)
	}
}

func TestParseDiff_CRLFLineEndings(t *testing.T) {
	// Windows-style \r\n line endings should not break parsing.
	key := fakeKey("WINDOWS")
	diff := "diff --git a/x.go b/x.go\r\n--- a/x.go\r\n+++ b/x.go\r\n@@ -1,2 +1,3 @@\r\n package x\r\n+var k = \"" + key + "\"\r\n\r\n"
	findings, _ := ScanDiff(diff, testPatterns())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding with CRLF line endings, got %d", len(findings))
	}
	if findings[0].File != "x.go" {
		t.Errorf("expected file x.go, got %q", findings[0].File)
	}
}

func TestParseDiff_DevNullSkipped(t *testing.T) {
	// +++ /dev/null should not be treated as a filename.
	diff := `diff --git a/deleted.go b/deleted.go
--- a/deleted.go
+++ /dev/null
@@ -1,3 +0,0 @@
-package deleted
-func old() {}
`
	result := parseDiff(diff)
	if len(result) != 0 {
		t.Fatalf("expected 0 files from /dev/null diff, got %d", len(result))
	}
}
