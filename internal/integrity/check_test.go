package integrity

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestGenerate_SimpleDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", "# Hello\n")
	writeFile(t, dir, "main.go", "package main\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if m.Version != ManifestVersion {
		t.Errorf("version: got %d, want %d", m.Version, ManifestVersion)
	}
	if len(m.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(m.Files))
	}
	if _, ok := m.Files["README.md"]; !ok {
		t.Error("missing README.md in manifest")
	}
	if _, ok := m.Files["main.go"]; !ok {
		t.Error("missing main.go in manifest")
	}
}

func TestGenerate_NestedDirectories(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "top.txt", "top\n")
	mkdirAll(t, dir, "sub/deep")
	writeFile(t, dir, "sub/mid.txt", "mid\n")
	writeFile(t, dir, "sub/deep/bottom.txt", "bottom\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	expected := []string{"top.txt", "sub/mid.txt", "sub/deep/bottom.txt"}
	if len(m.Files) != len(expected) {
		t.Fatalf("expected %d files, got %d", len(expected), len(m.Files))
	}
	for _, name := range expected {
		if _, ok := m.Files[name]; !ok {
			t.Errorf("missing %s in manifest", name)
		}
	}
}

func TestGenerate_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(m.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(m.Files))
	}
}

func TestGenerate_ExcludeGlobs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.txt", "keep\n")
	writeFile(t, dir, "skip.log", "skip\n")
	writeFile(t, dir, "also.log", "also skip\n")

	m, err := Generate(dir, []string{"*.log"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(m.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(m.Files))
	}
	if _, ok := m.Files["keep.txt"]; !ok {
		t.Error("expected keep.txt in manifest")
	}
}

func TestGenerate_ExcludeRecursive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.txt", "keep\n")
	mkdirAll(t, dir, "vendor/pkg")
	writeFile(t, dir, "vendor/dep.go", "package dep\n")
	writeFile(t, dir, "vendor/pkg/sub.go", "package sub\n")

	m, err := Generate(dir, []string{"vendor/**"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(m.Files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(m.Files), fileNames(m))
	}
	if _, ok := m.Files["keep.txt"]; !ok {
		t.Error("expected keep.txt in manifest")
	}
}

func TestGenerate_ExcludeDoublestarPrefix(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.txt", "keep\n")
	mkdirAll(t, dir, "a/b")
	writeFile(t, dir, "a/test.log", "log\n")
	writeFile(t, dir, "a/b/test.log", "log\n")

	m, err := Generate(dir, []string{"**/*.log"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(m.Files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(m.Files), fileNames(m))
	}
}

func TestGenerate_SkipsGitDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.txt", "keep\n")
	mkdirAll(t, dir, ".git/objects")
	writeFile(t, dir, ".git/HEAD", "ref: refs/heads/main\n")
	writeFile(t, dir, ".git/objects/pack", "binary\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(m.Files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(m.Files), fileNames(m))
	}
}

func TestGenerate_SkipsManifestFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.txt", "keep\n")
	writeFile(t, dir, DefaultManifestFile, `{"version":1}`)

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, ok := m.Files[DefaultManifestFile]; ok {
		t.Error("manifest file should be excluded from its own contents")
	}
	if len(m.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(m.Files))
	}
}

func TestGenerate_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "real.txt", "real\n")

	linkPath := filepath.Join(dir, "link.txt")
	if err := os.Symlink(filepath.Join(dir, "real.txt"), linkPath); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, ok := m.Files["link.txt"]; ok {
		t.Error("symlinks should be skipped")
	}
	if len(m.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(m.Files))
	}
}

func TestGenerate_StoresExcludes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "file.txt", "content\n")

	excludes := []string{"*.log", "tmp/**"}
	m, err := Generate(dir, excludes)
	if err != nil {
		t.Fatal(err)
	}

	if len(m.Excludes) != 2 {
		t.Errorf("expected 2 excludes, got %d", len(m.Excludes))
	}
}

func TestCheck_NoViolations(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "file.txt", "hello\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if len(violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(violations))
	}
}

func TestCheck_Modified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	writeFile(t, dir, "file.txt", "original\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the file.
	if err := os.WriteFile(path, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	v := violations[0]
	if v.Path != "file.txt" {
		t.Errorf("expected path file.txt, got %s", v.Path)
	}
	if v.Type != ViolationModified {
		t.Errorf("expected type modified, got %s", v.Type)
	}
	if v.Expected == "" || v.Actual == "" {
		t.Error("expected both expected and actual hashes")
	}
	if v.Expected == v.Actual {
		t.Error("expected different hashes for modified file")
	}
}

func TestCheck_Added(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "original.txt", "original\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add a new file.
	writeFile(t, dir, "new.txt", "new file\n")

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	v := violations[0]
	if v.Path != "new.txt" {
		t.Errorf("expected path new.txt, got %s", v.Path)
	}
	if v.Type != ViolationAdded {
		t.Errorf("expected type added, got %s", v.Type)
	}
}

func TestCheck_Removed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	writeFile(t, dir, "file.txt", "content\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Delete the file.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	v := violations[0]
	if v.Path != "file.txt" {
		t.Errorf("expected path file.txt, got %s", v.Path)
	}
	if v.Type != ViolationRemoved {
		t.Errorf("expected type removed, got %s", v.Type)
	}
}

func TestCheck_MultipleViolations(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "modify.txt", "original\n")
	writeFile(t, dir, "delete.txt", "will be deleted\n")
	writeFile(t, dir, "keep.txt", "stays the same\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Modify, delete, and add.
	if err := os.WriteFile(filepath.Join(dir, "modify.txt"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "delete.txt")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "added.txt", "surprise\n")

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if len(violations) != 3 {
		t.Fatalf("expected 3 violations, got %d", len(violations))
	}

	types := map[ViolationType]bool{}
	for _, v := range violations {
		types[v.Type] = true
	}
	if !types[ViolationModified] {
		t.Error("expected a modified violation")
	}
	if !types[ViolationAdded] {
		t.Error("expected an added violation")
	}
	if !types[ViolationRemoved] {
		t.Error("expected a removed violation")
	}
}

func TestCheck_RespectsExcludes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "tracked.txt", "tracked\n")

	m, err := Generate(dir, []string{"*.log"})
	if err != nil {
		t.Fatal(err)
	}

	// Add a .log file — should not appear as a violation.
	writeFile(t, dir, "debug.log", "log output\n")

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if len(violations) != 0 {
		t.Errorf("expected 0 violations (log excluded), got %d", len(violations))
	}
}

func TestCheck_BinaryFile(t *testing.T) {
	dir := t.TempDir()

	// Write binary content with null bytes.
	binary := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
	if err := os.WriteFile(filepath.Join(dir, "binary.bin"), binary, 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m.Files["binary.bin"]; !ok {
		t.Fatal("expected binary.bin in manifest")
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(violations))
	}
}

func TestMatchExclude_Patterns(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Simple basename globs.
		{"*.log", "debug.log", true},
		{"*.log", "app/debug.log", true},
		{"*.log", "file.txt", false},

		// Path globs.
		{"dir/*.txt", "dir/file.txt", true},
		{"dir/*.txt", "other/file.txt", false},

		// Recursive (**).
		{"vendor/**", "vendor/dep.go", true},
		{"vendor/**", "vendor/pkg/sub.go", true},
		{"vendor/**", "src/main.go", false},

		// Doublestar prefix.
		{"**/*.log", "a/b/debug.log", true},
		{"**/*.log", "debug.log", true},
		{"**/*.log", "file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got := matchExclude(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchExclude(%q, %q) = %v, want %v",
					tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestGenerate_NoPathTraversal(t *testing.T) {
	dir := t.TempDir()
	// Create a file in a directory with dots in the name (not actual traversal).
	mkdirAll(t, dir, "..something")
	writeFile(t, dir, "..something/file.txt", "content\n")
	writeFile(t, dir, "normal.txt", "normal\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// No manifest key should start with "../".
	for key := range m.Files {
		if strings.HasPrefix(key, "../") {
			t.Errorf("manifest key escapes workspace root: %s", key)
		}
	}

	// The ..something directory should still be tracked.
	if _, ok := m.Files["..something/file.txt"]; !ok {
		t.Error("expected ..something/file.txt in manifest")
	}
}

func TestGenerate_InvalidExcludePattern(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "file.txt", "content\n")

	_, err := Generate(dir, []string{"[unclosed"})
	if err == nil {
		t.Error("expected error for malformed exclude pattern")
	}
}

func TestGenerate_PathSeparators(t *testing.T) {
	dir := t.TempDir()
	mkdirAll(t, dir, "sub")
	writeFile(t, dir, "sub/file.txt", "content\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Manifest keys should always use forward slashes.
	if _, ok := m.Files["sub/file.txt"]; !ok {
		t.Errorf("expected forward-slash path, got keys: %v", fileNames(m))
	}
}

// --- helpers ---

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	parent := filepath.Dir(full)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mkdirAll(t *testing.T, dir, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(rel)), 0o750); err != nil {
		t.Fatal(err)
	}
}

func fileNames(m *Manifest) []string {
	names := make([]string, 0, len(m.Files))
	for k := range m.Files {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
