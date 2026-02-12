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

func TestMatchDoublestar_MultipleStars(t *testing.T) {
	// Patterns with more than one "**" segment return false.
	if matchDoublestar("a/**/b/**/c", "a/x/b/y/c") {
		t.Error("expected false for multiple ** segments")
	}
}

func TestMatchDoublestar_PrefixWithSuffix(t *testing.T) {
	// Pattern like "src/**/*.go" should match files under src/.
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"src/**/*.go", "src/main.go", true},
		{"src/**/*.go", "src/pkg/util.go", true},
		{"src/**/*.go", "src/readme.md", false},
		{"src/**/*.go", "other/main.go", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got := matchDoublestar(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchDoublestar(%q, %q) = %v, want %v",
					tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestMatchDoublestar_ExactPrefix(t *testing.T) {
	// When relPath exactly equals the prefix (no trailing slash).
	if !matchDoublestar("vendor/**", "vendor/anything") {
		t.Error("expected true for path under vendor/")
	}
}

func TestGenerate_UnreadableFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "readable.txt", "ok\n")

	// Create a subdirectory that's unreadable.
	unreadable := filepath.Join(dir, "secret")
	if err := os.MkdirAll(unreadable, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "secret/data.txt", "hidden\n")
	if err := os.Chmod(unreadable, 0o000); err != nil { //nolint:gosec // test: intentionally restricting permissions
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o700) }) //nolint:errcheck,gosec // best-effort cleanup

	_, err := Generate(dir, nil)
	if err == nil {
		t.Fatal("expected error for unreadable directory")
	}
}

func TestGenerate_HashFileError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "readable.txt", "ok\n")

	// Create a file that WalkDir finds but HashFile can't open.
	unreadable := filepath.Join(dir, "noperm.txt")
	if err := os.WriteFile(unreadable, []byte("secret"), 0o000); err != nil { //nolint:gosec // test: intentionally restricting permissions
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o600) }) //nolint:errcheck,gosec // best-effort cleanup

	_, err := Generate(dir, nil)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

func TestGenerate_ExcludeDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.txt", "keep\n")
	mkdirAll(t, dir, "logs/archive")
	writeFile(t, dir, "logs/app.log", "log\n")
	writeFile(t, dir, "logs/archive/old.log", "old\n")

	// Exclude with path-based glob (directory + file pattern).
	m, err := Generate(dir, []string{"logs/**"})
	if err != nil {
		t.Fatal(err)
	}

	if len(m.Files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(m.Files), fileNames(m))
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

func TestCheck_GenerateError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "file.txt", "content\n")

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make the directory unreadable so Check's internal Generate fails.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) }) //nolint:errcheck,gosec // best-effort cleanup

	_, err = Check(dir, m)
	if err == nil {
		t.Fatal("expected error when directory becomes unreadable")
	}
}

func TestValidateExcludes_PureDoublestar(t *testing.T) {
	// A pattern of just "**" should be valid (cleaned to empty string → skip).
	if err := validateExcludes([]string{"**"}); err != nil {
		t.Errorf("expected no error for **, got: %v", err)
	}
}

func TestValidateExcludes_Valid(t *testing.T) {
	patterns := []string{"*.log", "vendor/**", "**/*.tmp", "dir/*.txt"}
	if err := validateExcludes(patterns); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestMatchExclude_PathGlob(t *testing.T) {
	// Path glob with a slash matches against full relative path.
	if !matchExclude("config/secret.yaml", "config/secret.yaml") {
		t.Error("expected exact path match")
	}
	if matchExclude("config/secret.yaml", "other/secret.yaml") {
		t.Error("expected no match for different path")
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

// --- Permission Violation Tests ---

func TestCheck_PermissionViolation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "script.sh", "#!/bin/bash\necho hello\n")

	// Generate initial manifest
	manifest, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Change file permissions
	path := filepath.Join(dir, "script.sh")
	if err := os.Chmod(path, 0o755); err != nil { //nolint:gosec // G302: testing permission change detection
		t.Fatal(err)
	}

	// Re-generate to get the updated mode, then manually set manifest to expect old mode
	current, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Set expected mode to something different from current
	entry := manifest.Files["script.sh"]
	entry.Mode = "0600"
	entry.SHA256 = current.Files["script.sh"].SHA256 // keep hash same
	manifest.Files["script.sh"] = entry

	violations, err := Check(dir, manifest)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	found := false
	for _, v := range violations {
		if v.Type == ViolationPermissions && v.Path == "script.sh" {
			found = true
			if v.Expected != "0600" {
				t.Errorf("expected mode '0600', got %q", v.Expected)
			}
			break
		}
	}
	if !found {
		t.Error("expected permissions violation for script.sh")
	}
}

func TestCheck_NoPermissionViolation_MatchingMode(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "readme.txt", "hello\n")

	manifest, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Check with unchanged permissions - should have no violations
	violations, err := Check(dir, manifest)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	for _, v := range violations {
		if v.Type == ViolationPermissions {
			t.Errorf("unexpected permissions violation for %s", v.Path)
		}
	}
}

func TestCheck_NoPermissionViolation_EmptyMode(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "old.txt", "content\n")

	manifest, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Simulate an old manifest without Mode field (backward compat)
	entry := manifest.Files["old.txt"]
	entry.Mode = "" // old manifest format
	manifest.Files["old.txt"] = entry

	violations, err := Check(dir, manifest)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	for _, v := range violations {
		if v.Type == ViolationPermissions {
			t.Error("should not report permissions when manifest has empty Mode")
		}
	}
}

// --- Manifest Save Tests ---

func TestManifest_Save_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "test.txt", "hello\n")

	manifest, err := Generate(dir, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	savePath := filepath.Join(dir, ".manifest.json")
	if err := manifest.Save(savePath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(savePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(loaded.Files) != len(manifest.Files) {
		t.Errorf("file count: got %d, want %d", len(loaded.Files), len(manifest.Files))
	}
	for path, entry := range manifest.Files {
		loadedEntry, ok := loaded.Files[path]
		if !ok {
			t.Errorf("missing file %s in loaded manifest", path)
			continue
		}
		if loadedEntry.SHA256 != entry.SHA256 {
			t.Errorf("%s: hash mismatch", path)
		}
	}
}

func TestManifest_Save_BadDirectory(t *testing.T) {
	m := &Manifest{
		Version: ManifestVersion,
		Files:   map[string]FileEntry{},
	}
	err := m.Save("/nonexistent/dir/manifest.json")
	if err == nil {
		t.Fatal("expected error for bad directory")
	}
}

func TestHashFile_NonexistentFile(t *testing.T) {
	_, err := HashFile("/nonexistent/file.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "opening file") {
		t.Errorf("expected 'opening file' error, got: %v", err)
	}
}

func TestHashFile_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := "hello world\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	entry, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if entry.SHA256 == "" {
		t.Error("expected non-empty hash")
	}
	if entry.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), entry.Size)
	}
	if entry.Mode == "" {
		t.Error("expected non-empty mode")
	}
}

func TestManifest_Load_NullFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	// Valid JSON with version but files is null.
	if err := os.WriteFile(path, []byte(`{"version":1,"files":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for null files field")
	}
	if !strings.Contains(err.Error(), "null") {
		t.Errorf("expected error about null files, got: %v", err)
	}
}

func TestManifest_Load_WrongVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v2.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"files":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestManifest_Load_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{not json}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestManifest_Load_NonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/manifest.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestManifest_Save_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Make dir read-only so CreateTemp fails.
	if err := os.Chmod(subdir, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(subdir, 0o700) }) //nolint:gosec // restore for cleanup

	m := &Manifest{
		Version: ManifestVersion,
		Files:   map[string]FileEntry{"a.txt": {SHA256: "abc", Size: 3, Mode: "0644"}},
	}
	err := m.Save(filepath.Join(subdir, "manifest.json"))
	if err == nil {
		t.Fatal("expected error for read-only directory")
	}
}

func TestGenerate_SymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Create a symlink that should be skipped.
	if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Files["link.txt"]; ok {
		t.Error("expected symlink to be skipped")
	}
	if _, ok := m.Files["real.txt"]; !ok {
		t.Error("expected real.txt in manifest")
	}
}

func TestGenerate_HashErrorOnUnreadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noperm.txt")
	if err := os.WriteFile(path, []byte("secret"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) }) //nolint:errcheck,gosec // cleanup

	_, err := Generate(dir, nil)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}

func TestCheck_ModifiedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Modify the file.
	if err := os.WriteFile(path, []byte("modified"), 0o600); err != nil {
		t.Fatal(err)
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) == 0 {
		t.Fatal("expected violations for modified file")
	}

	found := false
	for _, v := range violations {
		if v.Path == "data.txt" && v.Type == ViolationModified {
			found = true
		}
	}
	if !found {
		t.Error("expected ViolationModified for data.txt")
	}
}

func TestCheck_AddedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "one.txt"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add a new file.
	if err := os.WriteFile(filepath.Join(dir, "two.txt"), []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, v := range violations {
		if v.Path == "two.txt" && v.Type == ViolationAdded {
			found = true
		}
	}
	if !found {
		t.Error("expected ViolationAdded for two.txt")
	}
}

func TestCheck_RemovedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gone.txt")
	if err := os.WriteFile(path, []byte("temp"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Remove the file.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	violations, err := Check(dir, m)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, v := range violations {
		if v.Path == "gone.txt" && v.Type == ViolationRemoved {
			found = true
		}
	}
	if !found {
		t.Error("expected ViolationRemoved for gone.txt")
	}
}

func TestMatchDoublestar_MultipleDoubleStars(t *testing.T) {
	// Multiple ** segments should return false.
	if matchDoublestar("a/**/b/**/c", "a/x/b/y/c") {
		t.Error("expected false for multiple ** segments")
	}
}

func TestMatchDoublestar_PrefixExactMatch(t *testing.T) {
	// relPath equals prefix exactly (without trailing path).
	if !matchDoublestar("dir/**", "dir/file.txt") {
		t.Error("expected match for dir/**")
	}
}

func TestMatchDoublestar_SuffixPattern(t *testing.T) {
	// **/pattern matching nested files.
	if !matchDoublestar("**/*.go", "internal/pkg/file.go") {
		t.Error("expected match for **/*.go")
	}
	if matchDoublestar("**/*.go", "internal/pkg/file.txt") {
		t.Error("expected no match for .txt file")
	}
}

func TestManifest_SaveAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-manifest.json")

	m := &Manifest{
		Version: ManifestVersion,
		Files: map[string]FileEntry{
			"a.txt": {SHA256: "abc123", Size: 6, Mode: "0644"},
			"b.txt": {SHA256: "def456", Size: 9, Mode: "0600"},
		},
	}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != ManifestVersion {
		t.Errorf("expected version %d, got %d", ManifestVersion, loaded.Version)
	}
	if len(loaded.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(loaded.Files))
	}
	if loaded.Files["a.txt"].SHA256 != "abc123" {
		t.Errorf("expected abc123, got %s", loaded.Files["a.txt"].SHA256)
	}
}

func TestCheck_HashError(t *testing.T) {
	// Check should report an error when a file in the manifest can't be read.
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make the file unreadable so hash fails during Check.
	if err := os.Chmod(path, 0o000); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) }) //nolint:gosec // restore

	violations, err := Check(dir, m)
	if err != nil {
		// Check might return an error for unreadable files
		return
	}
	// Or it might report a violation
	if len(violations) == 0 {
		t.Error("expected violation or error for unreadable file")
	}
}

func TestGenerate_WalkError(t *testing.T) {
	// Generate should handle errors from the file walker gracefully.
	dir := t.TempDir()
	subdir := filepath.Join(dir, "readable")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "ok.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Make the subdir unreadable so WalkDir can't list its contents.
	if err := os.Chmod(subdir, 0o000); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(subdir, 0o700) }) //nolint:gosec // restore

	_, err := Generate(dir, nil)
	if err == nil {
		t.Fatal("expected error for unreadable subdirectory")
	}
}
