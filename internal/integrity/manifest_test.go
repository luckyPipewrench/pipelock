package integrity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	content := "hello, integrity\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	entry, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}

	if entry.SHA256 == "" {
		t.Error("expected non-empty SHA256")
	}
	if entry.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), entry.Size)
	}
	if entry.Mode != "0600" {
		t.Errorf("expected mode 0600, got %s", entry.Mode)
	}
}

func TestHashFile_Deterministic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "det.txt")

	if err := os.WriteFile(path, []byte("same content"), 0o600); err != nil {
		t.Fatal(err)
	}

	e1, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}

	e2, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if e1.SHA256 != e2.SHA256 {
		t.Error("expected identical hashes for same content")
	}
}

func TestHashFile_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")

	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	entry, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// SHA256 of empty input is well-known.
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if entry.SHA256 != emptySHA256 {
		t.Errorf("expected empty file hash %s, got %s", emptySHA256, entry.SHA256)
	}
	if entry.Size != 0 {
		t.Errorf("expected size 0, got %d", entry.Size)
	}
}

func TestHashFile_Nonexistent(t *testing.T) {
	_, err := HashFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestManifest_SaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	now := time.Now().UTC().Truncate(time.Second)
	original := &Manifest{
		Version: ManifestVersion,
		Created: now,
		Updated: now,
		Files: map[string]FileEntry{
			"README.md":   {SHA256: "abc123", Size: 100, Mode: "0644"},
			"src/main.go": {SHA256: "def456", Size: 200, Mode: "0644"},
		},
		Excludes: []string{"*.log", ".git/**"},
	}

	if err := original.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Version != original.Version {
		t.Errorf("version: got %d, want %d", loaded.Version, original.Version)
	}
	if !loaded.Created.Equal(original.Created) {
		t.Errorf("created: got %v, want %v", loaded.Created, original.Created)
	}
	if len(loaded.Files) != len(original.Files) {
		t.Errorf("files count: got %d, want %d", len(loaded.Files), len(original.Files))
	}
	for path, expected := range original.Files {
		actual, ok := loaded.Files[path]
		if !ok {
			t.Errorf("missing file entry: %s", path)
			continue
		}
		if actual.SHA256 != expected.SHA256 {
			t.Errorf("%s SHA256: got %s, want %s", path, actual.SHA256, expected.SHA256)
		}
	}
	if len(loaded.Excludes) != len(original.Excludes) {
		t.Errorf("excludes count: got %d, want %d", len(loaded.Excludes), len(original.Excludes))
	}
}

func TestManifest_Save_Permissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := &Manifest{
		Version: ManifestVersion,
		Files:   map[string]FileEntry{},
	}

	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected permissions 0600, got %04o", info.Mode().Perm())
	}
}

func TestManifest_Save_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := &Manifest{
		Version: ManifestVersion,
		Files: map[string]FileEntry{
			"test.txt": {SHA256: "abc", Size: 10, Mode: "0644"},
		},
		Excludes: []string{"*.log"},
	}

	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: test reads its own temp file
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("saved manifest is not valid JSON: %v", err)
	}
}

func TestLoad_Nonexistent(t *testing.T) {
	_, err := Load("/nonexistent/manifest.json")
	if err == nil {
		t.Error("expected error for nonexistent manifest")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")

	if err := os.WriteFile(path, []byte("{invalid json}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoad_WrongVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	data := `{"version":99,"files":{}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for wrong manifest version")
	}
}

func TestSave_TargetIsDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatal(err)
	}

	m := &Manifest{Version: ManifestVersion, Files: map[string]FileEntry{}}
	// Rename(tempFile, directory) fails with EISDIR on Linux.
	err := m.Save(target)
	if err == nil {
		t.Fatal("expected error when target path is a directory")
	}
}

func TestHashFile_Directory(t *testing.T) {
	dir := t.TempDir()

	// Passing a directory to HashFile — io.Copy from dir fd fails with EISDIR.
	_, err := HashFile(dir)
	if err == nil {
		t.Fatal("expected error when hashing a directory")
	}
}

func TestSave_BadDirectory(t *testing.T) {
	m := &Manifest{
		Version: ManifestVersion,
		Files:   map[string]FileEntry{},
	}

	err := m.Save("/nonexistent/dir/manifest.json")
	if err == nil {
		t.Fatal("expected error for non-existent directory")
	}
}

func TestLoad_NilFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	data := `{"version":1}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for manifest with null files")
	}
}
