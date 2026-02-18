// Package integrity provides file integrity monitoring for agent workspaces.
//
// It generates SHA256 manifests of directory contents and detects unauthorized
// modifications, additions, and deletions — the foundation for securing
// inter-agent communication channels.
package integrity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ManifestVersion is the current manifest schema version.
const ManifestVersion = 1

// DefaultManifestFile is the default manifest filename within a workspace.
const DefaultManifestFile = ".integrity-manifest.json"

// Manifest records the integrity state of a workspace directory.
type Manifest struct {
	Version  int                  `json:"version"`
	Created  time.Time            `json:"created"`
	Updated  time.Time            `json:"updated"`
	Files    map[string]FileEntry `json:"files"`
	Excludes []string             `json:"excludes"`
}

// FileEntry records integrity data for a single file.
type FileEntry struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
}

// Load reads and parses a manifest from disk.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: caller controls path
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}

	if m.Version != ManifestVersion {
		return nil, fmt.Errorf("unsupported manifest version %d (expected %d)", m.Version, ManifestVersion)
	}
	if m.Files == nil {
		return nil, fmt.Errorf("parsing manifest: missing or null 'files' field")
	}

	return &m, nil
}

// Save atomically writes the manifest to disk with restrictive permissions.
// It writes to a temporary file and renames to prevent corruption on crash.
func (m *Manifest) Save(path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}

	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()        //nolint:errcheck,gosec // cleanup
		os.Remove(tmpName) //nolint:errcheck,gosec // cleanup
		return fmt.Errorf("writing manifest: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()        //nolint:errcheck,gosec // cleanup
		os.Remove(tmpName) //nolint:errcheck,gosec // cleanup
		return fmt.Errorf("setting manifest permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) //nolint:errcheck,gosec // cleanup
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil { //nolint:gosec // G703: path from caller, not user input
		os.Remove(tmpName) //nolint:errcheck,gosec // cleanup
		return fmt.Errorf("writing manifest: %w", err)
	}

	return nil
}

// HashFile computes the SHA256 hash and stats a single file.
func HashFile(path string) (FileEntry, error) {
	f, err := os.Open(path) //nolint:gosec // G304: caller controls path
	if err != nil {
		return FileEntry{}, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only

	info, err := f.Stat()
	if err != nil {
		return FileEntry{}, fmt.Errorf("stat file: %w", err)
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return FileEntry{}, fmt.Errorf("hashing file: %w", err)
	}

	return FileEntry{
		SHA256: fmt.Sprintf("%x", h.Sum(nil)),
		Size:   info.Size(),
		Mode:   fmt.Sprintf("%04o", info.Mode().Perm()),
	}, nil
}
