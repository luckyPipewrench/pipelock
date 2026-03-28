// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package integrity provides pre-spawn binary hash verification for MCP
// subprocess servers. It resolves symlinks and interpreter shebangs,
// hashes the actual binary (and script when an interpreter is detected),
// and compares against a trusted manifest. A second symlink resolution at
// exec time detects TOCTOU races.
package integrity

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ManifestVersion is the schema version for MCP binary integrity manifests.
const ManifestVersion = 1

// maxShebangLen caps the number of bytes read when looking for a #! line.
// A shebang line exceeding this is treated as "no shebang" (safe default).
const maxShebangLen = 256

// interpreters is the set of known interpreter basenames. When command[0]
// resolves to one of these, command[1] (the script) is also hashed.
var interpreters = map[string]bool{
	"python": true, "python3": true,
	"node": true, "bun": true, "deno": true,
	"ruby": true, "perl": true,
	"bash": true, "sh": true, "dash": true,
	"npx": true, "bunx": true, "uvx": true, "pipx": true,
}

// interpreterPrefixes lists prefixes for matching versioned interpreters
// like "python3.11", "node20", etc. Checked as fallback when exact match
// against the interpreters map fails.
var interpreterPrefixes = []string{
	"python", "python3", "node", "ruby", "perl", "bash", "sh", "bun", "deno",
}

// isInterpreterName checks whether baseName is a known interpreter. It first
// tries an exact match in the interpreters map (fast path), then falls back to
// prefix matching for versioned names like "python3.11" or "node20".
func isInterpreterName(baseName string) bool {
	if interpreters[baseName] {
		return true
	}
	for _, prefix := range interpreterPrefixes {
		if strings.HasPrefix(baseName, prefix) && len(baseName) > len(prefix) {
			return true
		}
	}
	return false
}

// Config controls MCP binary integrity verification.
type Config struct {
	Enabled      bool              `yaml:"enabled"`
	ManifestPath string            `yaml:"manifest_path"` // path to JSON manifest on disk
	Action       string            `yaml:"action"`        // "block" or "warn" (default "warn")
	Manifests    map[string]string `yaml:"-"`             // loaded: resolved_path -> expected SHA-256
}

// Manifest is the on-disk JSON format for trusted binary hashes.
type Manifest struct {
	Version int               `json:"version"`
	Entries map[string]string `json:"entries"` // resolved_path -> SHA-256 hex
}

// VerifyResult is the outcome of a pre-spawn integrity check.
type VerifyResult struct {
	Verified      bool   // true when all hashes match the manifest
	ResolvedPath  string // binary path after EvalSymlinks + LookPath
	ExpectedHash  string // from manifest (empty if binary is unknown)
	ActualHash    string // computed from file contents
	IsInterpreter bool   // true if command[0] is a known interpreter
	ScriptPath    string // script path when IsInterpreter is true
	ScriptHash    string // hash of the script when IsInterpreter is true
	Suspicious    bool   // true if binary is inside agent working directory
	Reason        string // human-readable explanation when Verified is false
}

// LoadManifest reads a binary integrity manifest from disk.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
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
	if m.Entries == nil {
		return nil, fmt.Errorf("parsing manifest: missing or null 'entries' field")
	}

	return &m, nil
}

// SaveManifest writes a manifest to disk with restrictive permissions.
func SaveManifest(path string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}

	data = append(data, '\n')

	return os.WriteFile(filepath.Clean(path), data, 0o600)
}

// Verify resolves the command binary path, hashes the file, and checks
// against the manifest. For interpreters it hashes both the interpreter
// and the script. Returns a VerifyResult describing the outcome.
//
// agentWorkDir, when non-empty, triggers suspicious-path detection:
// a resolved binary inside the agent's working directory is flagged.
func Verify(command []string, cfg *Config, agentWorkDir string) (*VerifyResult, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	result := &VerifyResult{}

	// Resolve binary path through PATH lookup and symlink resolution.
	resolved, err := resolveBinary(command[0])
	if err != nil {
		return nil, fmt.Errorf("resolving binary %q: %w", command[0], err)
	}
	result.ResolvedPath = resolved

	// Check if binary is inside the agent working directory.
	if agentWorkDir != "" {
		result.Suspicious = isInsideDir(resolved, agentWorkDir)
	}

	// Hash the binary via fd (TOCTOU mitigation: open first, hash contents).
	actualHash, err := hashFileByFD(resolved)
	if err != nil {
		return nil, fmt.Errorf("hashing binary %q: %w", resolved, err)
	}
	result.ActualHash = actualHash

	// Check if the binary is a known interpreter (exact or versioned prefix).
	// Check both the resolved name and the original command name because
	// symlinks can change the basename (e.g. "sh" -> "/usr/bin/dash").
	baseName := filepath.Base(resolved)
	result.IsInterpreter = isInterpreterName(baseName) || isInterpreterName(filepath.Base(command[0]))

	// Handle /usr/bin/env wrapper: if command[0] resolves to "env", the real
	// interpreter is command[1] and the script is command[2].
	if !result.IsInterpreter && baseName == "env" && len(command) > 1 {
		envInterp := command[1]
		envInterpResolved, envErr := resolveBinary(envInterp)
		if envErr != nil {
			return nil, fmt.Errorf("resolving env interpreter %q: %w", envInterp, envErr)
		}
		envInterpHash, envHashErr := hashFileByFD(envInterpResolved)
		if envHashErr != nil {
			return nil, fmt.Errorf("hashing env interpreter %q: %w", envInterpResolved, envHashErr)
		}
		result.IsInterpreter = true
		result.ResolvedPath = envInterpResolved
		result.ActualHash = envInterpHash

		// Hash the script argument (command[2]) if present.
		if len(command) > 2 {
			scriptPath, scriptHash, shebangErr := hashScript(command[2])
			if shebangErr != nil {
				return nil, fmt.Errorf("hashing script %q: %w", command[2], shebangErr)
			}
			result.ScriptPath = scriptPath
			result.ScriptHash = scriptHash
		}
	} else if result.IsInterpreter && len(command) > 1 {
		// Standard interpreter invocation: hash the script argument.
		scriptPath, scriptHash, shebangErr := hashScript(command[1])
		if shebangErr != nil {
			return nil, fmt.Errorf("hashing script %q: %w", command[1], shebangErr)
		}
		result.ScriptPath = scriptPath
		result.ScriptHash = scriptHash
	}

	// If not detected as interpreter, check shebang of command[0] itself.
	if !result.IsInterpreter {
		sheInterp := detectShebang(resolved)
		if sheInterp != "" {
			// The file is a script with a shebang. Hash the shebang interpreter too.
			result.IsInterpreter = true
			result.ScriptPath = resolved
			result.ScriptHash = actualHash

			interpResolved, interpErr := resolveBinary(sheInterp)
			if interpErr != nil {
				return nil, fmt.Errorf("resolving shebang interpreter %q: %w", sheInterp, interpErr)
			}
			interpHash, interpHashErr := hashFileByFD(interpResolved)
			if interpHashErr != nil {
				return nil, fmt.Errorf("hashing shebang interpreter %q: %w", interpResolved, interpHashErr)
			}
			result.ResolvedPath = interpResolved
			result.ActualHash = interpHash
		}
	}

	// Verify against manifest.
	result.Verified = true
	if cfg.Manifests != nil {
		expected, inManifest := cfg.Manifests[result.ResolvedPath]
		if inManifest {
			result.ExpectedHash = expected
			if result.ActualHash != expected {
				result.Verified = false
				result.Reason = fmt.Sprintf("binary hash mismatch for %s: expected %s, got %s",
					result.ResolvedPath, expected, result.ActualHash)
			}
		} else {
			// Binary not in manifest -- fail-closed: unknown binary is not verified.
			result.Verified = false
			result.Reason = fmt.Sprintf("binary %s not found in manifest", result.ResolvedPath)
		}

		// Also verify script hash if present.
		if result.IsInterpreter && result.ScriptPath != "" {
			expectedScript, scriptInManifest := cfg.Manifests[result.ScriptPath]
			if scriptInManifest {
				if result.ScriptHash != expectedScript {
					result.Verified = false
					result.Reason = fmt.Sprintf("script hash mismatch for %s: expected %s, got %s",
						result.ScriptPath, expectedScript, result.ScriptHash)
				}
			} else {
				result.Verified = false
				if result.Reason == "" {
					result.Reason = fmt.Sprintf("script %s not found in manifest", result.ScriptPath)
				}
			}
		}
	}

	return result, nil
}

// ResolveAndHash resolves a binary path and returns its resolved path and
// SHA-256 hash. Useful for generating manifest entries.
func ResolveAndHash(binary string) (resolvedPath, hash string, err error) {
	resolved, err := resolveBinary(binary)
	if err != nil {
		return "", "", err
	}

	h, err := hashFileByFD(resolved)
	if err != nil {
		return "", "", err
	}

	return resolved, h, nil
}

// CheckSymlinkRace compares the current symlink resolution against the
// path resolved at hash time. Returns an error if they differ, indicating
// a potential TOCTOU race (symlink was swapped between hash and exec).
func CheckSymlinkRace(originalCommand string, expectedResolved string) error {
	current, err := resolveBinary(originalCommand)
	if err != nil {
		return fmt.Errorf("re-resolving binary %q: %w", originalCommand, err)
	}
	if current != expectedResolved {
		return fmt.Errorf("symlink race detected: %q resolved to %q at hash time but %q now",
			originalCommand, expectedResolved, current)
	}
	return nil
}

// resolveBinary finds the actual binary path via exec.LookPath and
// resolves any symlinks to get the real filesystem path.
func resolveBinary(name string) (string, error) {
	// If it's an absolute or relative path with separators, resolve directly.
	var lookupPath string
	if strings.Contains(name, string(filepath.Separator)) || filepath.IsAbs(name) {
		abs, err := filepath.Abs(name)
		if err != nil {
			return "", fmt.Errorf("absolute path: %w", err)
		}
		lookupPath = abs
	} else {
		// Search PATH.
		found, err := exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("LookPath: %w", err)
		}
		lookupPath = found
	}

	resolved, err := filepath.EvalSymlinks(lookupPath)
	if err != nil {
		return "", fmt.Errorf("EvalSymlinks: %w", err)
	}

	return resolved, nil
}

// hashFileByFD opens the file, hashes the fd contents (TOCTOU mitigation),
// and returns the hex-encoded SHA-256 digest.
func hashFileByFD(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing: %w", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// hashScript resolves and hashes a script file. Returns the resolved path
// and SHA-256 hash.
func hashScript(scriptArg string) (string, string, error) {
	resolved, err := filepath.Abs(scriptArg)
	if err != nil {
		return "", "", fmt.Errorf("absolute path: %w", err)
	}

	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", "", fmt.Errorf("EvalSymlinks: %w", err)
	}

	h, err := hashFileByFD(resolved)
	if err != nil {
		return "", "", err
	}

	return resolved, h, nil
}

// detectShebang reads the first line of a file and returns the interpreter
// path if it starts with "#!". Returns empty string if no shebang is found.
func detectShebang(path string) string {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	reader := bufio.NewReaderSize(f, maxShebangLen)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return ""
	}

	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#!") {
		return ""
	}

	shebang := strings.TrimPrefix(line, "#!")
	shebang = strings.TrimSpace(shebang)

	// Handle "#!/usr/bin/env python3" -> return "python3"
	parts := strings.Fields(shebang)
	if len(parts) == 0 {
		return ""
	}

	if filepath.Base(parts[0]) == "env" && len(parts) > 1 {
		return parts[1]
	}

	return parts[0]
}

// isInsideDir checks if path is inside or equal to dir, after resolving
// both to absolute real paths.
func isInsideDir(path, dir string) bool {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}

	realDir, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return false
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	realPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return false
	}

	rel, err := filepath.Rel(realDir, realPath)
	if err != nil {
		return false
	}

	return !strings.HasPrefix(rel, "..")
}
