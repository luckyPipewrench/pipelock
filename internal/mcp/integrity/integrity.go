// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package integrity provides pre-spawn binary hash verification for MCP
// subprocess servers. It resolves symlinks and interpreter shebangs,
// hashes the actual binary (and script when an interpreter is detected),
// and compares against a trusted manifest. A second symlink resolution at
// exec time detects symlink swaps between hash-time and exec-time.
//
// NOTE: CheckSymlinkRace detects symlink target changes (path identity)
// but does NOT detect in-place content replacement after hashing. Full
// TOCTOU prevention would require fexecve-style fd binding, which Go's
// os/exec does not support. The gap is documented here and in
// CheckSymlinkRace so operators understand the threat model.
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
}

// packageRunners are tools that dynamically resolve executables at runtime.
// argv[1] is a package name, not a script path, so integrity verification
// of command[1] as a file is not meaningful. These are intentionally
// excluded from the interpreters map.
var packageRunners = map[string]bool{
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
// The suffix after the prefix must start with a digit or dot to avoid
// false positives on unrelated binaries (e.g. "shred", "node_exporter").
func isInterpreterName(baseName string) bool {
	if interpreters[baseName] {
		return true
	}
	for _, prefix := range interpreterPrefixes {
		if strings.HasPrefix(baseName, prefix) && len(baseName) > len(prefix) {
			suffix := baseName[len(prefix)]
			if suffix == '.' || (suffix >= '0' && suffix <= '9') {
				return true
			}
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
	Verified           bool     // true when all hashes match the manifest
	ResolvedPath       string   // binary path after EvalSymlinks + LookPath
	InterpreterPath    string   // interpreter binary path when env/shebang rewrites ResolvedPath
	ExpectedHash       string   // from manifest (empty if binary is unknown)
	ActualHash         string   // computed from file contents
	IsInterpreter      bool     // true if command[0] is a known interpreter
	IsPackageRunner    bool     // true if command[0] is a package runner (npx, bunx, etc.)
	ScriptPath         string   // script path when IsInterpreter is true
	ScriptHash         string   // hash of the script when IsInterpreter is true
	ExpectedScriptHash string   // from manifest (empty if script is unknown)
	Suspicious         bool     // true if binary is inside agent working directory
	Reason             string   // last/primary reason when Verified is false (backward compat)
	Reasons            []string // all accumulated failure reasons for audit evidence
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
// Uses atomic write (temp file + rename) to ensure the file always has
// correct permissions, even if it already exists with looser perms.
func SaveManifest(path string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}

	data = append(data, '\n')

	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)

	tmp, err := os.CreateTemp(dir, ".manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	// Clean up temp file on any error path.
	success := false
	defer func() {
		if !success {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("setting temp file permissions: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	if err := os.Rename(tmpName, cleanPath); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}

	success = true
	return nil
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

	// Hash the binary via fd (mitigates read-after-open races but not
	// in-place replacement after close; see package doc for limitations).
	actualHash, err := hashFileByFD(resolved)
	if err != nil {
		return nil, fmt.Errorf("hashing binary %q: %w", resolved, err)
	}
	result.ActualHash = actualHash

	// Check if the binary is a known interpreter (exact or versioned prefix).
	// Check both the resolved name and the original command name because
	// symlinks can change the basename (e.g. "sh" -> "/usr/bin/dash").
	baseName := filepath.Base(resolved)
	cmdBase := filepath.Base(command[0])
	result.IsInterpreter = isInterpreterName(baseName) || isInterpreterName(cmdBase)

	// Check for package runners (npx, bunx, etc.) -- these resolve executables
	// dynamically so argv[1] is not a hashable script path.
	if packageRunners[baseName] || packageRunners[cmdBase] {
		result.IsPackageRunner = true
		result.IsInterpreter = false
	}

	// Handle /usr/bin/env wrapper: if command[0] resolves to "env", skip env
	// flags (e.g. -S, -i, -u VAR, --) to find the real interpreter and script.
	if !result.IsInterpreter && baseName == "env" && len(command) > 1 {
		remaining := skipEnvFlags(command[1:])
		if len(remaining) > 0 {
			envInterp := remaining[0]
			envInterpResolved, envErr := resolveBinary(envInterp)
			if envErr != nil {
				return nil, fmt.Errorf("resolving env interpreter %q: %w", envInterp, envErr)
			}
			envInterpHash, envHashErr := hashFileByFD(envInterpResolved)
			if envHashErr != nil {
				return nil, fmt.Errorf("hashing env interpreter %q: %w", envInterpResolved, envHashErr)
			}
			result.IsInterpreter = true
			result.InterpreterPath = envInterpResolved
			result.ResolvedPath = envInterpResolved
			result.ActualHash = envInterpHash

			// Hash the script argument (first arg after interpreter) if present.
			if len(remaining) > 1 {
				scriptPath, scriptHash, shebangErr := hashScript(remaining[1], agentWorkDir)
				if shebangErr != nil {
					return nil, fmt.Errorf("hashing script %q: %w", remaining[1], shebangErr)
				}
				result.ScriptPath = scriptPath
				result.ScriptHash = scriptHash
			}
		}
	} else if result.IsInterpreter && len(command) > 1 {
		// Standard interpreter invocation: hash the script argument.
		scriptPath, scriptHash, shebangErr := hashScript(command[1], agentWorkDir)
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
			result.InterpreterPath = interpResolved
			result.ResolvedPath = interpResolved
			result.ActualHash = interpHash
		}
	}

	// Verify against manifest. Fail-closed: no manifest = not verified.
	if cfg.Manifests == nil {
		result.Verified = false
		result.Reason = "no manifest loaded"
		result.Reasons = append(result.Reasons, "no manifest loaded")
		return result, nil
	}

	result.Verified = true
	{
		expected, inManifest := cfg.Manifests[result.ResolvedPath]
		if inManifest {
			result.ExpectedHash = expected
			if result.ActualHash != expected {
				result.Verified = false
				reason := fmt.Sprintf("binary hash mismatch for %s: expected %s, got %s",
					result.ResolvedPath, expected, result.ActualHash)
				result.Reason = reason
				result.Reasons = append(result.Reasons, reason)
			}
		} else {
			// Binary not in manifest -- fail-closed: unknown binary is not verified.
			result.Verified = false
			reason := fmt.Sprintf("binary %s not found in manifest", result.ResolvedPath)
			result.Reason = reason
			result.Reasons = append(result.Reasons, reason)
		}

		// Also verify script hash if present.
		if result.IsInterpreter && result.ScriptPath != "" {
			expectedScript, scriptInManifest := cfg.Manifests[result.ScriptPath]
			if scriptInManifest {
				result.ExpectedScriptHash = expectedScript
				if result.ScriptHash != expectedScript {
					result.Verified = false
					reason := fmt.Sprintf("script hash mismatch for %s: expected %s, got %s",
						result.ScriptPath, expectedScript, result.ScriptHash)
					result.Reason = reason
					result.Reasons = append(result.Reasons, reason)
				}
			} else {
				result.Verified = false
				reason := fmt.Sprintf("script %s not found in manifest", result.ScriptPath)
				result.Reason = reason
				result.Reasons = append(result.Reasons, reason)
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
// a symlink swap between hash-time and exec-time.
//
// NOTE: This checks path identity (symlink target stability), not content
// identity. A file whose contents are replaced in-place after hashing
// will not be detected by this check. Full TOCTOU prevention would
// require opening the file by fd and using fexecve, which Go's os/exec
// does not expose. This is a known limitation of the threat model.
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

// hashFileByFD opens the file and hashes the fd contents, returning the
// hex-encoded SHA-256 digest. Hashing via the open fd avoids re-reading
// after resolution, but does not prevent in-place replacement after the
// fd is closed (see package doc for TOCTOU limitations).
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
// and SHA-256 hash. When workDir is non-empty and scriptArg is relative,
// the script is resolved relative to workDir (the subprocess cwd) rather
// than the proxy process cwd, avoiding path resolution mismatch.
func hashScript(scriptArg, workDir string) (string, string, error) {
	var resolved string
	if !filepath.IsAbs(scriptArg) && workDir != "" {
		resolved = filepath.Join(workDir, scriptArg)
	} else {
		abs, err := filepath.Abs(scriptArg)
		if err != nil {
			return "", "", fmt.Errorf("absolute path: %w", err)
		}
		resolved = abs
	}

	resolved, err := filepath.EvalSymlinks(resolved)
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
// Reads at most maxShebangLen bytes; a shebang line exceeding that limit
// is treated as "no shebang" (safe default).
func detectShebang(path string) string {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	// Limit reads to maxShebangLen to prevent unbounded reads when no
	// newline exists in the file (e.g. a binary).
	limited := io.LimitReader(f, maxShebangLen)
	reader := bufio.NewReaderSize(limited, maxShebangLen)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return ""
	}

	// If we read maxShebangLen bytes without finding a newline, the line
	// is too long to be a valid shebang. Treat as "no shebang".
	if err != nil && len(line) >= maxShebangLen {
		return ""
	}

	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#!") {
		return ""
	}

	shebang := strings.TrimPrefix(line, "#!")
	shebang = strings.TrimSpace(shebang)

	// Handle "#!/usr/bin/env python3" and "#!/usr/bin/env -S python3".
	parts := strings.Fields(shebang)
	if len(parts) == 0 {
		return ""
	}

	if filepath.Base(parts[0]) == "env" && len(parts) > 1 {
		remaining := skipEnvFlags(parts[1:])
		if len(remaining) > 0 {
			return remaining[0]
		}
		return "" // no interpreter found after env flags (fail-closed)
	}

	return parts[0]
}

// skipEnvFlags skips known /usr/bin/env flags and options, returning the
// remaining args starting from the actual interpreter name. Returns nil if
// no interpreter is found after exhausting all arguments. Fail-closed: if
// the args are ambiguous or unrecognized, returns nil (caller treats as
// "no interpreter found").
//
// Known flag patterns:
//   - -i, -0: standalone flags (no value)
//   - -u NAME: flag that consumes the next token as its value
//   - -S CMD: flag where the next token is the interpreter
//   - --: end of options, next token is interpreter
func skipEnvFlags(args []string) []string {
	for len(args) > 0 {
		switch args[0] {
		case "--":
			// End of options; interpreter follows (or empty = fail-closed).
			args = args[1:]
			if len(args) == 0 {
				return nil
			}
			return args
		case "-S":
			// -S means the next token is the command (interpreter).
			args = args[1:]
			if len(args) == 0 {
				return nil
			}
			return args
		case "-u":
			// -u takes a value (VAR name to unset); skip flag and value.
			args = args[1:]
			if len(args) == 0 {
				return nil
			}
			args = args[1:]
		case "-i", "-0":
			// Standalone flags; continue to next.
			args = args[1:]
		default:
			// Not a recognized flag -- this is the interpreter.
			return args
		}
	}
	return nil
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
