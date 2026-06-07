// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/secperm"
)

// SidecarOp is a deferred filesystem operation produced by WrapServer /
// UnwrapServer. Callers accumulate ops during their wrap / unwrap loops and
// apply them at the right moment in their commit sequence (writes before the
// canonical config rename, deletes only after the restored config is
// committed; dry-run skips apply entirely).
//
// Fields are unexported deliberately: the op is an opaque plan, constructed
// only via SidecarWrite / SidecarDelete (or returned by the wrap helpers) and
// consumed by ApplySidecarOps. Read-only accessors expose what callers and
// tests legitimately need to inspect without making the internal shape a
// mutable cross-package contract.
type SidecarOp struct {
	kind string // sidecarOpWrite | sidecarOpDelete
	path string // deterministic sidecar file location
	body []byte // file content, only populated for a write op
}

const (
	sidecarOpWrite  = "write"
	sidecarOpDelete = "delete"
)

// SidecarWrite returns an op that creates the sidecar file at path with body.
func SidecarWrite(path string, body []byte) SidecarOp {
	return SidecarOp{kind: sidecarOpWrite, path: path, body: body}
}

// SidecarDelete returns an op that removes the sidecar file at path.
func SidecarDelete(path string) SidecarOp {
	return SidecarOp{kind: sidecarOpDelete, path: path}
}

// Path reports the sidecar file path the op acts on.
func (o SidecarOp) Path() string { return o.path }

// Body reports the file content for a write op (nil for a delete).
func (o SidecarOp) Body() []byte { return o.body }

// IsWrite reports whether the op creates a sidecar.
func (o SidecarOp) IsWrite() bool { return o.kind == sidecarOpWrite }

// IsDelete reports whether the op removes a sidecar.
func (o SidecarOp) IsDelete() bool { return o.kind == sidecarOpDelete }

// ApplySidecarOps performs the writes and deletes described by ops. On a write
// failure it deletes any sidecars written earlier in the same call so callers
// never observe a partially-applied plan, and returns immediately. Delete
// failures (other than an already-absent file) are collected and returned
// joined so a caller can surface a credential sidecar that could not be
// removed rather than reporting a clean rollback while the file lingers. A
// missing file is not an error.
func ApplySidecarOps(ops []SidecarOp) error {
	written := make([]string, 0, len(ops))
	var deleteErrs []error
	for _, op := range ops {
		switch op.kind {
		case sidecarOpWrite:
			if err := commitHeaderSidecar(op.path, op.body); err != nil {
				for _, p := range written {
					_ = removeHeaderSidecar(p)
				}
				return err
			}
			written = append(written, op.path)
		case sidecarOpDelete:
			if err := removeHeaderSidecar(op.path); err != nil {
				deleteErrs = append(deleteErrs, err)
			}
		}
	}
	return errors.Join(deleteErrs...)
}

// RollbackSidecarWrites deletes every sidecar referenced by a write op. Used
// when a later step (the canonical config atomic write) fails after
// ApplySidecarOps has already landed sidecars on disk. Best-effort: a delete
// that fails here leaves a sidecar behind, but the caller is already returning
// the original failure.
func RollbackSidecarWrites(ops []SidecarOp) {
	for _, op := range ops {
		if op.kind == sidecarOpWrite {
			_ = removeHeaderSidecar(op.path)
		}
	}
}

// extractHeaderLines reads, validates, and returns the operator's HTTP header
// declarations as "Key: Value" lines ready for a sidecar file. The runtime
// parser repeats these checks at startup; doing them here means a bad header
// fails install rather than surfacing only after the agent starts. Returns nil
// when the server has no headers block.
func extractHeaderLines(server map[string]interface{}) ([]string, error) {
	headers, ok := server[FieldHeaders].(map[string]interface{})
	if !ok || len(headers) == 0 {
		return nil, nil
	}

	lines := make([]string, 0, len(headers))
	for key, raw := range headers {
		value, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("header %q has non-string value of type %T; only string header values are supported", key, raw)
		}
		key = strings.Trim(key, " \t")
		value = strings.Trim(value, " \t")
		if err := validateHeader(key, value); err != nil {
			return nil, err
		}
		lines = append(lines, key+": "+value)
	}
	// Deterministic ordering so the sidecar file is stable across reinstalls
	// even when Go's map iteration order shifts.
	sort.Strings(lines)
	return lines, nil
}

// headerSidecarDir returns the operator-private directory where install writes
// header sidecar files. Operator-private (0o700) so other local users cannot
// read credential headers, even with /proc visibility. Shared by every
// integration so sidecars live in one predictable, lockable place.
func headerSidecarDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, ".config", "pipelock", "wrap-headers"), nil
}

// headerSidecarPath returns the absolute path of the sidecar file for the
// given (target config, server name) pair. The hash of the absolute config
// path keeps sidecars from different installations from colliding on a shared
// server name (e.g. two configs both declaring "remote"). The hash of the raw
// server name keeps names that sanitize to the same path component (e.g.
// "prod/api" and "prod_api") from sharing one sidecar.
func headerSidecarPath(targetConfigPath, serverName string) (string, error) {
	dir, err := headerSidecarDir()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(filepath.Clean(targetConfigPath))
	if err != nil {
		return "", fmt.Errorf("resolving config path for sidecar: %w", err)
	}
	configSum := sha256.Sum256([]byte(abs))
	configPrefix := hex.EncodeToString(configSum[:])[:16]
	serverSum := sha256.Sum256([]byte(serverName))
	serverPrefix := hex.EncodeToString(serverSum[:])[:16]
	safeName := sanitizeSidecarComponent(serverName)
	if len(safeName) > 80 {
		safeName = safeName[:80]
	}
	return filepath.Join(dir, configPrefix+"-"+serverPrefix+"-"+safeName+".headers"), nil
}

// validatedHeaderSidecarDeletePath resolves and containment-checks a sidecar
// path read from (untrusted) on-disk metadata before a delete. It rejects
// relative paths, paths not ending in .headers, and any path that escapes the
// sidecar dir (lexically or via symlink) so a tampered _pipelock block cannot
// turn remove into an arbitrary-file delete.
func validatedHeaderSidecarDeletePath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("invalid _pipelock metadata: header sidecar path must be absolute")
	}
	if !strings.HasSuffix(filepath.Base(path), ".headers") {
		return "", fmt.Errorf("invalid _pipelock metadata: header sidecar path must end in .headers")
	}
	dir, err := headerSidecarDir()
	if err != nil {
		return "", err
	}
	cleanDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", fmt.Errorf("resolving header sidecar dir: %w", err)
	}
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolving header sidecar path: %w", err)
	}
	if !pathWithinDir(cleanDir, cleanPath) {
		return "", fmt.Errorf("invalid _pipelock metadata: header sidecar path escapes %s", cleanDir)
	}

	resolvedDir := cleanDir
	if realDir, err := filepath.EvalSymlinks(cleanDir); err == nil {
		resolvedDir = realDir
	}
	if realPath, err := filepath.EvalSymlinks(cleanPath); err == nil {
		if !pathWithinDir(resolvedDir, realPath) {
			return "", fmt.Errorf("invalid _pipelock metadata: header sidecar path resolves outside %s", resolvedDir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("resolving header sidecar path symlinks: %w", err)
	}

	return cleanPath, nil
}

func pathWithinDir(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil || rel == "." || rel == "" {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// sanitizeSidecarComponent strips characters that have meaning in path
// segments so an attacker-named MCP server cannot redirect the sidecar
// elsewhere. Replace anything outside [A-Za-z0-9._-] with '_'.
func sanitizeSidecarComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// commitHeaderSidecar atomically writes a sidecar body to path at 0o600 under a
// 0o700 parent. This is the side-effecting half of the sidecar lifecycle; the
// deciding half is done by WrapServer/UnwrapServer, which produce a SidecarOp
// plan applied by ApplySidecarOps.
func commitHeaderSidecar(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating sidecar dir %s: %w", dir, err)
	}
	// MkdirAll creates the dir 0o700, but a pre-existing dir may be looser.
	// Refuse to write credential files into a directory group/others can enter
	// rather than silently widening exposure. (An os.Chmod to 0o700 would auto-
	// fix it, but gosec flags a 0o700 chmod and surfacing the misconfiguration
	// is the safer choice for a credential carrier.)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat sidecar dir %s: %w", dir, err)
	}
	if secperm.TooPermissive(info.Mode().Perm(), 0o077) {
		return fmt.Errorf("sidecar dir %s is too permissive (%04o); restrict it to 0700", dir, info.Mode().Perm())
	}

	tmp, err := os.CreateTemp(dir, ".headers-*.tmp")
	if err != nil {
		return fmt.Errorf("creating sidecar temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing sidecar temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing sidecar temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("setting sidecar permissions: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming sidecar into place: %w", err)
	}
	return nil
}

// removeHeaderSidecar deletes the sidecar file. An empty path or an
// already-absent file is not an error; any other removal failure is returned so
// callers can surface a credential file that could not be deleted.
func removeHeaderSidecar(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(filepath.Clean(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing header sidecar %s: %w", path, err)
	}
	return nil
}

// validateHeader rejects empty/invalid header names, reserved transport-managed
// headers, and invalid value characters. The reserved-header set mirrors the
// runtime proxy's parser (internal/cli/runtime/mcp.go): the proxy is the
// enforcing authority (it re-validates the sidecar at every startup), but
// checking here fails a bad install up front rather than at agent launch.
func validateHeader(key, value string) error {
	if key == "" {
		return fmt.Errorf("header key is empty")
	}
	if !validHeaderName(key) {
		return fmt.Errorf("header %q has invalid characters", key)
	}
	switch strings.ToLower(key) {
	case "content-type", "accept", "mcp-session-id", "content-length", "transfer-encoding", "host":
		return fmt.Errorf("header %q is managed by the MCP HTTP transport and cannot be passed through", key)
	}
	if !validHeaderValue(value) {
		return fmt.Errorf("header %q has invalid value characters", key)
	}
	return nil
}

func validHeaderName(key string) bool {
	// HTTP header names are ASCII tokens (RFC 7230 §3.2.6); iterate by byte so
	// any non-ASCII byte is rejected by isHTTPTokenChar.
	for i := 0; i < len(key); i++ {
		if !isHTTPTokenChar(key[i]) {
			return false
		}
	}
	return true
}

func isHTTPTokenChar(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func validHeaderValue(value string) bool {
	for _, r := range value {
		if r == '\t' || r == ' ' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
		if r > 127 && unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// AtomicWriteFile writes data to targetPath via a temp file in tmpDir + rename,
// at 0o600. tmpDir should be the target's directory so the rename stays on one
// filesystem (cross-device renames fail).
func AtomicWriteFile(targetPath string, data []byte, tmpDir string) error {
	tmpFile, err := os.CreateTemp(tmpDir, "mcpwrap-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming to %s: %w", targetPath, err)
	}
	return nil
}
