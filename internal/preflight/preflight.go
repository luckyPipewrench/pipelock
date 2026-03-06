// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevWarning  = "warning"
	SevInfo     = "info"
)

const (
	CatHookRCE      = "hook_rce"
	CatMCPServerRCE = "mcp_server_rce"
	CatCredRedirect = "cred_redirect"
	CatAutoApproval = "auto_approval"
	CatObfuscation  = "obfuscation"
	CatConfig       = "config"
)

const maxFileBytes = 1 << 20 // 1 MB

// Report is the result of a preflight scan.
type Report struct {
	Version      string                `json:"version"`
	Directory    string                `json:"directory"`
	FilesScanned []string              `json:"files_scanned"`
	Findings     []projectscan.Finding `json:"findings"`
	Summary      Summary               `json:"summary"`
}

// Summary counts findings by severity.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
}

// RecomputeSummary recalculates the Summary from current Findings.
func (r *Report) RecomputeSummary() {
	r.Summary = Summary{}
	for _, f := range r.Findings {
		switch f.Severity {
		case SevCritical:
			r.Summary.Critical++
		case SevHigh:
			r.Summary.High++
		case SevWarning:
			r.Summary.Warning++
		default:
			r.Summary.Info++
		}
	}
}

// configTarget defines a config file to scan and its parser.
type configTarget struct {
	relPath  string
	parser   func(data []byte, filePath string) []projectscan.Finding
	warnInCI bool // if true and --ci is set and file exists, emit warning (shouldn't be committed)
}

// Option configures Scan behavior.
type Option func(*scanOpts)

type scanOpts struct {
	ci bool
}

// WithCI enables CI mode (stricter exit, warn on committed local settings).
func WithCI() Option {
	return func(o *scanOpts) { o.ci = true }
}

// Scan scans dir for dangerous AI agent config files.
func Scan(dir string, opts ...Option) (*Report, error) {
	var o scanOpts
	for _, fn := range opts {
		fn(&o)
	}

	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	// Canonicalize repo root ONCE. All path checks use this value.
	// No raw/resolved path mixing after this point.
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s: %w", dir, err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s: %w", dir, err)
	}

	r := &Report{Directory: dir}

	targets := []configTarget{
		{relPath: filepath.Join(".claude", "settings.json"), parser: parseClaudeSettings},
		{relPath: filepath.Join(".claude", "settings.local.json"), parser: parseClaudeSettings, warnInCI: true},
		{relPath: ".mcp.json", parser: parseMCPJSON},
		{relPath: filepath.Join(".cursor", "hooks.json"), parser: parseCursorHooks},
		{relPath: filepath.Join(".cursor", "mcp.json"), parser: parseMCPJSON},
	}

	for _, t := range targets {
		// Safe read: full path component symlink check + size limit + repo confinement.
		// Uses canonicalRoot for all comparisons (no raw/resolved mixing).
		data, safeFindings := safeRead(canonicalRoot, t.relPath)
		if len(safeFindings) > 0 {
			r.Findings = append(r.Findings, safeFindings...)
			r.FilesScanned = append(r.FilesScanned, t.relPath)
			continue
		}
		if data == nil {
			continue // file doesn't exist
		}

		// In CI, warn if a .local settings file is committed (it should be gitignored).
		// Still scan its contents: a committed .local file could contain malicious entries.
		if o.ci && t.warnInCI {
			r.Findings = append(r.Findings, projectscan.Finding{
				Severity: SevWarning,
				Category: CatConfig,
				Message:  fmt.Sprintf("%s is committed but should be gitignored: review contents", t.relPath),
				File:     t.relPath,
			})
		}

		r.FilesScanned = append(r.FilesScanned, t.relPath)
		r.Findings = append(r.Findings, t.parser(data, t.relPath)...)
	}

	// Scan .claude/commands/*.md (warning-level only).
	// Pre-validate the commands directory path before ReadDir to prevent
	// symlink-based traversal into external trees.
	commandsRelDir := filepath.Join(".claude", "commands")
	commandsDirParts := strings.Split(filepath.ToSlash(commandsRelDir), "/")
	commandsDirSafe := true
	for i := range commandsDirParts {
		partial := filepath.Join(canonicalRoot, filepath.Join(commandsDirParts[:i+1]...))
		linfo, lErr := os.Lstat(partial)
		if lErr != nil {
			if !os.IsNotExist(lErr) {
				// Directory exists but unreadable: fail-closed.
				r.Findings = append(r.Findings, projectscan.Finding{
					Severity: SevCritical,
					Category: CatConfig,
					Message:  fmt.Sprintf("unreadable commands directory prevents security analysis: %s: %s", commandsRelDir, lErr),
					File:     commandsRelDir,
				})
			}
			commandsDirSafe = false
			break
		}
		if linfo.Mode()&os.ModeSymlink != 0 {
			component := filepath.Join(commandsDirParts[:i+1]...)
			r.Findings = append(r.Findings, projectscan.Finding{
				Severity: SevCritical,
				Category: CatConfig,
				Message:  fmt.Sprintf("symlink detected at %s: symlinks in config paths prevent security analysis", component),
				File:     commandsRelDir,
			})
			commandsDirSafe = false
			break
		}
	}

	if commandsDirSafe {
		commandsDir := filepath.Join(canonicalRoot, commandsRelDir)
		entries, readDirErr := os.ReadDir(commandsDir)
		if readDirErr != nil && !os.IsNotExist(readDirErr) {
			// Directory exists but ReadDir failed (permission denied, etc.): fail-closed.
			r.Findings = append(r.Findings, projectscan.Finding{
				Severity: SevCritical,
				Category: CatConfig,
				Message:  fmt.Sprintf("unreadable commands directory prevents security analysis: %s: %s", commandsRelDir, readDirErr),
				File:     commandsRelDir,
			})
		}
		if readDirErr == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
					continue
				}
				relPath := filepath.Join(".claude", "commands", e.Name())

				// Apply same safeRead checks to slash commands (symlink, size, confinement)
				_, cmdFindings := safeRead(canonicalRoot, relPath)
				if len(cmdFindings) > 0 {
					r.Findings = append(r.Findings, cmdFindings...)
					r.FilesScanned = append(r.FilesScanned, relPath)
					continue
				}

				r.FilesScanned = append(r.FilesScanned, relPath)
				r.Findings = append(r.Findings, projectscan.Finding{
					Severity: SevWarning,
					Category: CatConfig,
					Message:  fmt.Sprintf("custom slash command: %s (review for unexpected behavior)", e.Name()),
					File:     relPath,
				})
			}
		}
	}

	// If zero files found: info finding
	if len(r.FilesScanned) == 0 && len(r.Findings) == 0 {
		r.Findings = append(r.Findings, projectscan.Finding{
			Severity: SevInfo,
			Category: CatConfig,
			Message:  "no AI agent config files found in this repository",
		})
	}

	r.RecomputeSummary()
	return r, nil
}

// safeRead validates a config file before reading.
// canonicalRoot is the pre-resolved repo root (computed once in Scan()).
// Checks EVERY path component for symlinks (not just the leaf).
// Rejects files > maxFileBytes with high severity (blocks CI gate).
// Unreadable files that exist get critical severity (fail-closed).
// Returns data or nil + findings.
func safeRead(canonicalRoot, relPath string) ([]byte, []projectscan.Finding) {
	// Check every path component for symlinks.
	// For relPath ".claude/settings.json", check:
	//   canonicalRoot/.claude (is it a symlink?)
	//   canonicalRoot/.claude/settings.json (is it a symlink?)
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	for i := range parts {
		partial := filepath.Join(canonicalRoot, filepath.Join(parts[:i+1]...))
		linfo, err := os.Lstat(partial)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil // file doesn't exist
			}
			// File exists but Lstat failed (permission denied, etc.)
			return nil, []projectscan.Finding{{
				Severity: SevCritical,
				Category: CatConfig,
				Message:  fmt.Sprintf("unreadable config prevents security analysis: %s: %s", relPath, err),
				File:     relPath,
			}}
		}
		if linfo.Mode()&os.ModeSymlink != 0 {
			component := filepath.Join(parts[:i+1]...)
			return nil, []projectscan.Finding{{
				Severity: SevCritical,
				Category: CatConfig,
				Message:  fmt.Sprintf("symlink detected at %s: symlinks in config paths prevent security analysis", component),
				File:     relPath,
			}}
		}
	}

	fullPath := filepath.Join(canonicalRoot, relPath)

	// Repo-root confinement: resolve and verify path stays under canonicalRoot.
	// Use filepath.Rel (NOT strings.HasPrefix) to prevent /repo matching /repo-evil.
	resolved, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []projectscan.Finding{{
			Severity: SevCritical,
			Category: CatConfig,
			Message:  fmt.Sprintf("unreadable config prevents security analysis: %s: %s", relPath, err),
			File:     relPath,
		}}
	}
	rel, err := filepath.Rel(canonicalRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, []projectscan.Finding{{
			Severity: SevCritical,
			Category: CatConfig,
			Message:  fmt.Sprintf("config path escapes repo root: %s resolves outside %s", relPath, canonicalRoot),
			File:     relPath,
		}}
	}

	// Size check: high severity (not warning) so --ci fails on evasion attempt
	finfo, err := os.Stat(resolved)
	if err != nil {
		return nil, []projectscan.Finding{{
			Severity: SevCritical,
			Category: CatConfig,
			Message:  fmt.Sprintf("unreadable config prevents security analysis: %s: %s", relPath, err),
			File:     relPath,
		}}
	}
	if finfo.Size() > maxFileBytes {
		return nil, []projectscan.Finding{{
			Severity: SevHigh,
			Category: CatConfig,
			Message:  fmt.Sprintf("config file exceeds 1 MB limit: %s (%d bytes), cannot verify safety", relPath, finfo.Size()),
			File:     relPath,
		}}
	}

	data, err := os.ReadFile(filepath.Clean(resolved))
	if err != nil {
		// Fail-closed: targeted file exists but can't be read = critical.
		// Prevents evasion via restrictive permissions on malicious config.
		return nil, []projectscan.Finding{{
			Severity: SevCritical,
			Category: CatConfig,
			Message:  fmt.Sprintf("unreadable config prevents security analysis: %s: %s", relPath, err),
			File:     relPath,
		}}
	}

	return data, nil
}
