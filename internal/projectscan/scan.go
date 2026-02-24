// Package projectscan implements project directory scanning for the
// pipelock audit command. It detects agent types, programming languages,
// package ecosystems, MCP servers, and secrets to generate a suggested
// Pipelock config.
package projectscan

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const severityCritical = "critical"

// Finding represents a single security finding from the project scan.
type Finding struct {
	Severity string `json:"severity"` // critical, warning, info
	Category string `json:"category"` // secret, config, ecosystem, agent
	Message  string `json:"message"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
}

// Report is the full result of scanning a project directory.
type Report struct {
	Dir        string      `json:"directory"`
	AgentType  string      `json:"agent_type"`
	Languages  []string    `json:"languages"`
	Ecosystems []string    `json:"ecosystems"`
	MCPServers []string    `json:"mcp_servers,omitempty"`
	Findings   []Finding   `json:"findings"`
	Score      int         `json:"score"`
	ScoreWith  int         `json:"score_with_config"`
	Config     *SuggestCfg `json:"-"`
}

// SuggestCfg holds the suggested config and metadata for rendering.
type SuggestCfg struct {
	Preset       string
	ExtraDomains []string
	ExtraDLP     []config.DLPPattern
	GitEnabled   bool
}

// skipDirs are directories that should never be scanned for secrets.
var skipDirs = map[string]bool{
	"node_modules":  true,
	"venv":          true,
	".venv":         true,
	".git":          true,
	"__pycache__":   true,
	"target":        true,
	"vendor":        true,
	"dist":          true,
	"build":         true,
	".next":         true,
	".nuxt":         true,
	".tox":          true,
	".mypy_cache":   true,
	".pytest_cache": true,
}

// secretFileExts are file extensions worth scanning for secrets.
var secretFileExts = map[string]bool{
	".env":        true,
	".yaml":       true,
	".yml":        true,
	".json":       true,
	".toml":       true,
	".ini":        true,
	".conf":       true,
	".cfg":        true,
	".properties": true,
}

// AdjustScoreForFindings recomputes ScoreWith based on the current Findings
// slice. Call this after filtering findings (e.g. via --exclude) so the
// penalty for critical findings stays consistent with what is reported.
func (r *Report) AdjustScoreForFindings() {
	r.ScoreWith = computeScore(r.Config)
	for _, f := range r.Findings {
		if f.Severity == severityCritical {
			r.ScoreWith -= 5
		}
	}
	if r.ScoreWith < 0 {
		r.ScoreWith = 0
	}
}

// Scan walks the project directory and produces a Report.
func Scan(dir string) (*Report, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	r := &Report{Dir: dir}

	// Detect agent type, languages, ecosystems, MCP servers
	r.AgentType = detectAgent(dir)
	r.Languages = detectLanguages(dir)
	r.Ecosystems = detectEcosystems(dir)
	r.MCPServers = detectMCPServers(dir)

	// Add info findings for detected items
	if r.AgentType != "generic" {
		r.Findings = append(r.Findings, Finding{
			Severity: "info",
			Category: "agent",
			Message:  fmt.Sprintf("Detected agent type: %s", r.AgentType),
		})
	}
	for _, eco := range r.Ecosystems {
		r.Findings = append(r.Findings, Finding{
			Severity: "info",
			Category: "ecosystem",
			Message:  fmt.Sprintf("Detected package ecosystem: %s", eco),
		})
	}
	if len(r.MCPServers) > 0 {
		r.Findings = append(r.Findings, Finding{
			Severity: "info",
			Category: "config",
			Message:  fmt.Sprintf("Found .mcp.json with %d server(s): %s", len(r.MCPServers), strings.Join(r.MCPServers, ", ")),
		})
	}
	if hasGitRepo(dir) {
		r.Findings = append(r.Findings, Finding{
			Severity: "info",
			Category: "config",
			Message:  "Git repository detected",
		})
	}

	// Compile DLP patterns once for both scans
	patterns := compileDLPPatterns()

	// Scan for secrets in environment
	envFindings := scanEnvSecrets(patterns)
	r.Findings = append(r.Findings, envFindings...)

	// Scan files for secrets
	fileFindings := scanFiles(dir, patterns)
	r.Findings = append(r.Findings, fileFindings...)

	// Build suggestion and compute scores
	r.Config = buildSuggestion(r)
	r.Score = computeScore(nil)
	r.ScoreWith = computeScore(r.Config)

	// Penalize "with config" score for critical findings that need manual remediation.
	// A suggested config enables protections but doesn't fix existing leaked secrets.
	for _, f := range r.Findings {
		if f.Severity == severityCritical {
			r.ScoreWith -= 5
		}
	}
	if r.ScoreWith < 0 {
		r.ScoreWith = 0
	}

	return r, nil
}

// scanEnvSecrets checks environment variables against DLP patterns.
func scanEnvSecrets(patterns []compiledDLP) []Finding {
	var findings []Finding

	// All secret matches are critical in audit context regardless of DLP pattern severity.
	// Pattern severity applies to proxy runtime scanning, not project auditing.
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 || len(parts[1]) < 8 {
			continue
		}
		name := parts[0]
		value := parts[1]

		for _, p := range patterns {
			if p.re.MatchString(value) {
				findings = append(findings, Finding{
					Severity: severityCritical,
					Category: "secret",
					Message:  fmt.Sprintf("API key found in environment: %s (%s)", name, p.name),
					Pattern:  p.name,
				})
				break // one match per env var is enough
			}
		}
	}

	return findings
}

type compiledDLP struct {
	name string
	re   *regexp.Regexp
}

func compileDLPPatterns() []compiledDLP {
	defaults := config.Defaults()
	patterns := make([]compiledDLP, 0, len(defaults.DLP.Patterns))
	for _, p := range defaults.DLP.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		patterns = append(patterns, compiledDLP{name: p.Name, re: re})
	}
	return patterns
}

// scanFiles walks the directory and scans config/env files for secrets.
func scanFiles(dir string, patterns []compiledDLP) []Finding {
	var findings []Finding

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Check file extension or basename
		base := d.Name()
		ext := filepath.Ext(base)
		isEnvFile := base == ".env" || strings.HasPrefix(base, ".env.")
		if !isEnvFile && !secretFileExts[ext] {
			return nil
		}

		// Skip large files (>1MB)
		info, err := d.Info()
		if err != nil || info.Size() > 1<<20 {
			return nil
		}

		relPath, _ := filepath.Rel(dir, path)
		if relPath == "" {
			relPath = path
		}

		fileFindings := scanFileForSecrets(path, relPath, patterns)
		findings = append(findings, fileFindings...)

		// Also check for high-entropy values in .env files
		if isEnvFile {
			entropyFindings := scanFileForEntropy(path, relPath)
			findings = append(findings, entropyFindings...)
		}

		return nil
	})

	return findings
}

func scanFileForSecrets(path, relPath string, patterns []compiledDLP) []Finding {
	f, err := os.Open(path) //nolint:gosec // G304: path from caller-controlled dir walk
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck // read-only file

	var findings []Finding
	s := bufio.NewScanner(f)
	lineNum := 0
	for s.Scan() {
		lineNum++
		line := s.Text()
		for _, p := range patterns {
			if p.re.MatchString(line) {
				findings = append(findings, Finding{
					Severity: severityCritical,
					Category: "secret",
					Message:  fmt.Sprintf("Secret pattern match: %s", p.name),
					File:     relPath,
					Line:     lineNum,
					Pattern:  p.name,
				})
				break // one match per line
			}
		}
	}

	return findings
}

func scanFileForEntropy(path, relPath string) []Finding {
	f, err := os.Open(path) //nolint:gosec // G304: path from caller-controlled dir walk
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck // read-only file

	const entropyThreshold = 4.5
	const minValueLen = 16

	var findings []Finding
	s := bufio.NewScanner(f)
	lineNum := 0
	for s.Scan() {
		lineNum++
		line := s.Text()

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.TrimSpace(parts[1])
		// Strip surrounding quotes
		value = strings.Trim(value, `"'`)
		if len(value) < minValueLen {
			continue
		}

		entropy := scanner.ShannonEntropy(value)
		if entropy > entropyThreshold {
			findings = append(findings, Finding{
				Severity: "warning",
				Category: "secret",
				Message:  fmt.Sprintf("High-entropy value (%.1f bits): %s", entropy, redact(value)),
				File:     relPath,
				Line:     lineNum,
			})
		}
	}

	return findings
}

// redact shows the first 8 characters followed by "...".
func redact(s string) string {
	r := []rune(s)
	if len(r) <= 8 {
		return "***"
	}
	return string(r[:8]) + "..."
}
