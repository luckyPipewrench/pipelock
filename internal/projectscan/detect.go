package projectscan

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Agent type constants.
const (
	AgentClaudeCode = "claude-code"
	AgentCursor     = "cursor"
	AgentCrewAI     = "crewai"
	AgentLangGraph  = "langgraph"
	AgentAutoGen    = "autogen"
	AgentGeneric    = "generic"
)

// detectAgent identifies the agent type from project markers.
func detectAgent(dir string) string {
	// Claude Code markers
	if dirExists(filepath.Join(dir, ".claude")) || fileExists(filepath.Join(dir, "CLAUDE.md")) {
		return AgentClaudeCode
	}

	// Cursor markers
	if dirExists(filepath.Join(dir, ".cursor")) || fileExists(filepath.Join(dir, ".cursorrules")) {
		return AgentCursor
	}

	// Framework markers in Python requirements
	if deps := readPythonDeps(dir); len(deps) > 0 {
		for _, dep := range deps {
			switch {
			case strings.HasPrefix(dep, "crewai"):
				return AgentCrewAI
			case strings.HasPrefix(dep, "langgraph"):
				return AgentLangGraph
			case strings.HasPrefix(dep, "autogen") || strings.HasPrefix(dep, "pyautogen"):
				return AgentAutoGen
			}
		}
	}

	// LangGraph in package.json
	if hasDependency(filepath.Join(dir, "package.json"), "@langchain/langgraph") {
		return AgentLangGraph
	}

	return AgentGeneric
}

// detectLanguages counts file extensions to identify languages.
func detectLanguages(dir string) []string {
	counts := make(map[string]int)
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(d.Name())
		switch ext {
		case ".py":
			counts["Python"]++
		case ".js":
			counts["JavaScript"]++
		case ".ts":
			counts["TypeScript"]++
		case ".go":
			counts["Go"]++
		case ".rs":
			counts["Rust"]++
		case ".rb":
			counts["Ruby"]++
		case ".java":
			counts["Java"]++
		}
		return nil
	})

	// Return languages sorted by count (descending)
	type langCount struct {
		name  string
		count int
	}
	var langs []langCount
	for name, count := range counts {
		langs = append(langs, langCount{name, count})
	}
	// Simple insertion sort -- small slice
	for i := 1; i < len(langs); i++ {
		for j := i; j > 0 && langs[j].count > langs[j-1].count; j-- {
			langs[j], langs[j-1] = langs[j-1], langs[j]
		}
	}

	result := make([]string, len(langs))
	for i, l := range langs {
		result[i] = l.name
	}
	return result
}

// Ecosystem constants.
const (
	EcoNPM      = "npm"
	EcoPip      = "pip"
	EcoGoMod    = "go"
	EcoCargo    = "cargo"
	EcoRubyGems = "rubygems"
	EcoMaven    = "maven"
)

// ecosystemDomains maps each ecosystem to domains that should be allowlisted.
var ecosystemDomains = map[string][]string{
	EcoNPM:      {"registry.npmjs.org", "*.npmjs.com"},
	EcoPip:      {"pypi.org", "*.python.org", "*.pythonhosted.org"},
	EcoGoMod:    {"pkg.go.dev", "proxy.golang.org", "sum.golang.org"},
	EcoCargo:    {"crates.io", "*.crates.io", "*.docs.rs"},
	EcoRubyGems: {"*.rubygems.org"},
	EcoMaven:    {"*.maven.org"},
}

// detectEcosystems identifies package ecosystems from manifest files.
func detectEcosystems(dir string) []string {
	var ecos []string
	checks := []struct {
		files []string
		eco   string
	}{
		{[]string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}, EcoNPM},
		{[]string{"requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"}, EcoPip},
		{[]string{"go.mod"}, EcoGoMod},
		{[]string{"Cargo.toml", "Cargo.lock"}, EcoCargo},
		{[]string{"Gemfile", "Gemfile.lock"}, EcoRubyGems},
		{[]string{"pom.xml", "build.gradle", "build.gradle.kts"}, EcoMaven},
	}

	for _, c := range checks {
		for _, f := range c.files {
			if fileExists(filepath.Join(dir, f)) {
				ecos = append(ecos, c.eco)
				break
			}
		}
	}
	return ecos
}

// mcpConfig represents the structure of .mcp.json files.
type mcpConfig struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
}

// detectMCPServers reads .mcp.json and returns server names.
func detectMCPServers(dir string) []string {
	path := filepath.Join(dir, ".mcp.json")
	data, err := os.ReadFile(path) //nolint:gosec // G304: controlled path
	if err != nil {
		return nil
	}

	var cfg mcpConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}

	servers := make([]string, 0, len(cfg.MCPServers))
	for name := range cfg.MCPServers {
		servers = append(servers, name)
	}
	return servers
}

// hasGitRepo checks for a .git directory.
func hasGitRepo(dir string) bool {
	return dirExists(filepath.Join(dir, ".git"))
}

// readPythonDeps reads dependency names from requirements.txt or pyproject.toml.
func readPythonDeps(dir string) []string {
	// Try requirements.txt first
	path := filepath.Join(dir, "requirements.txt")
	data, err := os.ReadFile(path) //nolint:gosec // G304: controlled path
	if err == nil {
		return parsePythonRequirements(string(data))
	}

	// Try pyproject.toml dependencies section (simplified)
	path = filepath.Join(dir, "pyproject.toml")
	data, err = os.ReadFile(path) //nolint:gosec // G304: controlled path
	if err == nil {
		return parsePyprojectDeps(string(data))
	}

	return nil
}

func parsePythonRequirements(content string) []string {
	var deps []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Extract package name before version specifier
		for i, ch := range line {
			if ch == '=' || ch == '>' || ch == '<' || ch == '!' || ch == '[' || ch == ';' {
				line = line[:i]
				break
			}
		}
		dep := strings.TrimSpace(strings.ToLower(line))
		if dep != "" {
			deps = append(deps, dep)
		}
	}
	return deps
}

func parsePyprojectDeps(content string) []string {
	// Simplified: look for lines that contain known framework names
	lower := strings.ToLower(content)
	var deps []string
	for _, name := range []string{"crewai", "langgraph", "autogen", "pyautogen"} {
		if strings.Contains(lower, name) {
			deps = append(deps, name)
		}
	}
	return deps
}

// hasDependency checks if a package.json contains a dependency.
func hasDependency(path, pkg string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // G304: controlled path
	if err != nil {
		return false
	}

	var pj struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return false
	}

	if _, ok := pj.Dependencies[pkg]; ok {
		return true
	}
	_, ok := pj.DevDependencies[pkg]
	return ok
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
