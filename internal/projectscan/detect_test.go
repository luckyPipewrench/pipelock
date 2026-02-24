package projectscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectAgent_ClaudeCode_DotClaude(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".claude"), 0o750); err != nil {
		t.Fatal(err)
	}
	if got := detectAgent(dir); got != AgentClaudeCode {
		t.Errorf("detectAgent = %q, want %q", got, AgentClaudeCode)
	}
}

func TestDetectAgent_ClaudeCode_CLAUDE_MD(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CLAUDE.md"), []byte("# Guide"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectAgent(dir); got != AgentClaudeCode {
		t.Errorf("detectAgent = %q, want %q", got, AgentClaudeCode)
	}
}

func TestDetectAgent_Cursor(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".cursor"), 0o750); err != nil {
		t.Fatal(err)
	}
	if got := detectAgent(dir); got != AgentCursor {
		t.Errorf("detectAgent = %q, want %q", got, AgentCursor)
	}
}

func TestDetectAgent_Cursor_Rules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".cursorrules"), []byte("rules"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectAgent(dir); got != AgentCursor {
		t.Errorf("detectAgent = %q, want %q", got, AgentCursor)
	}
}

func TestDetectAgent_CrewAI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("crewai>=0.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectAgent(dir); got != AgentCrewAI {
		t.Errorf("detectAgent = %q, want %q", got, AgentCrewAI)
	}
}

func TestDetectAgent_LangGraph_Python(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("langgraph\nopenai\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectAgent(dir); got != AgentLangGraph {
		t.Errorf("detectAgent = %q, want %q", got, AgentLangGraph)
	}
}

func TestDetectAgent_LangGraph_JS(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"dependencies": {"@langchain/langgraph": "^0.1.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectAgent(dir); got != AgentLangGraph {
		t.Errorf("detectAgent = %q, want %q", got, AgentLangGraph)
	}
}

func TestDetectAgent_AutoGen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("pyautogen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectAgent(dir); got != AgentAutoGen {
		t.Errorf("detectAgent = %q, want %q", got, AgentAutoGen)
	}
}

func TestDetectAgent_Generic(t *testing.T) {
	dir := t.TempDir()
	if got := detectAgent(dir); got != AgentGeneric {
		t.Errorf("detectAgent = %q, want %q", got, AgentGeneric)
	}
}

func TestDetectLanguages(t *testing.T) {
	dir := t.TempDir()
	files := map[string]int{
		"main.go":    3,
		"util.go":    0,
		"handler.go": 0,
		"app.py":     0,
		"test.js":    0,
	}
	for name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("// code"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	langs := detectLanguages(dir)
	if len(langs) == 0 {
		t.Fatal("expected at least one language")
	}
	if langs[0] != "Go" {
		t.Errorf("expected Go as top language, got %q", langs[0])
	}
}

func TestDetectLanguages_AllExtensions(t *testing.T) {
	dir := t.TempDir()
	// Exercise every switch branch in detectLanguages.
	for _, name := range []string{
		"main.go", "app.py", "index.js", "app.ts",
		"lib.rs", "server.rb", "App.java",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("//"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	langs := detectLanguages(dir)
	want := map[string]bool{
		"Go": true, "Python": true, "JavaScript": true,
		"TypeScript": true, "Rust": true, "Ruby": true, "Java": true,
	}
	got := make(map[string]bool)
	for _, l := range langs {
		got[l] = true
	}
	for lang := range want {
		if !got[lang] {
			t.Errorf("missing language %q", lang)
		}
	}
}

func TestDetectLanguages_WalkError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission-based test cannot run as root")
	}

	dir := t.TempDir()
	// Create an unreadable subdirectory to trigger the err != nil path
	// in the WalkDir callback.
	noread := filepath.Join(dir, "noperm")
	if err := os.Mkdir(noread, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(noread, 0o600) })

	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("//"), 0o600); err != nil {
		t.Fatal(err)
	}

	langs := detectLanguages(dir)
	// Should still detect Go from the readable file.
	if len(langs) == 0 || langs[0] != "Go" {
		t.Errorf("expected Go, got %v", langs)
	}
}

func TestDetectLanguages_SkipsDirs(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules", "pkg")
	if err := os.MkdirAll(nm, 0o750); err != nil {
		t.Fatal(err)
	}
	// Files in node_modules should be skipped
	if err := os.WriteFile(filepath.Join(nm, "index.js"), []byte("//"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("#"), 0o600); err != nil {
		t.Fatal(err)
	}

	langs := detectLanguages(dir)
	for _, l := range langs {
		if l == "JavaScript" {
			t.Error("should not detect JavaScript from node_modules")
		}
	}
}

func TestDetectLanguages_Empty(t *testing.T) {
	dir := t.TempDir()
	langs := detectLanguages(dir)
	if len(langs) != 0 {
		t.Errorf("expected no languages, got %v", langs)
	}
}

func TestDetectEcosystems(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"package.json", "go.mod"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ecos := detectEcosystems(dir)
	if len(ecos) != 2 {
		t.Fatalf("expected 2 ecosystems, got %d: %v", len(ecos), ecos)
	}

	found := make(map[string]bool)
	for _, e := range ecos {
		found[e] = true
	}
	if !found[EcoNPM] {
		t.Error("expected npm ecosystem")
	}
	if !found[EcoGoMod] {
		t.Error("expected go ecosystem")
	}
}

func TestDetectEcosystems_Empty(t *testing.T) {
	dir := t.TempDir()
	ecos := detectEcosystems(dir)
	if len(ecos) != 0 {
		t.Errorf("expected no ecosystems, got %v", ecos)
	}
}

func TestDetectMCPServers(t *testing.T) {
	dir := t.TempDir()
	mcp := `{
		"mcpServers": {
			"filesystem": {"command": "npx"},
			"postgres": {"command": "npx"},
			"github": {"command": "npx"}
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(mcp), 0o600); err != nil {
		t.Fatal(err)
	}

	servers := detectMCPServers(dir)
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d: %v", len(servers), servers)
	}
}

func TestDetectMCPServers_NoFile(t *testing.T) {
	dir := t.TempDir()
	servers := detectMCPServers(dir)
	if len(servers) != 0 {
		t.Errorf("expected no servers, got %v", servers)
	}
}

func TestDetectMCPServers_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	servers := detectMCPServers(dir)
	if len(servers) != 0 {
		t.Errorf("expected no servers from invalid JSON, got %v", servers)
	}
}

func TestHasGitRepo(t *testing.T) {
	dir := t.TempDir()
	if hasGitRepo(dir) {
		t.Error("expected no git repo in empty dir")
	}
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	if !hasGitRepo(dir) {
		t.Error("expected git repo after creating .git")
	}
}

func TestParsePythonRequirements(t *testing.T) {
	content := `
# comment
crewai>=0.1.0
openai==1.0
-r other.txt
langchain[llms]
`
	deps := parsePythonRequirements(content)
	found := make(map[string]bool)
	for _, d := range deps {
		found[d] = true
	}
	if !found["crewai"] {
		t.Error("expected crewai in deps")
	}
	if !found["openai"] {
		t.Error("expected openai in deps")
	}
	if !found["langchain"] {
		t.Error("expected langchain in deps")
	}
}

func TestHasDependency(t *testing.T) {
	dir := t.TempDir()
	pkg := `{"dependencies": {"express": "^4.0"}, "devDependencies": {"jest": "^29"}}`
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}

	if !hasDependency(path, "express") {
		t.Error("expected express to be found")
	}
	if !hasDependency(path, "jest") {
		t.Error("expected jest to be found in devDependencies")
	}
	if hasDependency(path, "react") {
		t.Error("did not expect react")
	}
}

func TestHasDependency_NoFile(t *testing.T) {
	if hasDependency("/nonexistent/package.json", "express") {
		t.Error("expected false for nonexistent file")
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if fileExists(path) {
		t.Error("file should not exist yet")
	}

	if err := os.WriteFile(path, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !fileExists(path) {
		t.Error("file should exist now")
	}

	// Directory should not count as file
	if fileExists(dir) {
		t.Error("directory should not count as file")
	}
}

func TestDirExists(t *testing.T) {
	dir := t.TempDir()
	if !dirExists(dir) {
		t.Error("temp dir should exist")
	}
	if dirExists(filepath.Join(dir, "nope")) {
		t.Error("nonexistent dir should not exist")
	}
}

func TestParsePyprojectDeps(t *testing.T) {
	content := `
[tool.poetry.dependencies]
python = "^3.9"
crewai = "^0.1"
langchain = "^0.2"
`
	deps := parsePyprojectDeps(content)
	found := make(map[string]bool)
	for _, d := range deps {
		found[d] = true
	}
	if !found["crewai"] {
		t.Error("expected crewai in deps")
	}
}

func TestDetectAgent_Pyproject(t *testing.T) {
	dir := t.TempDir()
	content := `[tool.poetry.dependencies]
crewai = "^0.1"
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectAgent(dir); got != AgentCrewAI {
		t.Errorf("detectAgent = %q, want %q", got, AgentCrewAI)
	}
}
