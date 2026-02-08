package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateDockerCompose_AllAgentTypes(t *testing.T) {
	for _, agent := range []string{"generic", "claude-code", "openhands"} {
		t.Run(agent, func(t *testing.T) {
			tmpl, err := composeTemplate(agent)
			if err != nil {
				t.Fatalf("composeTemplate(%q) error: %v", agent, err)
			}
			if tmpl == "" {
				t.Fatal("expected non-empty template")
			}
			// All templates must include pipelock service and internal network
			if !strings.Contains(tmpl, "pipelock-internal:") {
				t.Error("expected pipelock-internal network")
			}
			if !strings.Contains(tmpl, "internal: true") {
				t.Error("expected internal: true on isolated network")
			}
			if !strings.Contains(tmpl, "ghcr.io/luckypipewrench/pipelock:latest") {
				t.Error("expected pipelock image reference")
			}
			if !strings.Contains(tmpl, "PIPELOCK_FETCH_URL=http://pipelock:8888/fetch") {
				t.Error("expected PIPELOCK_FETCH_URL env var in agent service")
			}
			if !strings.Contains(tmpl, "condition: service_healthy") {
				t.Error("expected healthcheck dependency")
			}
		})
	}
}

func TestGenerateDockerCompose_UnknownAgent(t *testing.T) {
	_, err := composeTemplate("nonexistent")
	if err == nil {
		t.Error("expected error for unknown agent type")
	}
}

func TestGenerateDockerCompose_GenericTemplate(t *testing.T) {
	tmpl, err := composeTemplate("generic")
	if err != nil {
		t.Fatal(err)
	}

	// Generic should have placeholder build context
	if !strings.Contains(tmpl, "build: .") {
		t.Error("expected build context placeholder in generic template")
	}
	// Should NOT include volumes section (no named volumes)
	if strings.Contains(tmpl, "volumes:\n  claude-cache:") {
		t.Error("generic template should not include claude-cache volume")
	}
}

func TestGenerateDockerCompose_ClaudeCodeTemplate(t *testing.T) {
	tmpl, err := composeTemplate("claude-code")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(tmpl, "node:22-slim") {
		t.Error("expected node:22-slim base image")
	}
	if !strings.Contains(tmpl, "stdin_open: true") {
		t.Error("expected stdin_open for interactive TTY")
	}
	if !strings.Contains(tmpl, "tty: true") {
		t.Error("expected tty for interactive TTY")
	}
	if !strings.Contains(tmpl, "@anthropic-ai/claude-code") {
		t.Error("expected claude-code entrypoint")
	}
	if !strings.Contains(tmpl, "claude-cache:") {
		t.Error("expected claude-cache volume for npm cache")
	}
}

func TestGenerateDockerCompose_OpenhandsTemplate(t *testing.T) {
	tmpl, err := composeTemplate("openhands")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(tmpl, "all-hands-ai/openhands") {
		t.Error("expected openhands image reference")
	}
	if !strings.Contains(tmpl, "3000:3000") {
		t.Error("expected port 3000 mapping for openhands UI")
	}
	if !strings.Contains(tmpl, "SANDBOX_NETWORK_MODE=none") {
		t.Error("expected sandbox network mode none for openhands")
	}
}

func TestGenerateDockerCompose_NetworkIsolation(t *testing.T) {
	tmpl, err := composeTemplate("generic")
	if err != nil {
		t.Fatal(err)
	}

	// Pipelock must be on both networks
	pipelockSection := extractServiceSection(tmpl, "pipelock:")
	if !strings.Contains(pipelockSection, "pipelock-internal") {
		t.Error("pipelock must be on internal network")
	}
	if !strings.Contains(pipelockSection, "pipelock-external") {
		t.Error("pipelock must be on external network")
	}

	// Agent must be on internal network ONLY
	agentSection := extractServiceSection(tmpl, "agent:")
	if !strings.Contains(agentSection, "pipelock-internal") {
		t.Error("agent must be on internal network")
	}
	if strings.Contains(agentSection, "pipelock-external") {
		t.Error("agent must NOT be on external network")
	}
}

func TestGenerateDockerCompose_PipelockListenAddress(t *testing.T) {
	tmpl, err := composeTemplate("generic")
	if err != nil {
		t.Fatal(err)
	}

	// Must use 0.0.0.0 not 127.0.0.1 for cross-container access
	if !strings.Contains(tmpl, "0.0.0.0:8888") {
		t.Error("pipelock must listen on 0.0.0.0 for cross-container access")
	}
}

func TestGenerateDockerComposeCmd_Stdout(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "docker-compose"})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	_, _ = w.Close(), r.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateDockerComposeCmd_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "docker-compose.yaml")

	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "docker-compose", "--output", outPath})
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(outPath) //nolint:gosec // test reads its own temp file
	if err != nil {
		t.Fatalf("expected output file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty output file")
	}
	if !strings.Contains(string(data), "pipelock-internal:") {
		t.Error("expected compose content in output file")
	}
}

func TestGenerateDockerComposeCmd_InvalidAgent(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "docker-compose", "--agent", "unknown"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for unknown agent type")
	}
}

func TestGenerateDockerComposeCmd_Help(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"generate", "docker-compose", "--help"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "--agent") {
		t.Error("expected --agent flag in help")
	}
	if !strings.Contains(output, "claude-code") {
		t.Error("expected claude-code in help")
	}
	if !strings.Contains(output, "openhands") {
		t.Error("expected openhands in help")
	}
}

// extractServiceSection returns the YAML block for a given service name.
func extractServiceSection(compose, serviceName string) string {
	idx := strings.Index(compose, "  "+serviceName)
	if idx < 0 {
		return ""
	}
	rest := compose[idx:]
	// Find next top-level service (2-space indent followed by a non-space char)
	lines := strings.Split(rest, "\n")
	var section []string
	for i, line := range lines {
		if i == 0 {
			section = append(section, line)
			continue
		}
		// Stop at next service definition or section (non-indented or 2-space indent with content)
		if len(line) > 0 && line[0] != ' ' {
			break
		}
		if strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ' && strings.HasSuffix(strings.TrimSpace(line), ":") {
			break
		}
		section = append(section, line)
	}
	return strings.Join(section, "\n")
}
