package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/gitprotect"
	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

// Runtime-built credential-like strings to avoid tripping pipelock's own
// security scanner in CI (scan-diff mode).
//
//nolint:goconst // test values, intentionally duplicated across helpers
var (
	fakeToken    = "@" + "to" + "ken = to" + "ken" // looks like cred-in-url pattern
	fakeAPIKey   = "api" + "Key = getKey()"        // ditto
	fakePassword = "pass" + `word = env("PASS")`   // ditto
	fakeCredURL  = "pass" + "word=secret123"       // Credential in URL
	fakeAntKey1  = "sk-" + "ant-test123456"        // Anthropic API Key
	fakeAntKey2  = "sk-" + "ant-other12345"        // Anthropic API Key
)

func TestSuppressRe(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		match    bool
		wantRule string
	}{
		{
			name:     "hash bare ignore",
			line:     fakeToken + ` # pipelock:ignore`,
			match:    true,
			wantRule: "",
		},
		{
			name:     "hash with rule name",
			line:     fakeToken + ` # pipelock:ignore Anthropic API Key`,
			match:    true,
			wantRule: "Anthropic API Key",
		},
		{
			name:     "slash bare ignore",
			line:     `apiKey := os.Getenv("API_KEY") // pipelock:ignore`,
			match:    true,
			wantRule: "",
		},
		{
			name:     "slash with rule name",
			line:     `apiKey := os.Getenv("API_KEY") // pipelock:ignore credential-in-url`,
			match:    true,
			wantRule: "credential-in-url",
		},
		{
			name:     "no comment",
			line:     `apiKey := os.Getenv("API_KEY")`,
			match:    false,
			wantRule: "",
		},
		{
			name:     "pipelock without ignore",
			line:     `// pipelock:suppress this line`,
			match:    false,
			wantRule: "",
		},
		{
			name:     "extra whitespace around comment",
			line:     `val = x  //   pipelock:ignore   Credential in URL  `,
			match:    true,
			wantRule: "Credential in URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := suppressRe.FindStringSubmatch(tt.line)
			if tt.match && m == nil {
				t.Errorf("expected match for %q", tt.line)
				return
			}
			if !tt.match && m != nil {
				t.Errorf("expected no match for %q, got %v", tt.line, m)
				return
			}
			if tt.match {
				got := strings.TrimSpace(m[1])
				if got != tt.wantRule {
					t.Errorf("expected rule %q, got %q", tt.wantRule, got)
				}
			}
		})
	}
}

func TestReadSourceLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.go")
	content := "line one\nline two\nline three\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		line    int
		want    string
		wantErr bool
	}{
		{name: "first line", line: 1, want: "line one"},
		{name: "second line", line: 2, want: "line two"},
		{name: "third line", line: 3, want: "line three"},
		{name: "out of range", line: 5, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readSourceLine(path, tt.line)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for line %d", tt.line)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestReadSourceLine_NonexistentFile(t *testing.T) {
	_, err := readSourceLine("/nonexistent/file.go", 1)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestCheckInlineSuppression(t *testing.T) {
	dir := t.TempDir()

	// Create a file with inline suppression comments.
	// Content built at runtime to avoid triggering the security scanner.
	path := filepath.Join(dir, "app.rb")
	content := strings.Join([]string{
		"require 'something'",
		fakeToken + " # pipelock:ignore Credential in URL",
		fakeAPIKey + " # pipelock:ignore",
		"normal_line = true",
		fakePassword + " // pipelock:ignore Wrong Rule",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		file       string
		line       int
		rule       string
		suppressed bool
	}{
		{
			name:       "matching rule suppressed",
			file:       path,
			line:       2,
			rule:       "Credential in URL",
			suppressed: true,
		},
		{
			name:       "bare ignore suppresses any rule",
			file:       path,
			line:       3,
			rule:       "Anthropic API Key",
			suppressed: true,
		},
		{
			name:       "normal line not suppressed",
			file:       path,
			line:       4,
			rule:       "Credential in URL",
			suppressed: false,
		},
		{
			name:       "wrong rule not suppressed",
			file:       path,
			line:       5,
			rule:       "Credential in URL",
			suppressed: false,
		},
		{
			name:       "empty file path skipped",
			file:       "",
			line:       1,
			rule:       "test",
			suppressed: false,
		},
		{
			name:       "zero line skipped",
			file:       path,
			line:       0,
			rule:       "test",
			suppressed: false,
		},
		{
			name:       "nonexistent file skipped",
			file:       filepath.Join(dir, "nope.go"),
			line:       1,
			rule:       "test",
			suppressed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := checkInlineSuppression(tt.file, tt.line, tt.rule)
			if r.suppressed != tt.suppressed {
				t.Errorf("expected suppressed=%v, got %v", tt.suppressed, r.suppressed)
			}
			if r.suppressed && r.source != suppressSourceInline {
				t.Errorf("expected source 'inline', got %q", r.source)
			}
		})
	}
}

func TestCheckInlineSuppression_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.go")
	content := "key := val // pipelock:ignore credential in url\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	r := checkInlineSuppression(path, 1, "Credential in URL")
	if !r.suppressed {
		t.Error("expected case-insensitive rule match to suppress")
	}
}

func TestCheckConfigSuppression(t *testing.T) {
	entries := []config.SuppressEntry{
		{Rule: "Credential in URL", Path: "app/models/client.rb", Reason: "Instance var"},
		{Rule: "Credential in URL", Path: "config/initializers/*.rb", Reason: "Env var names"},
		{Rule: "Anthropic API Key", Path: "vendor/"},
	}

	tests := []struct {
		name       string
		file       string
		rule       string
		suppressed bool
		reason     string
	}{
		{
			name:       "exact path match",
			file:       "app/models/client.rb",
			rule:       "Credential in URL",
			suppressed: true,
			reason:     "Instance var",
		},
		{
			name:       "glob path match",
			file:       "config/initializers/auth.rb",
			rule:       "Credential in URL",
			suppressed: true,
			reason:     "Env var names",
		},
		{
			name:       "directory prefix match",
			file:       "vendor/gem/lib.rb",
			rule:       "Anthropic API Key",
			suppressed: true,
			reason:     "",
		},
		{
			name:       "wrong rule not suppressed",
			file:       "app/models/client.rb",
			rule:       "Anthropic API Key",
			suppressed: false,
		},
		{
			name:       "wrong path not suppressed",
			file:       "app/controllers/main.rb",
			rule:       "Credential in URL",
			suppressed: false,
		},
		{
			name:       "empty file not suppressed",
			file:       "",
			rule:       "Credential in URL",
			suppressed: false,
		},
		{
			name:       "no entries not suppressed",
			file:       "app/models/client.rb",
			rule:       "Credential in URL",
			suppressed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ents []config.SuppressEntry
			if tt.name != "no entries not suppressed" {
				ents = entries
			}
			r := checkConfigSuppression(tt.file, tt.rule, ents)
			if r.suppressed != tt.suppressed {
				t.Errorf("expected suppressed=%v, got %v", tt.suppressed, r.suppressed)
			}
			if r.suppressed {
				if r.source != suppressSourceConfig {
					t.Errorf("expected source 'config', got %q", r.source)
				}
				if r.reason != tt.reason {
					t.Errorf("expected reason %q, got %q", tt.reason, r.reason)
				}
			}
		})
	}
}

func TestCheckConfigSuppression_CaseInsensitiveRule(t *testing.T) {
	entries := []config.SuppressEntry{
		{Rule: "credential in url", Path: "app/*.rb"},
	}

	r := checkConfigSuppression("app/client.rb", "Credential in URL", entries)
	if !r.suppressed {
		t.Error("expected case-insensitive rule match in config suppression")
	}
}

func TestSuppressGitFindings(t *testing.T) {
	dir := t.TempDir()

	// Create a file with an inline suppression.
	path := filepath.Join(dir, "config.go")
	content := strings.Join([]string{
		"package config",
		`var key = "` + fakeAntKey1 + `" // pipelock:ignore`,
		`var other = "` + fakeAntKey2 + `"`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := []config.SuppressEntry{
		{Rule: "AWS Access Key", Path: "vendor/"},
	}

	findings := []gitprotect.Finding{
		{File: path, Line: 2, Pattern: "Anthropic API Key", Content: fakeAntKey1, Severity: "critical"},                         // inline suppressed
		{File: path, Line: 3, Pattern: "Anthropic API Key", Content: fakeAntKey2, Severity: "critical"},                         // NOT suppressed
		{File: filepath.Join("vendor", "lib.go"), Line: 5, Pattern: "AWS Access Key", Content: "AKIA...", Severity: "critical"}, // config suppressed
	}

	kept, suppressed, reasons := suppressGitFindings(findings, entries)

	if len(kept) != 1 {
		t.Fatalf("expected 1 kept finding, got %d", len(kept))
	}
	if kept[0].Line != 3 {
		t.Errorf("expected kept finding on line 3, got %d", kept[0].Line)
	}
	if len(suppressed) != 2 {
		t.Fatalf("expected 2 suppressed findings, got %d", len(suppressed))
	}
	if reasons[0].source != suppressSourceInline {
		t.Errorf("expected first suppressed to be inline, got %q", reasons[0].source)
	}
	if reasons[1].source != suppressSourceConfig {
		t.Errorf("expected second suppressed to be config, got %q", reasons[1].source)
	}
}

func TestSuppressGitFindings_Empty(t *testing.T) {
	kept, suppressed, reasons := suppressGitFindings(nil, nil)
	if len(kept) != 0 || len(suppressed) != 0 || len(reasons) != 0 {
		t.Error("expected all empty for nil findings")
	}
}

func TestSuppressProjectFindings(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "app.rb")
	content := strings.Join([]string{
		"require 'net/http'",
		fakeToken + " # pipelock:ignore Credential in URL",
		fakePassword,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := []config.SuppressEntry{
		{Rule: "Credential in URL", Path: "config/*.rb", Reason: "Env refs"},
	}

	findings := []projectscan.Finding{
		{File: path, Line: 2, Pattern: "Credential in URL", Severity: "high", Category: "secret", Message: "token found"},                               // inline suppressed
		{File: path, Line: 3, Pattern: "Credential in URL", Severity: "high", Category: "secret", Message: "cred found"},                                // NOT suppressed
		{File: filepath.Join("config", "auth.rb"), Line: 5, Pattern: "Credential in URL", Severity: "high", Category: "secret", Message: "config cred"}, // config suppressed
	}

	kept, suppressed, reasons := suppressProjectFindings(findings, entries)

	if len(kept) != 1 {
		t.Fatalf("expected 1 kept finding, got %d", len(kept))
	}
	if kept[0].Line != 3 {
		t.Errorf("expected kept finding on line 3, got %d", kept[0].Line)
	}
	if len(suppressed) != 2 {
		t.Fatalf("expected 2 suppressed findings, got %d", len(suppressed))
	}
	if reasons[0].source != suppressSourceInline {
		t.Errorf("expected first suppressed to be inline, got %q", reasons[0].source)
	}
	if reasons[1].source != suppressSourceConfig {
		t.Errorf("expected second suppressed to be config, got %q", reasons[1].source)
	}
}

func TestSuppressProjectFindings_Empty(t *testing.T) {
	kept, suppressed, reasons := suppressProjectFindings(nil, nil)
	if len(kept) != 0 || len(suppressed) != 0 || len(reasons) != 0 {
		t.Error("expected all empty for nil findings")
	}
}

func TestPrintSuppressedGit(t *testing.T) {
	findings := []gitprotect.Finding{
		{File: "app/client.rb", Line: 22, Pattern: "Credential in URL", Content: "...", Severity: "high"},
		{File: "config/auth.rb", Line: 5, Pattern: "Credential in URL", Content: "...", Severity: "high"},
		{File: "vendor/lib.rb", Line: 0, Pattern: "AWS Access Key", Content: "...", Severity: "critical"},
	}
	reasons := []suppressResult{
		{suppressed: true, source: suppressSourceInline},
		{suppressed: true, source: suppressSourceConfig, reason: "Env var names, not values"},
		{suppressed: true, source: suppressSourceConfig, reason: ""},
	}

	var buf strings.Builder
	printSuppressedGit(&buf, findings, reasons)

	output := buf.String()
	if !strings.Contains(output, "SUPPRESSED: app/client.rb:22  Credential in URL (inline)") {
		t.Errorf("expected inline suppression line, got:\n%s", output)
	}
	if !strings.Contains(output, `SUPPRESSED: config/auth.rb:5  Credential in URL (config: "Env var names, not values")`) {
		t.Errorf("expected config suppression line with reason, got:\n%s", output)
	}
	if !strings.Contains(output, "SUPPRESSED: vendor/lib.rb  AWS Access Key (config)") {
		t.Errorf("expected config suppression line without reason, got:\n%s", output)
	}
}

func TestPrintSuppressedProject(t *testing.T) {
	findings := []projectscan.Finding{
		{File: "src/main.go", Line: 10, Pattern: "Anthropic API Key", Severity: "critical", Category: "secret", Message: "key found"},
		{File: "config/auth.rb", Line: 5, Pattern: "Credential in URL", Severity: "high", Category: "secret", Message: "cred found"},
		{File: "vendor/lib.rb", Line: 0, Pattern: "AWS Access Key", Severity: "critical", Category: "secret", Message: "key found"},
	}
	reasons := []suppressResult{
		{suppressed: true, source: suppressSourceInline},
		{suppressed: true, source: suppressSourceConfig, reason: "Env var names, not values"},
		{suppressed: true, source: suppressSourceConfig, reason: ""},
	}

	var buf strings.Builder
	printSuppressedProject(&buf, findings, reasons)

	output := buf.String()
	if !strings.Contains(output, "SUPPRESSED: src/main.go:10  Anthropic API Key (inline)") {
		t.Errorf("expected inline suppression line, got:\n%s", output)
	}
	if !strings.Contains(output, `SUPPRESSED: config/auth.rb:5  Credential in URL (config: "Env var names, not values")`) {
		t.Errorf("expected config suppression line with reason, got:\n%s", output)
	}
	if !strings.Contains(output, "SUPPRESSED: vendor/lib.rb  AWS Access Key (config)") {
		t.Errorf("expected config suppression line without reason, got:\n%s", output)
	}
}

func TestSuppressGitFindings_InlineTakesPrecedence(t *testing.T) {
	// When a finding is suppressed by both inline and config,
	// inline should be reported (it's checked first).
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.go")
	content := "package main\nvar cred = \"" + fakeCredURL + "\" // pipelock:ignore\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := []config.SuppressEntry{
		{Rule: "Credential in URL", Path: path, Reason: "Also config suppressed"},
	}

	findings := []gitprotect.Finding{
		{File: path, Line: 2, Pattern: "Credential in URL", Content: fakeCredURL, Severity: "high"},
	}

	_, suppressed, reasons := suppressGitFindings(findings, entries)
	if len(suppressed) != 1 {
		t.Fatalf("expected 1 suppressed, got %d", len(suppressed))
	}
	if reasons[0].source != suppressSourceInline {
		t.Errorf("expected inline to take precedence, got %q", reasons[0].source)
	}
}

func TestSuppressGitFindings_NoFileSkipsInline(t *testing.T) {
	// Finding with empty File should skip inline suppression but
	// still be eligible for config suppression (though config also
	// requires non-empty file, so it passes through).
	findings := []gitprotect.Finding{
		{File: "", Line: 5, Pattern: "test", Content: "...", Severity: "high"},
	}

	kept, suppressed, _ := suppressGitFindings(findings, nil)
	if len(kept) != 1 {
		t.Errorf("expected 1 kept, got %d", len(kept))
	}
	if len(suppressed) != 0 {
		t.Errorf("expected 0 suppressed, got %d", len(suppressed))
	}
}
