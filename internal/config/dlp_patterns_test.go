// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

func TestDefaultDLPPatternsMatchDefaults(t *testing.T) {
	t.Parallel()

	got := scrubPatternRuntimeFields(Defaults().DLP.Patterns)
	want := DefaultDLPPatterns()
	if diff := compareDLPPatternSets(got, want); diff != "" {
		t.Fatal(diff)
	}
}

func TestDefaultDLPPatternsReturnsDeepCopy(t *testing.T) {
	t.Parallel()

	first := DefaultDLPPatterns()
	if len(first) == 0 || len(first[0].ExemptDomains) == 0 {
		t.Fatal("first canonical pattern should have exempt domains")
	}
	first[0].Name = "mutated"
	first[0].ExemptDomains[0] = "mutated.example"

	second := DefaultDLPPatterns()
	if second[0].Name == "mutated" {
		t.Fatal("pattern name mutation leaked into canonical registry")
	}
	if second[0].ExemptDomains[0] == "mutated.example" {
		t.Fatal("exempt_domains mutation leaked into canonical registry")
	}
}

func TestPresetDLPPatternsProfiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		profile         string
		wantLen         int
		wantSeverity    string
		wantPatternName string
	}{
		{
			name:            "full",
			profile:         DLPPresetProfileFull,
			wantLen:         66,
			wantSeverity:    SeverityHigh,
			wantPatternName: "Google API Key",
		},
		{
			name:            "hostile",
			profile:         DLPPresetProfileHostile,
			wantLen:         66,
			wantSeverity:    SeverityCritical,
			wantPatternName: "Google API Key",
		},
		{
			name:            "quickstart",
			profile:         DLPPresetProfileQuickstart,
			wantLen:         22,
			wantSeverity:    SeverityCritical,
			wantPatternName: "OpenAI API Key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			patterns, err := PresetDLPPatterns(tt.profile)
			if err != nil {
				t.Fatalf("PresetDLPPatterns(%q): %v", tt.profile, err)
			}
			if len(patterns) != tt.wantLen {
				t.Fatalf("len = %d, want %d", len(patterns), tt.wantLen)
			}
			got, ok := dlpPatternByName(patterns, tt.wantPatternName)
			if !ok {
				t.Fatalf("pattern %q not found", tt.wantPatternName)
			}
			if got.Severity != tt.wantSeverity {
				t.Fatalf("%s severity = %q, want %q", tt.wantPatternName, got.Severity, tt.wantSeverity)
			}
		})
	}
}

func TestPresetDLPPatternsRejectsUnknownProfile(t *testing.T) {
	t.Parallel()

	if _, err := PresetDLPPatterns("missing"); err == nil {
		t.Fatal("expected unknown profile error")
	}
}

func TestQuickstartDLPPatternsReuseDefaultDefinitions(t *testing.T) {
	t.Parallel()

	defaultsByName := make(map[string]DLPPattern, len(defaultDLPPatternSet))
	for _, pattern := range DefaultDLPPatterns() {
		defaultsByName[pattern.Name] = pattern
	}
	quickstart, err := PresetDLPPatterns(DLPPresetProfileQuickstart)
	if err != nil {
		t.Fatalf("PresetDLPPatterns(%q): %v", DLPPresetProfileQuickstart, err)
	}
	for _, got := range quickstart {
		want, ok := defaultsByName[got.Name]
		if !ok {
			t.Fatalf("quickstart pattern %q not found in defaults", got.Name)
		}
		if got.Regex != want.Regex {
			t.Fatalf("%s quickstart regex = %q, want default %q", got.Name, got.Regex, want.Regex)
		}
		if got.Severity != want.Severity {
			t.Fatalf("%s quickstart severity = %q, want default %q", got.Name, got.Severity, want.Severity)
		}
		if got.Validator != want.Validator {
			t.Fatalf("%s quickstart validator = %q, want default %q", got.Name, got.Validator, want.Validator)
		}
		if !sameStrings(got.ExemptDomains, want.ExemptDomains) {
			t.Fatalf("%s quickstart exempt_domains = %q, want default %q", got.Name, got.ExemptDomains, want.ExemptDomains)
		}
	}
}

func TestGenerateDLPPresetFilesCurrentFilesInSync(t *testing.T) {
	t.Parallel()

	out, err := GenerateDLPPresetFiles(filepath.Join("..", ".."), false)
	if err != nil {
		t.Fatalf("GenerateDLPPresetFiles: %v", err)
	}
	if !strings.Contains(out, "8 files checked, 0 updated") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestDefaultDLPPatternsRedactionMirrorCoverage(t *testing.T) {
	t.Parallel()

	matcher := redact.NewDefaultMatcher()
	tests := []struct {
		name  string
		value string
		class redact.Class
	}{
		{name: "Anthropic API Key", value: "sk-" + "ant-" + strings.Repeat("A", 20), class: redact.ClassAnthropicKey},
		{name: "OpenAI API Key", value: "sk-" + "proj-" + strings.Repeat("A", 20), class: redact.ClassOpenAIAPIKey},
		{name: "OpenAI Service Key", value: "sk-" + "svcacct-" + strings.Repeat("A", 20), class: redact.ClassOpenAIAPIKey},
		{name: "Fireworks API Key", value: "fw_" + strings.Repeat("A", 22), class: redact.ClassFireworksAPIKey},
		{name: "LLM Router API Key", value: "sk-" + "or-v1-" + strings.Repeat("a", 20), class: redact.ClassAIProviderKey},
		{name: "Answer Engine API Key", value: "pplx-" + strings.Repeat("A", 20), class: redact.ClassAIProviderKey},
		{name: "Web Research API Key", value: "tvly-" + strings.Repeat("A", 20), class: redact.ClassAIProviderKey},
		{name: "Google API Key", value: "AIza" + strings.Repeat("A", 35), class: redact.ClassGoogleAPIKey},
		{name: "GitHub Token", value: "ghp_" + strings.Repeat("A", 36), class: redact.ClassGitHubToken},
		{name: "GitHub Fine-Grained PAT", value: "github_pat_" + strings.Repeat("A", 36), class: redact.ClassGitHubToken},
		{name: "GitLab PAT", value: "glpat-" + strings.Repeat("A", 20), class: redact.ClassGitLabToken},
		{name: "GitLab Deploy Token", value: "gldt-" + strings.Repeat("A", 20), class: redact.ClassGitLabToken},
		{name: "PostgreSQL Connection String", value: "postgres://user:" + strings.Repeat("p", 8) + "@api.vendor.example/db", class: redact.ClassDBConnString},
		{name: "AWS Access ID", value: "AKIA" + strings.Repeat("A", 16), class: redact.ClassAWSAccessKey},
		{name: "AWS Secret Key", value: "aws_secret_access_key = " + strings.Repeat("A", 40), class: redact.ClassAWSSecretKey},
		{name: "Azure Storage Account Key", value: "AccountKey=" + strings.Repeat("A", 86) + "==", class: redact.ClassAzureStorageKey},
		{name: "Azure SAS Token", value: "sig=" + strings.Repeat("A", 43) + "%3d", class: redact.ClassAzureSAS},
		{name: "Slack Token", value: "xoxb-" + strings.Repeat("A", 15), class: redact.ClassSlackToken},
		{name: "Hugging Face Token", value: "hf_" + strings.Repeat("A", 34), class: redact.ClassHuggingFaceToken},
		{name: "Databricks Token", value: "dapi" + strings.Repeat("a", 32), class: redact.ClassDatabricksPAT},
		{name: "Replicate API Token", value: "r8_" + strings.Repeat("a", 40), class: redact.ClassReplicateAPIToken},
		{name: "Together AI Key", value: "tok_" + strings.Repeat("a", 40), class: redact.ClassTogetherAIKey},
		{name: "HashiCorp Vault Token", value: "hvs." + strings.Repeat("A", 24), class: redact.ClassVaultToken},
		{name: "Vercel Token", value: "vercel_" + strings.Repeat("A", 24), class: redact.ClassVercelToken},
		{name: "Supabase Service Key", value: "sb_secret_" + strings.Repeat("A", 22) + "_" + strings.Repeat("B", 8), class: redact.ClassSupabaseKey},
		{name: "npm Token", value: "npm_" + strings.Repeat("A", 36), class: redact.ClassNPMToken},
		{name: "PyPI Token", value: "pypi-" + "AgE" + strings.Repeat("A", 90), class: redact.ClassPyPIToken},
		{name: "Linear API Key", value: "lin_api_" + strings.Repeat("A", 40), class: redact.ClassLinearAPIKey},
		{name: "Notion API Key", value: "ntn_" + strings.Repeat("A", 40), class: redact.ClassNotionAPIKey},
		{name: "Sentry Auth Token", value: "sntrys_" + strings.Repeat("A", 40), class: redact.ClassSentryAuthToken},
		{name: "Twilio API Key", value: "SK" + strings.Repeat("a", 32), class: redact.ClassTwilioAPIKey},
		{name: "Mailgun API Key", value: "key-" + strings.Repeat("A", 32), class: redact.ClassMailgunAPIKey},
		{name: "SendGrid API Key", value: "SG." + strings.Repeat("A", 22) + "." + strings.Repeat("B", 43), class: redact.ClassSendGridAPIKey},
		{name: "JWT Token", value: "eyJ" + strings.Repeat("A", 7) + "." + "eyJ" + strings.Repeat("B", 7) + "." + strings.Repeat("C", 10), class: redact.ClassJWT},
		{name: "Social Security Number", value: "123-45" + "-6789", class: redact.ClassSSN},
		{name: "Environment Variable Secret", value: "VENDOR_API_KEY=" + strings.Repeat("A", 8), class: redact.ClassEnvSecret},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pattern, ok := dlpPatternByName(DefaultDLPPatterns(), tt.name)
			if !ok {
				t.Fatalf("default DLP pattern %q not found", tt.name)
			}
			if !regexpMustCompile(t, pattern.Regex).MatchString(tt.value) {
				t.Fatalf("sample %q no longer matches canonical DLP regex %q", tt.value, pattern.Regex)
			}
			for _, match := range matcher.Scan(tt.value) {
				if match.Class == tt.class && strings.Contains(tt.value, match.Original) {
					return
				}
			}
			t.Fatalf("redaction mirror did not classify %q as %s; matches=%+v", tt.name, tt.class, matcher.Scan(tt.value))
		})
	}
}

func TestGenerateDLPPresetFilesRejectsMalformedYAML(t *testing.T) {
	t.Parallel()

	if _, err := parseYAMLDLPPatterns([]byte("dlp:\n  patterns:\n    - name: [")); err == nil {
		t.Fatal("expected malformed YAML error")
	}
}

func TestGenerateDLPPresetFilesRejectsMissingPatterns(t *testing.T) {
	t.Parallel()

	if _, err := parseYAMLDLPPatterns([]byte("version: 1\n")); err == nil {
		t.Fatal("expected missing dlp.patterns error")
	}
}

func TestCompareDLPPatternSetsDetectsDrift(t *testing.T) {
	t.Parallel()

	base := []DLPPattern{{Name: "Token", Regex: `tok_[a-z]+`, Severity: SeverityHigh, Validator: ValidatorLuhn, ExemptDomains: []string{"api.vendor.example"}}}
	tests := []struct {
		name string
		got  []DLPPattern
		want string
	}{
		{name: "count", got: nil, want: "pattern count"},
		{name: "name", got: []DLPPattern{{Name: "Other", Regex: base[0].Regex, Severity: base[0].Severity, Validator: base[0].Validator, ExemptDomains: base[0].ExemptDomains}}, want: "pattern[0].name"},
		{name: "regex", got: []DLPPattern{{Name: base[0].Name, Regex: `bad`, Severity: base[0].Severity, Validator: base[0].Validator, ExemptDomains: base[0].ExemptDomains}}, want: "regex drifted"},
		{name: "severity", got: []DLPPattern{{Name: base[0].Name, Regex: base[0].Regex, Severity: SeverityCritical, Validator: base[0].Validator, ExemptDomains: base[0].ExemptDomains}}, want: "severity drifted"},
		{name: "validator", got: []DLPPattern{{Name: base[0].Name, Regex: base[0].Regex, Severity: base[0].Severity, Validator: ValidatorMod97, ExemptDomains: base[0].ExemptDomains}}, want: "validator drifted"},
		{name: "exempt domains", got: []DLPPattern{{Name: base[0].Name, Regex: base[0].Regex, Severity: base[0].Severity, Validator: base[0].Validator, ExemptDomains: []string{"other.vendor.example"}}}, want: "exempt_domains drifted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if diff := compareDLPPatternSets(tt.got, base); !strings.Contains(diff, tt.want) {
				t.Fatalf("diff = %q, want substring %q", diff, tt.want)
			}
		})
	}
}

func TestRewriteDLPPatternBlockErrorsOnMissingBlock(t *testing.T) {
	t.Parallel()

	if _, err := rewriteDLPPatternBlock([]byte("version: 1\n"), DefaultDLPPatterns()); err == nil {
		t.Fatal("expected missing dlp.patterns block error")
	}
}

func TestRewriteDLPPatternBlockRendersPatternScalars(t *testing.T) {
	t.Parallel()

	raw := []byte("version: 1\ndlp:\n  scan_env: true\n  patterns:\n    - name: old\n      regex: old\n      severity: low\nresponse_scanning:\n  enabled: true\n")
	patterns := []DLPPattern{{
		Name:          "Token",
		Regex:         `key='value'`,
		Severity:      SeverityCritical,
		Validator:     ValidatorLuhn,
		ExemptDomains: []string{"api.vendor.example"},
	}}
	rewritten, err := rewriteDLPPatternBlock(raw, patterns)
	if err != nil {
		t.Fatalf("rewriteDLPPatternBlock: %v", err)
	}
	got := string(rewritten)
	for _, want := range []string{
		`    - name: "Token"`,
		`      regex: 'key=''value'''`,
		`      severity: critical`,
		`      validator: luhn`,
		`        - "api.vendor.example"`,
		`response_scanning:`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten block missing %q:\n%s", want, got)
		}
	}
}

func TestRewriteDLPPatternBlockPreservesDLPSiblingsAfterPatterns(t *testing.T) {
	t.Parallel()

	raw := []byte("version: 1\ndlp:\n  scan_env: true\n  patterns:\n    - name: old\n      regex: old\n      severity: low\n  min_env_secret_length: 32\nresponse_scanning:\n  enabled: true\n")
	patterns := []DLPPattern{{Name: "Token", Regex: `tok_[a-z]+`, Severity: SeverityHigh}}
	rewritten, err := rewriteDLPPatternBlock(raw, patterns)
	if err != nil {
		t.Fatalf("rewriteDLPPatternBlock: %v", err)
	}
	got := string(rewritten)
	for _, want := range []string{
		`    - name: "Token"`,
		`  min_env_secret_length: 32`,
		`response_scanning:`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten block missing %q:\n%s", want, got)
		}
	}
}

func TestRewriteDLPPatternBlockUsesDetectedIndent(t *testing.T) {
	t.Parallel()

	raw := []byte("version: 1\ndlp:\n    scan_env: true\n    patterns:\n      - name: old\n        regex: old\n        severity: low\n    min_env_secret_length: 32\n")
	patterns := []DLPPattern{{Name: "Token", Regex: `tok_[a-z]+`, Severity: SeverityHigh}}
	rewritten, err := rewriteDLPPatternBlock(raw, patterns)
	if err != nil {
		t.Fatalf("rewriteDLPPatternBlock: %v", err)
	}
	got := string(rewritten)
	for _, want := range []string{
		`      - name: "Token"`,
		`        regex: 'tok_[a-z]+'`,
		`        severity: high`,
		`    min_env_secret_length: 32`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten block missing %q:\n%s", want, got)
		}
	}

	again, err := rewriteDLPPatternBlock(rewritten, patterns)
	if err != nil {
		t.Fatalf("rewriteDLPPatternBlock second pass: %v", err)
	}
	if !bytes.Equal(again, rewritten) {
		t.Fatalf("rewrite should be idempotent with nonstandard indent:\n%s", again)
	}
}

func TestGenerateDLPPresetFilesDetectsFileDrift(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for _, target := range dlpPresetTargets {
		src := filepath.Join("..", "..", target.Path)
		dst := filepath.Join(root, target.Path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(dst), err)
		}
		raw, err := os.ReadFile(filepath.Clean(src))
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		if err := os.WriteFile(filepath.Clean(dst), raw, 0o600); err != nil {
			t.Fatalf("write %s: %v", dst, err)
		}
	}
	path := filepath.Join(root, "configs", "balanced.yaml")
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read copied preset: %v", err)
	}
	raw = []byte(strings.Replace(string(raw), "severity: high", "severity: low", 1))
	if err := os.WriteFile(filepath.Clean(path), raw, 0o600); err != nil {
		t.Fatalf("write drifted preset: %v", err)
	}

	if _, err := GenerateDLPPresetFiles(root, false); err == nil || !strings.Contains(err.Error(), "severity drifted") {
		t.Fatalf("GenerateDLPPresetFiles error = %v, want severity drift", err)
	}

	out, err := GenerateDLPPresetFiles(root, true)
	if err != nil {
		t.Fatalf("GenerateDLPPresetFiles write=true: %v", err)
	}
	for _, want := range []string{
		"updated configs/balanced.yaml (full): 66 patterns",
		"DLP preset generation complete: 8 files checked, 1 updated",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("GenerateDLPPresetFiles output missing %q:\n%s", want, out)
		}
	}
	rewritten, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read rewritten preset: %v", err)
	}
	got, err := parseYAMLDLPPatterns(rewritten)
	if err != nil {
		t.Fatalf("parse rewritten preset: %v", err)
	}
	want, err := PresetDLPPatterns(DLPPresetProfileFull)
	if err != nil {
		t.Fatalf("PresetDLPPatterns: %v", err)
	}
	if diff := compareDLPPatternSets(got, want); diff != "" {
		t.Fatalf("rewritten preset drifted: %s", diff)
	}
	out, err = GenerateDLPPresetFiles(root, false)
	if err != nil {
		t.Fatalf("GenerateDLPPresetFiles follow-up dry run: %v", err)
	}
	if !strings.Contains(out, "DLP preset generation complete: 8 files checked, 0 updated") {
		t.Fatalf("GenerateDLPPresetFiles follow-up output unexpected:\n%s", out)
	}
}

func scrubPatternRuntimeFields(patterns []DLPPattern) []DLPPattern {
	out := cloneDLPPatterns(patterns)
	for i := range out {
		out[i].Compiled = false
		out[i].Bundle = ""
		out[i].BundleVersion = ""
	}
	return out
}

func dlpPatternByName(patterns []DLPPattern, name string) (DLPPattern, bool) {
	for _, pattern := range patterns {
		if pattern.Name == name {
			return pattern, true
		}
	}
	return DLPPattern{}, false
}

func regexpMustCompile(t *testing.T, expr string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(expr)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return re
}
