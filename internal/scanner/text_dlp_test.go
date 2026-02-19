package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScanTextForDLP(t *testing.T) {
	tests := []struct {
		name         string
		setupConfig  func() *config.Config
		setupScanner func(s *Scanner)
		text         string
		wantClean    bool
		wantPattern  string // substring match on PatternName if non-empty
		wantEncoded  string // expected Encoded field value if non-empty
	}{
		{
			name:      "clean text no matches",
			text:      "This is a perfectly normal piece of text with no secrets.",
			wantClean: true,
		},
		{
			name: "raw DLP pattern match - Anthropic API Key",
			//nolint:goconst // test value
			text:        "Please use this key: " + "sk-ant-" + strings.Repeat("a", 25),
			wantClean:   false,
			wantPattern: "Anthropic API Key",
		},
		{
			name:        "raw DLP pattern match - AWS Access Key",
			text:        "My access key is AKIA" + strings.Repeat("A", 16),
			wantClean:   false,
			wantPattern: "AWS Access Key",
		},
		{
			name: "base64-encoded secret decoded and matched",
			text: func() string {
				secret := "sk-ant-" + strings.Repeat("b", 25)
				return base64.StdEncoding.EncodeToString([]byte(secret))
			}(),
			wantClean:   false,
			wantPattern: "Anthropic API Key",
			wantEncoded: "base64",
		},
		{
			name: "hex-encoded secret decoded and matched",
			text: func() string {
				secret := "sk-ant-" + strings.Repeat("c", 25)
				return hex.EncodeToString([]byte(secret))
			}(),
			wantClean:   false,
			wantPattern: "Anthropic API Key",
			wantEncoded: "hex",
		},
		{
			name: "base32-encoded secret decoded and matched",
			text: func() string {
				secret := "sk-ant-" + strings.Repeat("d", 25)
				return base32.StdEncoding.EncodeToString([]byte(secret))
			}(),
			wantClean:   false,
			wantPattern: "Anthropic API Key",
			wantEncoded: "base32",
		},
		{
			name: "env variable leak detection - raw",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.DLP.ScanEnv = true
				return cfg
			},
			setupScanner: func(s *Scanner) {
				s.envSecrets = []string{"MyTopSecretEnvValue1234"} //nolint:goconst // test value
			},
			text:        "Here is the value: MyTopSecretEnvValue1234",
			wantClean:   false,
			wantPattern: "Environment Variable Leak",
			wantEncoded: "env",
		},
		{
			name: "env variable leak detection - base64 encoded",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.DLP.ScanEnv = true
				return cfg
			},
			setupScanner: func(s *Scanner) {
				s.envSecrets = []string{"AnotherSecretValue56789"} //nolint:goconst // test value
			},
			text: func() string {
				return "encoded: " + base64.StdEncoding.EncodeToString([]byte("AnotherSecretValue56789"))
			}(),
			wantClean:   false,
			wantPattern: "Environment Variable Leak",
			wantEncoded: "env",
		},
		{
			name: "zero-width character bypass attempt - still caught",
			text: func() string {
				// Insert zero-width space inside the key pattern
				prefix := "sk-ant-" //nolint:goconst // test value
				suffix := strings.Repeat("e", 25)
				return prefix + "\u200B" + suffix
			}(),
			wantClean:   false,
			wantPattern: "Anthropic API Key",
		},
		{
			name: "NFKC normalization - Unicode confusables",
			text: func() string {
				// Use fullwidth characters that NFKC normalizes to ASCII
				// U+FF53 = fullwidth 's', U+FF4B = fullwidth 'k'
				// sk-ant- with fullwidth s and k
				return "\uff53\uff4b-ant-" + strings.Repeat("f", 25)
			}(),
			wantClean:   false,
			wantPattern: "Anthropic API Key",
		},
		{
			name:      "empty text returns clean",
			text:      "",
			wantClean: true,
		},
		{
			name: "no DLP patterns configured returns clean",
			setupConfig: func() *config.Config {
				cfg := testConfig()
				cfg.DLP.Patterns = nil
				cfg.DLP.ScanEnv = false
				return cfg
			},
			text:      "sk-ant-" + strings.Repeat("g", 25),
			wantClean: true,
		},
		{
			name: "deduplication - same pattern raw + encoded only appears once per encoding",
			text: func() string {
				// Both the raw secret and its base64 form in same text
				secret := "sk-ant-" + strings.Repeat("h", 25)
				encoded := base64.StdEncoding.EncodeToString([]byte(secret))
				return secret + " " + encoded
			}(),
			wantClean: false,
		},
		{
			name: "multiple pattern matches in single text",
			text: func() string {
				anthropic := "sk-ant-" + strings.Repeat("i", 25)
				aws := "AKIA" + strings.Repeat("B", 16)
				return "Keys: " + anthropic + " and " + aws
			}(),
			wantClean: false,
		},
		{
			name:        "case variation - uppercase Anthropic key",
			text:        "SK-ANT-" + strings.Repeat("A", 25),
			wantClean:   false,
			wantPattern: "Anthropic API Key",
		},
		{
			name:        "case variation - mixed case AWS key",
			text:        "akia" + strings.Repeat("X", 16),
			wantClean:   false,
			wantPattern: "AWS Access Key",
		},
		{
			name:        "null byte injection - secret split by null bytes",
			text:        "sk-ant-\x00" + strings.Repeat("j", 25),
			wantClean:   false,
			wantPattern: "Anthropic API Key",
		},
		{
			name:        "case variation - uppercase private key header",
			text:        "-----BEGIN " + strings.ToUpper("rsa") + " PRIVATE KEY-----",
			wantClean:   false,
			wantPattern: "Private Key",
		},
		{
			name:        "case variation - lowercase private key header",
			text:        strings.ToLower("-----BEGIN RSA") + " private key-----",
			wantClean:   false,
			wantPattern: "Private Key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg *config.Config
			if tt.setupConfig != nil {
				cfg = tt.setupConfig()
			} else {
				cfg = testConfig()
			}
			s := New(cfg)
			defer s.Close()

			if tt.setupScanner != nil {
				tt.setupScanner(s)
			}

			result := s.ScanTextForDLP(tt.text)

			if result.Clean != tt.wantClean {
				t.Errorf("Clean = %v, want %v (matches: %v)", result.Clean, tt.wantClean, result.Matches)
			}

			if tt.wantPattern != "" {
				found := false
				for _, m := range result.Matches {
					if strings.Contains(m.PatternName, tt.wantPattern) {
						found = true
						if tt.wantEncoded != "" && m.Encoded != tt.wantEncoded {
							t.Errorf("match %q Encoded = %q, want %q", m.PatternName, m.Encoded, tt.wantEncoded)
						}
						break
					}
				}
				if !found {
					t.Errorf("expected match containing %q, got matches: %v", tt.wantPattern, result.Matches)
				}
			}
		})
	}
}

func TestScanTextForDLP_Deduplication(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// The raw secret appears in the text AND the base64-decoded form also matches.
	// The raw match (Encoded="") should appear once, the base64 match (Encoded="base64")
	// should appear once — no duplicates within the same PatternName+Encoded pair.
	secret := "sk-ant-" + strings.Repeat("x", 25) //nolint:goconst // test value
	// Construct text that has the raw secret AND its base64 encoding
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	text := secret + " " + encoded

	result := s.ScanTextForDLP(text)
	if result.Clean {
		t.Fatal("expected matches, got clean")
	}

	// Count occurrences of "Anthropic API Key" with Encoded=""
	rawCount := 0
	b64Count := 0
	for _, m := range result.Matches {
		if m.PatternName == "Anthropic API Key" && m.Encoded == "" { //nolint:goconst // test value
			rawCount++
		}
		if m.PatternName == "Anthropic API Key" && m.Encoded == "base64" { //nolint:goconst // test value
			b64Count++
		}
	}

	if rawCount > 1 {
		t.Errorf("expected at most 1 raw match, got %d", rawCount)
	}
	if b64Count > 1 {
		t.Errorf("expected at most 1 base64 match, got %d", b64Count)
	}
}

func TestScanTextForDLP_MultiplePatterns(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	anthropic := "sk-ant-" + strings.Repeat("j", 25)
	aws := "AKIA" + strings.Repeat("C", 16)
	github := "ghp_" + strings.Repeat("D", 40)
	text := anthropic + " " + aws + " " + github

	result := s.ScanTextForDLP(text)
	if result.Clean {
		t.Fatal("expected matches, got clean")
	}

	patternNames := make(map[string]bool)
	for _, m := range result.Matches {
		patternNames[m.PatternName] = true
	}

	for _, want := range []string{"Anthropic API Key", "AWS Access Key", "GitHub Token"} {
		if !patternNames[want] {
			t.Errorf("expected pattern %q in matches, got: %v", want, result.Matches)
		}
	}
}

func TestDeduplicateMatches(t *testing.T) {
	tests := []struct {
		name  string
		input []TextDLPMatch
		want  int
	}{
		{
			name:  "nil input",
			input: nil,
			want:  0,
		},
		{
			name: "single match",
			input: []TextDLPMatch{
				{PatternName: "test", Encoded: ""},
			},
			want: 1,
		},
		{
			name: "duplicate same pattern and encoding",
			input: []TextDLPMatch{
				{PatternName: "test", Encoded: ""},
				{PatternName: "test", Encoded: ""},
			},
			want: 1,
		},
		{
			name: "same pattern different encoding",
			input: []TextDLPMatch{
				{PatternName: "test", Encoded: ""},
				{PatternName: "test", Encoded: "base64"},
			},
			want: 2,
		},
		{
			name: "different patterns same encoding",
			input: []TextDLPMatch{
				{PatternName: "pattern-a", Encoded: ""},
				{PatternName: "pattern-b", Encoded: ""},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateMatches(tt.input)
			if len(got) != tt.want {
				t.Errorf("deduplicateMatches returned %d matches, want %d", len(got), tt.want)
			}
		})
	}
}

func TestMatchDLPPatterns(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Test that matchDLPPatterns tags encoding correctly
	secret := "sk-ant-" + strings.Repeat("k", 25) //nolint:goconst // test value
	matches := s.matchDLPPatterns(secret, "hex")

	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}

	for _, m := range matches {
		if m.Encoded != "hex" {
			t.Errorf("expected Encoded=%q, got %q", "hex", m.Encoded)
		}
	}
}

func TestCheckEnvLeakText_NoSecrets(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// No env secrets configured
	s.envSecrets = nil
	matches := s.checkEnvLeakText("some text with anything")
	if len(matches) != 0 {
		t.Errorf("expected no matches with empty envSecrets, got %d", len(matches))
	}
}

func TestCheckEnvLeakText_HexEncoded(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := "SuperSecretTestValue99" //nolint:goconst // test value
	s.envSecrets = []string{secret}

	hexEncoded := hex.EncodeToString([]byte(secret))
	matches := s.checkEnvLeakText("data: " + hexEncoded)
	if len(matches) == 0 {
		t.Error("expected hex-encoded env leak to be caught")
	}
}

func TestCheckEnvLeakText_Base32Encoded(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := "Base32TestSecretValue!" //nolint:goconst // test value
	s.envSecrets = []string{secret}

	b32Encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	matches := s.checkEnvLeakText("data: " + b32Encoded)
	if len(matches) == 0 {
		t.Error("expected base32-encoded env leak to be caught")
	}
}

func TestCheckEnvLeakText_URLSafeBase64(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	// Use a secret that produces different URL-safe vs standard base64
	secret := "Secret?With>Special+Chars" //nolint:goconst // test value
	s.envSecrets = []string{secret}

	urlEncoded := base64.URLEncoding.EncodeToString([]byte(secret))
	stdEncoded := base64.StdEncoding.EncodeToString([]byte(secret))

	// Verify they differ (otherwise this test isn't testing the URL-safe path)
	if urlEncoded == stdEncoded {
		t.Skip("URL-safe and standard base64 encodings are the same for this secret")
	}

	matches := s.checkEnvLeakText("data: " + urlEncoded)
	if len(matches) == 0 {
		t.Error("expected URL-safe base64-encoded env leak to be caught")
	}
}

func TestScanTextForDLP_DoubleURLEncoding(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Double URL-encode an AWS key: AKIA... → %41%4B%49%41... → %2541%254B...
	// Single QueryUnescape would only decode one layer, missing the key.
	aws := "AKIA" + strings.Repeat("Z", 16)
	singleEncoded := url.QueryEscape(aws)
	doubleEncoded := url.QueryEscape(singleEncoded)

	result := s.ScanTextForDLP(doubleEncoded)
	if result.Clean {
		t.Fatal("expected DLP to catch double-URL-encoded AWS key via IterativeDecode")
	}
	found := false
	for _, m := range result.Matches {
		if m.PatternName == "AWS Access Key" { //nolint:goconst // test value
			found = true
		}
	}
	if !found {
		t.Errorf("expected AWS Access Key pattern match, got: %v", result.Matches)
	}
}

func TestScanTextForDLP_URLEncodedNullByte(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// URL-encoded null byte %00 in the middle of a secret. After IterativeDecode,
	// the null byte should be stripped by matchDLPPatterns and the key detected.
	key := "sk-ant-%00" + strings.Repeat("a", 25) //nolint:goconst // test value
	result := s.ScanTextForDLP(key)
	if result.Clean {
		t.Fatal("expected DLP to catch key with URL-encoded null byte")
	}
	found := false
	for _, m := range result.Matches {
		if strings.Contains(m.PatternName, "Anthropic") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Anthropic API Key match, got: %v", result.Matches)
	}
}

func TestScanTextForDLP_DNSSubdomainExfil(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name      string
		text      string
		wantClean bool
		wantEnc   string
	}{
		{
			name:      "secret split across subdomains",
			text:      "https://sk-ant-api03.AABBCCDD.EEFFGGHH.IIJJKKLL.evil.com/",
			wantClean: false,
			wantEnc:   "subdomain",
		},
		{
			name:      "long key in single subdomain - caught by raw match",
			text:      "https://" + "sk-ant-" + strings.Repeat("a", 25) + ".evil.com/",
			wantClean: false,
		},
		{
			name:      "AWS key split across subdomains",
			text:      "https://AKIA.IOSFODNN.7EXAMPLE1.evil.com/",
			wantClean: false,
			wantEnc:   "subdomain",
		},
		{
			name:      "normal domain with dots - no false positive",
			text:      "https://www.google.com/search?q=hello",
			wantClean: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ScanTextForDLP(tt.text)
			if result.Clean != tt.wantClean {
				t.Errorf("Clean = %v, want %v (matches: %v)", result.Clean, tt.wantClean, result.Matches)
			}
			if tt.wantEnc != "" {
				found := false
				for _, m := range result.Matches {
					if m.Encoded == tt.wantEnc {
						found = true
					}
				}
				if !found {
					t.Errorf("expected encoding=%q in matches, got: %v", tt.wantEnc, result.Matches)
				}
			}
		})
	}
}

func TestScanTextForDLP_ControlCharBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Build key at runtime to avoid gitleaks
	prefix := "sk-ant-"
	suffix := strings.Repeat("a", 25) //nolint:goconst // test value

	tests := []struct {
		name    string
		ctrlStr string
	}{
		{"null_byte", "\x00"},
		{"backspace", "\x08"},
		{"tab", "\x09"},
		{"newline", "\x0a"},
		{"carriage_return", "\x0d"},
		{"vertical_tab", "\x0b"},
		{"escape", "\x1b"},
		{"DEL", "\x7f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := prefix + tt.ctrlStr + suffix
			result := s.ScanTextForDLP(text)
			if result.Clean {
				t.Errorf("expected DLP to catch key with %s control char", tt.name)
			}
		})
	}
}

func TestScanTextForDLP_MultipleControlChars(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Multiple control chars scattered through an AWS key
	key := "AKIA" + "\x08" + "IOSFODNN" + "\x09" + "7EXAMPLE"
	result := s.ScanTextForDLP(key)
	if result.Clean {
		t.Error("expected DLP to catch AWS key with multiple control chars")
	}
}

// --- DLP confusable/combining mark bypass tests ---

func TestScanTextForDLP_ConfusableBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name        string
		text        string
		wantPattern string
	}{
		{
			name:        "Cyrillic_a_in_Anthropic_key",
			text:        "sk-\u0430nt-" + strings.Repeat("a", 25), // Cyrillic а U+0430
			wantPattern: "Anthropic API Key",
		},
		{
			name:        "Armenian_a_in_Anthropic_key",
			text:        "sk-\u0561nt-" + strings.Repeat("a", 25), // Armenian ա U+0561 → 'a'
			wantPattern: "Anthropic API Key",
		},
		{
			name:        "Greek_A_in_AWS_key",
			text:        "\u0391KIA" + strings.Repeat("B", 16), // Greek Α U+0391 for A
			wantPattern: "AWS Access Key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ScanTextForDLP(tt.text)
			if result.Clean {
				t.Errorf("confusable bypass not caught: %s", tt.name)
			}
			found := false
			for _, m := range result.Matches {
				if strings.Contains(m.PatternName, tt.wantPattern) {
					found = true
				}
			}
			if !found {
				t.Errorf("expected %s match, got: %v", tt.wantPattern, result.Matches)
			}
		})
	}
}

func TestScanTextForDLP_CombiningMarkBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Combining long stroke overlay (U+0337) inserted into key prefix
	key := "sk-a\u0337nt-" + strings.Repeat("a", 25) //nolint:goconst // test value
	result := s.ScanTextForDLP(key)
	if result.Clean {
		t.Error("expected DLP to catch key with combining mark in prefix")
	}
}

func TestScanTextForDLP_LatinSmallCapBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Latin small cap letters in GitHub token prefix
	key := "ghp_" + strings.Repeat("D", 40) //nolint:goconst // test value
	// Replace 'g' with Latin Small Capital G (not in confusable map, but 'ghp_' starts with lowercase g)
	// Test combining mark + confusable in same key
	keyWithMark := "gh\u0307p_" + strings.Repeat("D", 40)
	result := s.ScanTextForDLP(keyWithMark)
	if result.Clean {
		t.Error("expected DLP to catch GitHub token with combining mark")
	}

	// Verify clean key still matches
	result = s.ScanTextForDLP(key)
	if result.Clean {
		t.Error("expected DLP to catch clean GitHub token")
	}
}

// --- File Secret Text DLP Tests ---

func TestScanTextForDLP_FileSecretRawMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "MyFileSecretValue1234" //nolint:goconst // test value
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	result := s.ScanTextForDLP("Here is the secret: " + secret)
	if result.Clean {
		t.Error("expected file secret to be detected in text")
	}
	found := false
	for _, m := range result.Matches {
		if m.PatternName == "Known Secret Leak" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Known Secret Leak' pattern, got %v", result.Matches)
	}
}

func TestScanTextForDLP_FileSecretBase64Match(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "MyFileSecretValue1234" //nolint:goconst // test value
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	result := s.ScanTextForDLP(encoded)
	if result.Clean {
		t.Error("expected base64-encoded file secret to be detected")
	}
}

func TestScanTextForDLP_FileSecretHexMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "MyFileSecretValue1234" //nolint:goconst // test value
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := hex.EncodeToString([]byte(secret))
	result := s.ScanTextForDLP(encoded)
	if result.Clean {
		t.Error("expected hex-encoded file secret to be detected")
	}
}

func TestScanTextForDLP_FileSecretBase32Match(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "MyFileSecretValue1234" //nolint:goconst // test value
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	result := s.ScanTextForDLP(encoded)
	if result.Clean {
		t.Error("expected base32-encoded file secret to be detected")
	}
}

func TestScanTextForDLP_FileSecretDistinctFromEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	fileSecret := "FileOnlySecretValue1" //nolint:goconst // test value
	if err := os.WriteFile(path, []byte(fileSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	// Also inject an env secret
	s.envSecrets = []string{"EnvOnlySecretValue11"}

	// Text contains file secret — should match "Known Secret Leak"
	result := s.ScanTextForDLP(fileSecret)
	if result.Clean {
		t.Fatal("expected detection")
	}
	for _, m := range result.Matches {
		if m.PatternName == "Environment Variable Leak" {
			t.Error("file secret should NOT produce 'Environment Variable Leak' pattern")
		}
	}
}

func TestScanTextForDLP_NoFileSecrets_Clean(t *testing.T) {
	cfg := testConfig()
	// No secrets_file configured
	s := New(cfg)
	defer s.Close()

	result := s.ScanTextForDLP("This text contains no secrets at all.")
	if !result.Clean {
		t.Errorf("expected clean result with no file secrets, got %v", result.Matches)
	}
}
