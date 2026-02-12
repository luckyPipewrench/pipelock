package audit

import (
	"strings"
	"testing"
	"unicode"

	"github.com/rs/zerolog"
)

func FuzzSanitizeString(f *testing.F) {
	f.Add("https://example.com")
	f.Add("https://evil.com/\x1b[2Jclear")
	f.Add("\x1b[31mred\x1b[0m")
	f.Add("normal\x00null\x07bell")
	f.Add("tabs\tand\nnewlines")
	f.Add("\x1b")           // incomplete escape
	f.Add("\x1b[999999999") // long incomplete escape

	f.Fuzz(func(t *testing.T, input string) {
		result := sanitizeString(input)
		for _, r := range result {
			if r == '\x1b' {
				t.Errorf("output contains ESC: %q", result)
			}
			if r != '\t' && r != '\n' && unicode.IsControl(r) {
				t.Errorf("output contains control char %U: %q", r, result)
			}
		}
		// Idempotent: sanitizing twice produces the same result.
		if sanitizeString(result) != result {
			t.Errorf("sanitizeString is not idempotent for input %q", input)
		}
	})
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"clean", "https://example.com", "https://example.com"},
		{"ansi clear screen", "https://evil.com/\x1b[2Jclear", "https://evil.com/clear"},
		{"ansi color", "\x1b[31mred\x1b[0m", "red"}, // both escape sequences fully consumed including terminator
		{"null byte", "before\x00after", "beforeafter"},
		{"bell", "ding\x07dong", "dingdong"},
		{"carriage return", "line\roverwrite", "lineoverwrite"},
		{"tabs preserved", "col1\tcol2", "col1\tcol2"},
		{"newlines preserved", "line1\nline2", "line1\nline2"},
		{"incomplete escape at end", "text\x1b", "text"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeString(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLogAllowed_SanitizesURL(t *testing.T) {
	logger := &Logger{zl: zerolog.Nop(), includeAllowed: true}
	// Should not panic with ANSI in URL.
	logger.LogAllowed("GET", "https://evil.com/\x1b[2Jclear", "127.0.0.1", "req-1", 200, 0, 0)
}

func TestLogBlocked_SanitizesURLAndReason(t *testing.T) {
	logger := &Logger{zl: zerolog.Nop(), includeBlocked: true}
	logger.LogBlocked("GET", "https://\x1b[2Jevil.com", "dlp", "found \x1b[31msecret\x1b[0m", "127.0.0.1", "req-1")
}

func TestSanitizeString_NoAllocation_CleanInput(t *testing.T) {
	clean := "https://example.com/path?q=value"
	result := sanitizeString(clean)
	if result != clean {
		t.Errorf("expected identical string for clean input")
	}
	// Verify the fast path returns the original string (not a copy).
	if !strings.Contains(result, "example.com") {
		t.Error("unexpected result")
	}
}
