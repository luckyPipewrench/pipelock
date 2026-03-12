package plsentry

import (
	"strings"
	"testing"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func testDLPPatterns() []config.DLPPattern {
	return []config.DLPPattern{
		{Name: "AWS Access Key", Regex: `AKIA[0-9A-Z]{16}`, Severity: "critical"},
		{Name: "GitHub Token", Regex: `ghp_[A-Za-z0-9]{36}`, Severity: "critical"},
		{Name: "Anthropic API Key", Regex: `sk-ant-[a-zA-Z0-9\-_]{10,}`, Severity: "critical"},
		{Name: "Slack Token", Regex: `xox[bpras]-[0-9a-zA-Z-]{15,}`, Severity: "critical"},
	}
}

func TestScrubString_DLPPatterns(t *testing.T) {
	// Build fake credentials at runtime for gosec G101.
	tests := []struct {
		name  string
		input string
	}{
		{"AWS key", "error at url with " + "AKIA" + "IOSFODNN7EXAMPLE"},
		{"GitHub token", "failed for " + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
		{"Anthropic key", "request to " + "sk-ant-" + "api03-abcdef1234"},
		{"Bearer token", "Authorization header Bearer " + "eyJhbGciOiJIUzI1NiJ9.test"},
		{"Slack token", "webhook " + "xoxb-" + "123456789012345"},
	}

	s := NewScrubber(testDLPPatterns(), nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.ScrubString(tt.input)
			if result == tt.input {
				t.Errorf("expected secret to be scrubbed from %q", tt.input)
			}
			if !containsRedacted(result) {
				t.Errorf("expected [REDACTED] in result %q", result)
			}
		})
	}
}

func TestScrubString_DLPPatterns_CaseInsensitive(t *testing.T) {
	// DLP patterns are auto-prefixed with (?i) so mixed-case variants must
	// still be scrubbed. This mirrors the scanner.New() behavior.
	s := NewScrubber(testDLPPatterns(), nil)

	// "ghp_" token with the prefix chars in different case won't match the
	// original regex literally, but the real vector is an agent upper-casing
	// secrets. Use a Slack token variant since xox is case-sensitive in the
	// regex but agents can uppercase.
	mixedCase := "webhook " + "XOXb-" + "123456789012345"
	result := s.ScrubString(mixedCase)
	if result == mixedCase {
		t.Errorf("expected mixed-case Slack token to be scrubbed, got %q", result)
	}
	if !containsRedacted(result) {
		t.Errorf("expected [REDACTED] in result %q", result)
	}
}

func TestScrubString_SafetyNet_CaseInsensitive(t *testing.T) {
	s := NewScrubber(nil, nil)

	// Lowercase "bearer" and "authorization" must still be caught.
	lower := "header: bearer " + "eyJhbGciOiJIUzI1NiJ9.test"
	result := s.ScrubString(lower)
	if result == lower {
		t.Errorf("expected lowercase bearer to be scrubbed, got %q", result)
	}
	if !containsRedacted(result) {
		t.Errorf("expected [REDACTED] in result %q", result)
	}

	authLower := "authorization: Basic dXNlcjpwYXNz"
	result = s.ScrubString(authLower)
	if result == authLower {
		t.Errorf("expected lowercase authorization to be scrubbed, got %q", result)
	}
}

func TestScrubString_NonSecretPassesThrough(t *testing.T) {
	s := NewScrubber(testDLPPatterns(), nil)
	input := "normal error message without secrets"
	result := s.ScrubString(input)
	// URL param scrubbing won't affect this since there are no URL params.
	if result != input {
		t.Errorf("expected unchanged string, got %q", result)
	}
}

func TestScrubString_EmptyString(t *testing.T) {
	s := NewScrubber(testDLPPatterns(), nil)
	if s.ScrubString("") != "" {
		t.Error("expected empty string to pass through")
	}
}

func TestScrubString_EnvSecrets(t *testing.T) {
	secret := "my-super-secret-value-12345" //nolint:goconst // test value
	s := NewScrubber(nil, []string{secret})
	input := "error: env value was " + secret + " in context"
	result := s.ScrubString(input)
	if result == input {
		t.Error("expected env secret to be scrubbed")
	}
	if !containsRedacted(result) {
		t.Errorf("expected [REDACTED] in result %q", result)
	}
}

func TestScrubString_URLQueryParams(t *testing.T) {
	s := NewScrubber(nil, nil)
	input := "error fetching https://example.com/api?token=secretvalue&user=admin" // pipelock:ignore Credential in URL
	result := s.ScrubString(input)
	if result == input {
		t.Error("expected URL query params to be scrubbed")
	}
}

func TestScrubEvent_Message(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE" //nolint:goconst // test value
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Message: "error with key " + awsKey,
	}
	result := s.ScrubEvent(event, nil)
	if result.Message == event.Message {
		// ScrubEvent modifies in-place, so compare against original value
		t.Log("message was scrubbed in-place, checking for redaction")
	}
	if !containsRedacted(result.Message) {
		t.Errorf("expected [REDACTED] in message %q", result.Message)
	}
}

func TestScrubEvent_Exception(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Exception: []sentry.Exception{
			{
				Value: "secret " + awsKey + " leaked",
				Stacktrace: &sentry.Stacktrace{
					Frames: []sentry.Frame{
						{Vars: map[string]interface{}{"key": awsKey}},
					},
				},
			},
		},
	}
	result := s.ScrubEvent(event, nil)
	if !containsRedacted(result.Exception[0].Value) {
		t.Errorf("expected [REDACTED] in exception value %q", result.Exception[0].Value)
	}
	if sv, ok := result.Exception[0].Stacktrace.Frames[0].Vars["key"].(string); !ok || !containsRedacted(sv) {
		t.Errorf("expected [REDACTED] in frame vars")
	}
}

func TestScrubEvent_Breadcrumbs(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Breadcrumbs: []*sentry.Breadcrumb{
			{
				Message: "fetching with " + awsKey,
				Data:    map[string]interface{}{"url": "https://api.example.com?key=" + awsKey},
			},
		},
	}
	result := s.ScrubEvent(event, nil)
	if !containsRedacted(result.Breadcrumbs[0].Message) {
		t.Errorf("expected [REDACTED] in breadcrumb message %q", result.Breadcrumbs[0].Message)
	}
}

func TestScrubEvent_Tags(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Tags: map[string]string{"url": "https://api.example.com/" + awsKey},
	}
	result := s.ScrubEvent(event, nil)
	if !containsRedacted(result.Tags["url"]) {
		t.Errorf("expected [REDACTED] in tag %q", result.Tags["url"])
	}
}

func TestScrubEvent_Extra(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Extra: map[string]interface{}{"detail": "key=" + awsKey},
	}
	result := s.ScrubEvent(event, nil)
	sv, ok := result.Extra["detail"].(string)
	if !ok {
		t.Fatal("expected extra detail to be string")
	}
	if !containsRedacted(sv) {
		t.Errorf("expected [REDACTED] in extra %q", sv)
	}
}

func TestScrubEvent_RequestWiped(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Request: &sentry.Request{
			URL:    "https://api.example.com/secret",
			Method: "POST",
		},
	}
	result := s.ScrubEvent(event, nil)
	if result.Request != nil {
		t.Error("expected Request to be wiped")
	}
}

func TestScrubEvent_UserWiped(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		User: sentry.User{
			ID:        "123",
			IPAddress: "192.168.1.1",
		},
	}
	result := s.ScrubEvent(event, nil)
	if result.User.ID != "" || result.User.IPAddress != "" {
		t.Error("expected User to be wiped")
	}
}

func TestScrubEvent_NilEvent(t *testing.T) {
	s := NewScrubber(nil, nil)
	result := s.ScrubEvent(nil, nil)
	if result != nil {
		t.Error("expected nil for nil event")
	}
}

func TestNewScrubber_InvalidPatternSkipped(t *testing.T) {
	patterns := []config.DLPPattern{
		{Name: "Invalid", Regex: `[invalid`, Severity: "high"},
		{Name: "Valid", Regex: `secret`, Severity: "high"},
	}
	s := NewScrubber(patterns, nil)
	// Should not panic. Safety-net patterns + one valid = at least len(safetyNetPatterns)+1.
	if len(s.patterns) < len(safetyNetPatterns)+1 {
		t.Errorf("expected at least %d patterns, got %d", len(safetyNetPatterns)+1, len(s.patterns))
	}
}

func TestScrubString_SafetyNetPatternsAlwaysApplied(t *testing.T) {
	// Even with no config DLP patterns, safety-net patterns should work.
	s := NewScrubber(nil, nil)
	bearerInput := "header: Bearer " + "some-token-value-here"
	result := s.ScrubString(bearerInput)
	if !containsRedacted(result) {
		t.Errorf("expected safety-net Bearer pattern to scrub, got %q", result)
	}
}

func TestScrubEvent_ServerNameWiped(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		ServerName: "prod-secret-host-01.internal.corp",
	}
	result := s.ScrubEvent(event, nil)
	if result.ServerName != "" {
		t.Errorf("expected ServerName to be wiped, got %q", result.ServerName)
	}
}

func TestScrubEvent_ExceptionType(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Exception: []sentry.Exception{
			{
				Type:  "error at " + awsKey,
				Value: "some value",
			},
		},
	}
	result := s.ScrubEvent(event, nil)
	if !containsRedacted(result.Exception[0].Type) {
		t.Errorf("expected [REDACTED] in exception type %q", result.Exception[0].Type)
	}
}

func TestScrubEvent_Transaction(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Transaction: "/api/fetch?key=" + awsKey,
	}
	result := s.ScrubEvent(event, nil)
	if !containsRedacted(result.Transaction) {
		t.Errorf("expected [REDACTED] in transaction %q", result.Transaction)
	}
}

func TestScrubEvent_Fingerprint(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Fingerprint: []string{"error-group", "key=" + awsKey},
	}
	result := s.ScrubEvent(event, nil)
	if !containsRedacted(result.Fingerprint[1]) {
		t.Errorf("expected [REDACTED] in fingerprint %q", result.Fingerprint[1])
	}
}

func TestScrubEvent_ExtraNonStringDeleted(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Extra: map[string]interface{}{
			"safe_string": "hello",
			"dangerous":   []byte("secret bytes"),
			"number":      42,
		},
	}
	result := s.ScrubEvent(event, nil)
	if _, ok := result.Extra["dangerous"]; ok {
		t.Error("expected non-string Extra value to be deleted (fail-closed)")
	}
	if _, ok := result.Extra["number"]; ok {
		t.Error("expected non-string Extra value to be deleted (fail-closed)")
	}
	if _, ok := result.Extra["safe_string"]; !ok {
		t.Error("expected string Extra value to be preserved")
	}
}

func TestScrubEvent_BreadcrumbDataNonStringDeleted(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Breadcrumbs: []*sentry.Breadcrumb{
			{
				Message: "test",
				Data: map[string]interface{}{
					"safe":      "value",
					"dangerous": map[string]interface{}{"nested": "secret"},
				},
			},
		},
	}
	result := s.ScrubEvent(event, nil)
	if _, ok := result.Breadcrumbs[0].Data["dangerous"]; ok {
		t.Error("expected non-string breadcrumb data to be deleted (fail-closed)")
	}
	if _, ok := result.Breadcrumbs[0].Data["safe"]; !ok {
		t.Error("expected string breadcrumb data to be preserved")
	}
}

func TestScrubEvent_ContextsStringScrubbed(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Contexts: map[string]sentry.Context{
			"custom": {"url": "https://api.example.com/" + awsKey},
		},
	}
	result := s.ScrubEvent(event, nil)
	sv, ok := result.Contexts["custom"]["url"].(string)
	if !ok {
		t.Fatal("expected context value to remain string")
	}
	if !containsRedacted(sv) {
		t.Errorf("expected [REDACTED] in context value %q", sv)
	}
}

func TestScrubEvent_ContextsNonStringDeleted(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Contexts: map[string]sentry.Context{
			"custom": {
				"safe":      "value",
				"dangerous": []byte("secret bytes"),
				"number":    42,
			},
		},
	}
	result := s.ScrubEvent(event, nil)
	if _, ok := result.Contexts["custom"]["dangerous"]; ok {
		t.Error("expected non-string Context value to be deleted (fail-closed)")
	}
	if _, ok := result.Contexts["custom"]["number"]; ok {
		t.Error("expected non-string Context value to be deleted (fail-closed)")
	}
	if _, ok := result.Contexts["custom"]["safe"]; !ok {
		t.Error("expected string Context value to be preserved")
	}
}

func TestScrubEvent_VarsNonStringDeleted(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Exception: []sentry.Exception{
			{
				Value: "error",
				Stacktrace: &sentry.Stacktrace{
					Frames: []sentry.Frame{
						{Vars: map[string]interface{}{
							"safe":      "value",
							"dangerous": []string{"nested"},
						}},
					},
				},
			},
		},
	}
	result := s.ScrubEvent(event, nil)
	vars := result.Exception[0].Stacktrace.Frames[0].Vars
	if _, ok := vars["dangerous"]; ok {
		t.Error("expected non-string Vars value to be deleted (fail-closed)")
	}
	if _, ok := vars["safe"]; !ok {
		t.Error("expected string Vars value to be preserved")
	}
}

func TestScrubEvent_ThreadsVarsScrubbed(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		Threads: []sentry.Thread{
			{
				ID:   "1",
				Name: "main",
				Stacktrace: &sentry.Stacktrace{
					Frames: []sentry.Frame{
						{Vars: map[string]interface{}{"key": awsKey, "safe": "hello"}},
					},
				},
			},
		},
	}
	result := s.ScrubEvent(event, nil)
	sv, ok := result.Threads[0].Stacktrace.Frames[0].Vars["key"].(string)
	if !ok || !containsRedacted(sv) {
		t.Errorf("expected [REDACTED] in thread frame vars, got %v", result.Threads[0].Stacktrace.Frames[0].Vars["key"])
	}
	if _, ok := result.Threads[0].Stacktrace.Frames[0].Vars["safe"]; !ok {
		t.Error("expected safe string var to be preserved in thread")
	}
}

func TestScrubEvent_ThreadsVarsNonStringDeleted(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Threads: []sentry.Thread{
			{
				ID: "1",
				Stacktrace: &sentry.Stacktrace{
					Frames: []sentry.Frame{
						{Vars: map[string]interface{}{
							"safe":      "value",
							"dangerous": 42,
						}},
					},
				},
			},
		},
	}
	result := s.ScrubEvent(event, nil)
	vars := result.Threads[0].Stacktrace.Frames[0].Vars
	if _, ok := vars["dangerous"]; ok {
		t.Error("expected non-string thread var to be deleted (fail-closed)")
	}
	if _, ok := vars["safe"]; !ok {
		t.Error("expected string thread var to be preserved")
	}
}

func TestScrubEvent_ThreadsNilStacktrace(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Threads: []sentry.Thread{
			{ID: "1", Stacktrace: nil},
		},
	}
	// Should not panic on nil stacktrace.
	result := s.ScrubEvent(event, nil)
	if len(result.Threads) != 1 {
		t.Errorf("expected 1 thread, got %d", len(result.Threads))
	}
}

func containsRedacted(s string) bool {
	return strings.Contains(s, redacted)
}
