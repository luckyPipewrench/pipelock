package plsentry

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testEnvSecret = "my-super-secret-value-12345"
	testAWSKeyID  = "AKIA" + "IOSFODNN7EXAMPLE" // split to dodge gosec G101
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
	tests := []struct {
		name  string
		input string
	}{
		{"AWS key", "error at url with " + testAWSKeyID},
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
	s := NewScrubber(testDLPPatterns(), nil)

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
	s := NewScrubber(nil, []string{testEnvSecret})
	input := "error: env value was " + testEnvSecret + " in context"
	result := s.ScrubString(input)
	if result == input {
		t.Error("expected env secret to be scrubbed")
	}
	if !containsRedacted(result) {
		t.Errorf("expected [REDACTED] in result %q", result)
	}
}

func TestScrubString_URLAuthorityAndPathDropped(t *testing.T) {
	s := NewScrubber(nil, nil)
	input := "mcp upstream failed: " + fakeURLWithUserinfo("user", "novel-secret", "internal-host.example", "/p?q=secret")
	result := s.ScrubString(input)

	for _, forbidden := range []string{"user", "novel-secret", "internal-host.example", "/p", "q=secret"} {
		if strings.Contains(result, forbidden) {
			t.Fatalf("URL component %q leaked in %q", forbidden, result)
		}
	}
	if !strings.Contains(result, "wss://"+redacted) {
		t.Fatalf("expected coarse redacted URL, got %q", result)
	}
}

func TestScrubEvent_AllowlistPayloadShape(t *testing.T) {
	eventTime := time.Unix(1700000000, 0).UTC()
	s := NewScrubber(testDLPPatterns(), nil)
	event := &sentry.Event{
		EventID:    "1234567890abcdef1234567890abcdef",
		Timestamp:  eventTime,
		Level:      sentry.LevelError,
		Message:    "failed with " + testAWSKeyID,
		Release:    "v1.2.3",
		ServerName: "prod-secret-host-01.internal",
		User:       sentry.User{ID: "user-123", IPAddress: "192.0.2.10"},
		Request:    &sentry.Request{URL: "https://api.vendor.example/private", Method: "POST"},
		Breadcrumbs: []*sentry.Breadcrumb{
			{Message: "visited private path", Data: map[string]interface{}{"url": "https://api.vendor.example/private"}},
		},
		Tags:     map[string]string{"tenant": "acme-prod"},
		Contexts: map[string]sentry.Context{"custom": {"hostname": "prod-secret-host-01.internal"}},
		Modules:  map[string]string{"github.com/private/module": "v0.0.1"},
		Attachments: []*sentry.Attachment{
			{Filename: "secret.txt", Payload: []byte("secret")},
		},
		Exception: []sentry.Exception{
			{
				Type:  "error at " + testAWSKeyID,
				Value: "upstream failed with " + testAWSKeyID,
				Stacktrace: &sentry.Stacktrace{
					Frames: []sentry.Frame{
						{
							Function:    "runProxy",
							Module:      "github.com/luckyPipewrench/pipelock/internal/cli/runtime",
							Filename:    "/home/developer/project/internal/cli/runtime/mcp.go",
							AbsPath:     "/home/developer/project/internal/cli/runtime/mcp.go",
							Lineno:      1115,
							ContextLine: "return upstreamURL.String()",
							Vars:        map[string]interface{}{"upstream": fakeURLWithUserinfo("user", "secret", "host", "/p")},
						},
					},
				},
			},
		},
	}

	result := s.ScrubEvent(event, nil)
	if result == nil {
		t.Fatal("expected sanitized event")
	}
	if result.EventID != event.EventID || !result.Timestamp.Equal(eventTime) || result.Level != sentry.LevelError || result.Release != "v1.2.3" {
		t.Fatalf("safe scalar fields not preserved: %+v", result)
	}
	if !containsRedacted(result.Message) || !containsRedacted(result.Exception[0].Type) || !containsRedacted(result.Exception[0].Value) {
		t.Fatalf("expected surviving diagnostic strings to be scrubbed: %+v", result.Exception[0])
	}
	if result.Request != nil || result.ServerName != "" || result.User.ID != "" || len(result.Breadcrumbs) != 0 ||
		len(result.Tags) != 0 || len(result.Contexts) != 0 || len(result.Modules) != 0 || len(result.Attachments) != 0 {
		t.Fatalf("unsafe event fields survived: %+v", result)
	}

	frame := result.Exception[0].Stacktrace.Frames[0]
	if frame.Filename != "mcp.go" || frame.Lineno != 1115 || frame.Function != "runProxy" {
		t.Fatalf("safe frame fields not preserved: %+v", frame)
	}
	if frame.AbsPath != "" || frame.ContextLine != "" || len(frame.PreContext) != 0 || len(frame.PostContext) != 0 || len(frame.Vars) != 0 {
		t.Fatalf("unsafe frame fields survived: %+v", frame)
	}

	if result.DebugMeta != nil || len(result.Spans) != 0 || len(result.Logs) != 0 || len(result.Metrics) != 0 {
		t.Fatalf("unsafe event type fields survived: %+v", result)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal sanitized event: %v", err)
	}
	payload := string(raw)
	for _, forbidden := range []string{"request", "user", "server_name", "breadcrumbs", "tags", "contexts", "modules", "debug_meta", "attachments", "vars", "abs_path", "context_line"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("forbidden field %q survived in payload: %s", forbidden, payload)
		}
	}
}

func TestScrubEvent_UpstreamURLUserinfoHostPathDropped(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Exception: []sentry.Exception{{
			Type:  "mcp upstream error",
			Value: "connect failed for " + fakeURLWithUserinfo("urluser", "novel-secret", "internal-host.example", "/p"),
		}},
	}

	result := s.ScrubEvent(event, nil)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal sanitized event: %v", err)
	}
	payload := string(raw)
	for _, forbidden := range []string{"urluser", "novel-secret", "internal-host.example", "/p"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("forbidden URL component %q survived in payload: %s", forbidden, payload)
		}
	}
}

func TestScrubEvent_SanitizerPanicDropsEvent(t *testing.T) {
	s := &Scrubber{patterns: []*regexp.Regexp{nil}}
	result := s.ScrubEvent(&sentry.Event{Message: "panic path"}, nil)
	if result != nil {
		t.Fatalf("expected sanitizer panic to drop event, got %+v", result)
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
	if len(s.patterns) < len(safetyNetPatterns)+1 {
		t.Errorf("expected at least %d patterns, got %d", len(safetyNetPatterns)+1, len(s.patterns))
	}
}

func TestScrubString_SafetyNetPatternsAlwaysApplied(t *testing.T) {
	s := NewScrubber(nil, nil)
	bearerInput := "header: Bearer " + "some-token-value-here"
	result := s.ScrubString(bearerInput)
	if !containsRedacted(result) {
		t.Errorf("expected safety-net Bearer pattern to scrub, got %q", result)
	}
}

func containsRedacted(s string) bool {
	return strings.Contains(s, redacted)
}

func fakeURLWithUserinfo(user, pass, host, path string) string {
	return "wss://" + user + ":" + pass + "@" + host + path
}
