package plsentry

import (
	"encoding/json"
	"regexp"
	"runtime"
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

func TestScrubString_ProtocolRelativeURLPathDropped(t *testing.T) {
	s := NewScrubber(nil, nil)
	input := `parse "//internal-host.example/private-agent/token?key=secret": missing protocol scheme`
	result := s.ScrubString(input)

	for _, forbidden := range []string{"internal-host.example", "/private-agent", "token", "key=secret"} {
		if strings.Contains(result, forbidden) {
			t.Fatalf("protocol-relative URL component %q leaked in %q", forbidden, result)
		}
	}
	if !strings.Contains(result, "//"+redacted) {
		t.Fatalf("expected coarse protocol-relative URL redaction, got %q", result)
	}
}

func TestScrubString_DeploymentLocatorsDropped(t *testing.T) {
	s := NewScrubber(nil, nil)
	input := strings.Join([]string{
		"open /home/agent/.config/pipelock/private.yaml: permission denied",
		`open C:\Users\agent\AppData\Roaming\pipelock\private.yaml: access denied`,
		`open \\fileserver\share\private.yaml: access denied`,
		"dial tcp 10.0.0.12:8443: connect: connection refused",
		"dial tcp 10.0.0.12:8443/private-token: connect: connection refused",
		"lookup internal-host.example on 10.0.0.2:53: no such host",
		"x509: certificate is valid for private.service.internal, not public.vendor.example",
		"upstream private.service.internal/v1/secret refused",
		"dial tcp [fd00::10]:443: connect: network unreachable",
		"dial tcp [fd00::10]:443/private-token: network unreachable",
		"proxy auth failed for deployer:novel-secret@private.service.internal:443/private-token",
	}, "\n")

	result := s.ScrubString(input)
	for _, forbidden := range []string{
		"/home/agent",
		`C:\Users\agent`,
		`\\fileserver\share`,
		"10.0.0.12",
		"10.0.0.2",
		"internal-host.example",
		"private.service.internal",
		"public.vendor.example",
		"fd00::10",
		"private-token",
		"/v1/secret",
		"deployer",
		"novel-secret",
	} {
		if strings.Contains(result, forbidden) {
			t.Fatalf("deployment locator %q leaked in %q", forbidden, result)
		}
	}
	if !containsRedacted(result) {
		t.Fatalf("expected redaction marker in %q", result)
	}
}

func TestRedactionPipeline_SharedStringAndCodeSurfaces(t *testing.T) {
	s := NewScrubber(nil, []string{testEnvSecret})
	input := "failed at " + fakeURLWithUserinfo("user", testEnvSecret, "internal-host.example", "/private") +
		" api_key=novel-secret"

	for name, scrub := range map[string]func(string) string{
		"string": s.ScrubString,
		"code":   s.safeScrubCodeString,
	} {
		t.Run(name, func(t *testing.T) {
			result := scrub(input)
			for _, forbidden := range []string{"user", testEnvSecret, "internal-host.example", "/private", "novel-secret"} {
				if strings.Contains(result, forbidden) {
					t.Fatalf("%s surface leaked %q in %q", name, forbidden, result)
				}
			}
			if !containsRedacted(result) {
				t.Fatalf("%s surface result did not include redaction marker: %q", name, result)
			}
		})
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
							Function:    "github.com/luckyPipewrench/pipelock/internal/cli/runtime.runProxy",
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
	if result.Platform != "go/"+runtime.GOOS {
		t.Fatalf("platform = %q, want coarse OS only", result.Platform)
	}
	if !containsRedacted(result.Message) || !containsRedacted(result.Exception[0].Type) || !containsRedacted(result.Exception[0].Value) {
		t.Fatalf("expected surviving diagnostic strings to be scrubbed: %+v", result.Exception[0])
	}
	if result.Request != nil || result.ServerName != "" || result.User.ID != "" || len(result.Breadcrumbs) != 0 ||
		len(result.Tags) != 0 || len(result.Contexts) != 0 || len(result.Modules) != 0 || len(result.Attachments) != 0 {
		t.Fatalf("unsafe event fields survived: %+v", result)
	}

	frame := result.Exception[0].Stacktrace.Frames[0]
	if frame.Filename != "mcp.go" || frame.Lineno != 1115 || frame.Function != "runtime.runProxy" || frame.Module != "runtime" {
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

func TestScrubEvent_ExceptionValueDropsPathsAndBareEndpoints(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Exception: []sentry.Exception{{
			Type:  "PathError",
			Value: "open /home/agent/work/private.yaml: dial tcp 10.0.0.8:443: lookup private.internal.example on 10.0.0.2:53: no such host",
		}},
	}

	result := s.ScrubEvent(event, nil)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal sanitized event: %v", err)
	}
	payload := string(raw)
	for _, forbidden := range []string{"/home/agent", "10.0.0.8", "private.internal.example", "10.0.0.2"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("deployment locator %q survived in payload: %s", forbidden, payload)
		}
	}
}

func TestScrubEvent_FrameFilenameWindowsBasenameOnly(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Exception: []sentry.Exception{{
			Stacktrace: &sentry.Stacktrace{
				Frames: []sentry.Frame{{Filename: `C:\Users\agent\src\private.go`}},
			},
		}},
	}

	result := s.ScrubEvent(event, nil)
	frame := result.Exception[0].Stacktrace.Frames[0]
	if frame.Filename != "private.go" {
		t.Fatalf("filename = %q, want basename only", frame.Filename)
	}
}

func TestSafeScrubFilename_UsesCrossPlatformLeaf(t *testing.T) {
	s := NewScrubber(nil, nil)
	key := "tok" + "en"
	result := s.safeScrubFilename(`/home/agent/src/private.go?` + key + `=novel-secret`)
	if strings.Contains(result, "/home/agent") || strings.Contains(result, "novel-secret") {
		t.Fatalf("filename scrub leaked path or token payload in %q", result)
	}
	if !strings.Contains(result, "private.go?"+key+"="+redacted) {
		t.Fatalf("filename scrub = %q, want basename with redacted token value", result)
	}
}

func TestScrubEvent_FrameIdentifiersScrubQueryPayloads(t *testing.T) {
	s := NewScrubber(nil, nil)
	event := &sentry.Event{
		Exception: []sentry.Exception{{
			Stacktrace: &sentry.Stacktrace{
				Frames: []sentry.Frame{{
					Function: "handler?" + "token=novel-secret",
					Module:   "runtime&" + "api_key=novel-secret",
					Filename: "/tmp/private-token=novel-secret.go?session=novel-secret",
				}},
			},
		}},
	}

	result := s.ScrubEvent(event, nil)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal sanitized event: %v", err)
	}
	payload := string(raw)
	if strings.Contains(payload, "novel-secret") {
		t.Fatalf("frame identifier query payload leaked in %s", payload)
	}
	frame := result.Exception[0].Stacktrace.Frames[0]
	for _, field := range []string{frame.Function, frame.Module, frame.Filename} {
		if !containsRedacted(field) {
			t.Fatalf("frame field %q did not include redaction marker", field)
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
