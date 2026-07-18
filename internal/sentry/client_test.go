// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package plsentry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const testDSN = "https://examplePublicKey@o0.ingest.sentry.io/0"

// mockTransport captures events sent through the Sentry SDK.
type mockTransport struct {
	mu                    sync.Mutex
	events                []*sentry.Event
	flushCalls            int
	flushWithContextCalls int
}

func (t *mockTransport) Configure(_ sentry.ClientOptions) {}
func (t *mockTransport) Close()                           {}

func (t *mockTransport) Flush(_ time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flushCalls++
	return true
}

func (t *mockTransport) FlushWithContext(_ context.Context) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flushWithContextCalls++
	return true
}

func (t *mockTransport) SendEvent(event *sentry.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, event)
}

func (t *mockTransport) Events() []*sentry.Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make([]*sentry.Event, len(t.events))
	copy(cp, t.events)
	return cp
}

func (t *mockTransport) FlushCalls() (int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.flushCalls, t.flushWithContextCalls
}

// initTestClient creates an enabled client with a mock transport.
func initTestClient(t *testing.T, dlpPatterns []config.DLPPattern) (*Client, *mockTransport) {
	t.Helper()
	transport := &mockTransport{}
	cfg := config.Defaults()
	enabled := true
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	cfg.DLP.Patterns = dlpPatterns
	c, err := initClient(cfg, "test-version", transport)
	if err != nil {
		t.Fatalf("unexpected Init error: %v", err)
	}
	if !c.enabled {
		t.Fatal("expected enabled client")
	}
	return c, transport
}

func TestInit_DisabledReturnsNoOp(t *testing.T) {
	f := false
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &f
	c, err := Init(cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.enabled {
		t.Error("expected disabled client")
	}
}

func TestInit_DisabledClearsStaleGlobalClient(t *testing.T) {
	t.Cleanup(func() {
		sentry.CurrentHub().BindClient(nil)
	})

	staleTransport := &mockTransport{}
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	if _, err := initClient(cfg, "test", staleTransport); err != nil {
		t.Fatalf("enable stale client: %v", err)
	}

	disabled := false
	cfg.Sentry.Enabled = &disabled
	c, err := Init(cfg, "test")
	if err != nil {
		t.Fatalf("disabled init: %v", err)
	}
	if c.enabled {
		t.Fatal("expected disabled client")
	}

	if id := sentry.CaptureMessage("must not reach stale transport"); id != nil {
		t.Fatalf("package-level capture returned event id after disabled init: %s", *id)
	}
	if events := staleTransport.Events(); len(events) != 0 {
		t.Fatalf("stale global client captured %d event(s) after disabled init", len(events))
	}
}

func TestInit_EmptyDSNReturnsNoOp(t *testing.T) {
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = ""
	// Ensure SENTRY_DSN env is not set for this test.
	t.Setenv("SENTRY_DSN", "")
	c, err := Init(cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.enabled {
		t.Error("expected disabled client when DSN is empty")
	}
}

func TestInit_EnvDSNUsedWhenConfigEmpty(t *testing.T) {
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = ""
	// Set a valid-looking DSN via env. The Sentry SDK will accept it
	// but won't actually connect in tests.
	t.Setenv("SENTRY_DSN", "https://examplePublicKey@o0.ingest.sentry.io/0")
	c, err := Init(cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.enabled {
		t.Error("expected enabled client when SENTRY_DSN env is set")
	}
}

func TestInit_EnvDSNOverridesConfig(t *testing.T) {
	envDSN := "https://envKey@o0.ingest.sentry.io/0"
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = "https://configKey@o0.ingest.sentry.io/0"
	t.Setenv("SENTRY_DSN", envDSN)

	transport := &mockTransport{}
	c, err := initClient(cfg, "test", transport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.enabled {
		t.Error("expected enabled client")
	}
	// Verify the env DSN was used by sending an event and checking it arrived
	// (if the wrong DSN were used with a real transport, it would fail).
	c.CaptureMessage("test")
	_ = c.Flush(2 * time.Second)
	if len(transport.Events()) == 0 {
		t.Error("expected event to be captured with env DSN")
	}
}

func TestNilClient_NoPanic(t *testing.T) {
	var c *Client
	// All methods should be safe no-ops on nil receiver.
	c.CaptureError(errors.New("test"))
	c.CaptureMessage("test")
	c.AddBreadcrumb("license", "expiry", "warn", map[string]any{"days": "7"})
	c.Close()
	if !c.Flush(0) {
		t.Error("expected Flush to return true on nil client")
	}
}

func TestDisabledClient_NoPanic(t *testing.T) {
	c := &Client{enabled: false}
	c.CaptureError(errors.New("test"))
	c.CaptureMessage("test")
	c.AddBreadcrumb("license", "expiry", "warn", map[string]any{"days": "7"})
	c.Close()
	if !c.Flush(0) {
		t.Error("expected Flush to return true on disabled client")
	}
}

func TestAddBreadcrumbEnabledClient(t *testing.T) {
	c, transport := initTestClient(t, nil)
	defer c.Close()

	c.AddBreadcrumb("license", "expiry warning", "warn", map[string]any{
		"threshold_days": "7",
		"days_remaining": "6",
	})
	c.CaptureMessage("license status changed")
	_ = c.Flush(time.Second)

	events := transport.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if len(events[0].Breadcrumbs) != 0 {
		t.Fatalf("breadcrumbs = %d, want 0", len(events[0].Breadcrumbs))
	}
}

func TestInit_InvalidDSNReturnsError(t *testing.T) {
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = "not-a-valid-dsn"
	c, err := Init(cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid DSN")
	}
	if c != nil {
		t.Error("expected nil client on error")
	}
}

func TestInit_InvalidDSNClearsStaleGlobalClient(t *testing.T) {
	t.Cleanup(func() {
		sentry.CurrentHub().BindClient(nil)
	})
	t.Setenv("SENTRY_DSN", "")

	staleTransport := &mockTransport{}
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	if _, err := initClient(cfg, "test", staleTransport); err != nil {
		t.Fatalf("enable stale client: %v", err)
	}

	cfg.Sentry.DSN = "not-a-valid-dsn"
	if c, err := Init(cfg, "test"); err == nil || c != nil {
		t.Fatalf("invalid dsn init = (%+v, %v), want nil client and error", c, err)
	}

	if id := sentry.CaptureMessage("must not reach stale transport"); id != nil {
		t.Fatalf("package-level capture returned event id after failed init: %s", *id)
	}
	if events := staleTransport.Events(); len(events) != 0 {
		t.Fatalf("stale global client captured %d event(s) after failed init", len(events))
	}
}

func TestInit_ScrubberPopulated(t *testing.T) {
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	cfg.DLP.Patterns = testDLPPatterns()
	c, err := Init(cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.scrubber == nil {
		t.Fatal("expected scrubber to be populated")
	}
	if len(c.scrubber.patterns) < len(safetyNetPatterns) {
		t.Errorf("expected at least %d patterns (safety-net), got %d",
			len(safetyNetPatterns), len(c.scrubber.patterns))
	}
}

func TestInit_EnvSecretsCollected(t *testing.T) {
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	cfg.DLP.ScanEnv = true
	t.Setenv("PIPELOCK_TEST_SECRET", "this-is-a-long-enough-secret")
	c, err := Init(cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.scrubber.secrets) == 0 {
		t.Error("expected env secrets to be collected when DLP.ScanEnv is true")
	}
}

func TestInit_EnvSecretsSkippedWhenScanEnvFalse(t *testing.T) {
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	cfg.DLP.ScanEnv = false
	c, err := Init(cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.scrubber.secrets) != 0 {
		t.Error("expected no env secrets when DLP.ScanEnv is false")
	}
}

func TestCaptureError_SendsEvent(t *testing.T) {
	c, transport := initTestClient(t, nil)
	defer c.Close()

	c.CaptureError(errors.New("test proxy error"))
	_ = c.Flush(2 * time.Second)

	events := transport.Events()
	if len(events) == 0 {
		t.Fatal("expected at least one event from CaptureError")
	}
}

func TestCaptureError_EventIsScrubbed(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	c, transport := initTestClient(t, testDLPPatterns())
	defer c.Close()

	c.CaptureError(errors.New("failed with key " + awsKey))
	_ = c.Flush(2 * time.Second)

	events := transport.Events()
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}
	for _, e := range events {
		for _, exc := range e.Exception {
			if strings.Contains(exc.Value, awsKey) {
				t.Errorf("secret leaked in exception value: %q", exc.Value)
			}
		}
	}
}

func TestCaptureError_DropsContextCanceled(t *testing.T) {
	c, transport := initTestClient(t, nil)
	defer c.Close()

	c.CaptureError(context.Canceled)
	c.CaptureError(fmt.Errorf("mcp proxy: %w", context.Canceled))
	_ = c.Flush(2 * time.Second)

	if events := transport.Events(); len(events) != 0 {
		t.Fatalf("expected no events for context.Canceled, got %d", len(events))
	}
}

func TestCaptureMessage_SendsEvent(t *testing.T) {
	c, transport := initTestClient(t, nil)
	defer c.Close()

	c.CaptureMessage("test message")
	_ = c.Flush(2 * time.Second)

	events := transport.Events()
	if len(events) == 0 {
		t.Fatal("expected at least one event from CaptureMessage")
	}
}

func TestCaptureMessage_EventIsScrubbed(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	c, transport := initTestClient(t, testDLPPatterns())
	defer c.Close()

	c.CaptureMessage("error with key " + awsKey)
	_ = c.Flush(2 * time.Second)

	events := transport.Events()
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}
	for _, e := range events {
		if strings.Contains(e.Message, awsKey) {
			t.Errorf("secret leaked in message: %q", e.Message)
		}
	}
}

func TestFlush_EnabledClient(t *testing.T) {
	c, _ := initTestClient(t, nil)
	defer c.Close()

	c.CaptureMessage("flush test")
	if !c.Flush(2 * time.Second) {
		t.Error("expected Flush to return true")
	}
}

func TestClose_FlushesEvents(t *testing.T) {
	c, transport := initTestClient(t, nil)

	c.CaptureMessage("before close")
	c.Close()

	events := transport.Events()
	if len(events) == 0 {
		t.Fatal("expected Close to flush pending events")
	}
}

func TestInit_FileSecretsLoaded(t *testing.T) {
	// Build secret at runtime to avoid DLP false positive (gosec G101).
	fileSecret := "superSecretVault" + "TokenValue1234"

	dir := t.TempDir()
	secretsFile := filepath.Join(dir, "secrets.txt")
	if err := os.WriteFile(secretsFile, []byte(fileSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	transport := &mockTransport{}
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = secretsFile
	c, err := initClient(cfg, "test", transport)
	if err != nil {
		t.Fatalf("unexpected Init error: %v", err)
	}

	// The file secret should be in the scrubber's secrets list.
	found := false
	for _, s := range c.scrubber.secrets {
		if s == fileSecret {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected file secret to be loaded into scrubber")
	}

	// Verify it actually scrubs: send a message containing the file secret.
	c.CaptureMessage("error with " + fileSecret)
	_ = c.Flush(2 * time.Second)

	events := transport.Events()
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}
	for _, e := range events {
		if strings.Contains(e.Message, fileSecret) {
			t.Errorf("file secret leaked in message: %q", e.Message)
		}
	}
}

func TestInit_FileSecretsFileNotFound_WarnsAndContinues(t *testing.T) {
	transport := &mockTransport{}
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	cfg.DLP.SecretsFile = "/nonexistent/secrets.txt"
	c, err := initClient(cfg, "test", transport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.enabled {
		t.Error("expected client to still be enabled despite missing secrets file")
	}
}

func TestBeforeSend_ScrubEventCalled(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	c, transport := initTestClient(t, testDLPPatterns())
	defer c.Close()

	c.CaptureMessage("key=" + awsKey + " leaked")
	_ = c.Flush(2 * time.Second)

	events := transport.Events()
	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}
	// Verify BeforeSend (ScrubEvent) ran: message should be scrubbed,
	// ServerName should be empty, Request should be nil.
	e := events[0]
	if strings.Contains(e.Message, awsKey) {
		t.Errorf("BeforeSend did not scrub message: %q", e.Message)
	}
	if e.ServerName != "" {
		t.Errorf("BeforeSend did not wipe ServerName: %q", e.ServerName)
	}
	if e.Request != nil {
		t.Error("BeforeSend did not wipe Request")
	}
}

func TestInit_DefaultOmittedDisabledEvenWithDSN(t *testing.T) {
	cfg := config.Defaults()
	cfg.Sentry.DSN = testDSN

	c, err := Init(cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.enabled {
		t.Error("expected disabled client when sentry.enabled is omitted")
	}
}

func TestInit_ExplicitTrueWithDSNEnabled(t *testing.T) {
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN

	transport := &mockTransport{}
	c, err := initClient(cfg, "test", transport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.enabled {
		t.Fatal("expected enabled client")
	}
}

func TestInit_SampleRateZeroRejectedWhenEnabled(t *testing.T) {
	enabled := true
	zero := 0.0
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	cfg.Sentry.SampleRate = &zero

	_, err := initClient(cfg, "test", &mockTransport{})
	if err == nil || !strings.Contains(err.Error(), "sample_rate 0.0") {
		t.Fatalf("expected sample_rate 0.0 rejection, got %v", err)
	}
}

func TestInit_SampleRateZeroClearsStaleGlobalClient(t *testing.T) {
	t.Cleanup(func() {
		sentry.CurrentHub().BindClient(nil)
	})

	staleTransport := &mockTransport{}
	enabled := true
	cfg := config.Defaults()
	cfg.Sentry.Enabled = &enabled
	cfg.Sentry.DSN = testDSN
	if _, err := initClient(cfg, "test", staleTransport); err != nil {
		t.Fatalf("enable stale client: %v", err)
	}

	zero := 0.0
	cfg.Sentry.SampleRate = &zero
	if _, err := initClient(cfg, "test", &mockTransport{}); err == nil || !strings.Contains(err.Error(), "sample_rate 0.0") {
		t.Fatalf("expected sample_rate 0.0 rejection, got %v", err)
	}

	if id := sentry.CaptureMessage("must not reach stale transport"); id != nil {
		t.Fatalf("package-level capture returned event id after rejected init: %s", *id)
	}
	if events := staleTransport.Events(); len(events) != 0 {
		t.Fatalf("stale global client captured %d event(s) after rejected init", len(events))
	}
}

func TestEventTypes_DroppedBeforeTransport(t *testing.T) {
	c, transport := initTestClient(t, nil)
	defer c.Close()

	sentry.CaptureEvent(&sentry.Event{
		Type:        "transaction",
		Transaction: "GET /private",
		Spans:       []*sentry.Span{{Description: "https://api.vendor.example/private"}},
	})
	sentry.CaptureEvent(&sentry.Event{
		Type: "log",
		Logs: []sentry.Log{{Body: "log body that must not ship"}},
	})
	sentry.CaptureCheckIn(&sentry.CheckIn{
		MonitorSlug: "private-monitor",
		Status:      sentry.CheckInStatusOK,
	}, nil)
	_ = c.Flush(2 * time.Second)

	if events := transport.Events(); len(events) != 0 {
		t.Fatalf("expected transaction/log/check-in events to be dropped, got %d", len(events))
	}
}

func TestTransportGuard_SanitizesNormalEvents(t *testing.T) {
	transport := &mockTransport{}
	guard := dropUnsafeEventTransport{
		delegate: transport,
		scrubber: NewScrubber(testDLPPatterns(), []string{
			testEnvSecret,
		}),
	}

	guard.SendEvent(&sentry.Event{
		Message:    "failed for " + fakeURLWithUserinfo("user", testEnvSecret, "internal-host.example", "/private"),
		ServerName: "agent-prod-01.internal",
		User:       sentry.User{ID: "agent-user"},
		Request:    &sentry.Request{URL: "https://internal-host.example/private"},
		Breadcrumbs: []*sentry.Breadcrumb{
			{Message: "visited /private"},
		},
		Exception: []sentry.Exception{{
			Type:  "PathError",
			Value: "open /home/agent/private.yaml: " + testAWSKeyID,
		}},
	})

	events := transport.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1 sanitized event", len(events))
	}
	event := events[0]
	if event.ServerName != "" || event.User.ID != "" || event.Request != nil || len(event.Breadcrumbs) != 0 {
		t.Fatalf("unsafe fields survived transport guard: %+v", event)
	}
	raw := fmt.Sprintf("%+v", event)
	for _, forbidden := range []string{"user", testEnvSecret, "internal-host.example", "/private", "/home/agent", testAWSKeyID} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("transport guard leaked %q in %+v", forbidden, event)
		}
	}
}

func TestTransportGuard_FlushWithContextDelegates(t *testing.T) {
	if !(dropUnsafeEventTransport{}).FlushWithContext(context.Background()) {
		t.Fatal("nil delegate FlushWithContext should be a successful no-op")
	}

	transport := &mockTransport{}
	guard := dropUnsafeEventTransport{delegate: transport}
	if !guard.FlushWithContext(context.Background()) {
		t.Fatal("expected delegated FlushWithContext to succeed")
	}

	flushCalls, flushWithContextCalls := transport.FlushCalls()
	if flushCalls != 0 || flushWithContextCalls != 1 {
		t.Fatalf("flush calls = %d, flush-with-context calls = %d; want 0 and 1", flushCalls, flushWithContextCalls)
	}
}

func TestTransportGuard_DropsSanitizerPanic(t *testing.T) {
	transport := &mockTransport{}
	guard := dropUnsafeEventTransport{
		delegate: transport,
		scrubber: &Scrubber{patterns: []*regexp.Regexp{nil}},
	}

	guard.SendEvent(&sentry.Event{Message: "panic path"})
	if events := transport.Events(); len(events) != 0 {
		t.Fatalf("expected sanitizer panic to drop event, got %d", len(events))
	}
}
