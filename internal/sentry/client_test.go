package plsentry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
	mu     sync.Mutex
	events []*sentry.Event
}

func (t *mockTransport) Configure(_ sentry.ClientOptions) {}
func (t *mockTransport) Close()                           {}

func (t *mockTransport) Flush(_ time.Duration) bool {
	return true
}

func (t *mockTransport) FlushWithContext(_ context.Context) bool {
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

// initTestClient creates an enabled client with a mock transport.
func initTestClient(t *testing.T, dlpPatterns []config.DLPPattern) (*Client, *mockTransport) {
	t.Helper()
	transport := &mockTransport{}
	cfg := config.Defaults()
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

func TestInit_EmptyDSNReturnsNoOp(t *testing.T) {
	cfg := config.Defaults()
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
	cfg := config.Defaults()
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

func TestNilClient_NoPanic(t *testing.T) {
	var c *Client
	// All methods should be safe no-ops on nil receiver.
	c.CaptureError(errors.New("test"))
	c.CaptureMessage("test")
	c.Close()
	if !c.Flush(0) {
		t.Error("expected Flush to return true on nil client")
	}
}

func TestDisabledClient_NoPanic(t *testing.T) {
	c := &Client{enabled: false}
	c.CaptureError(errors.New("test"))
	c.CaptureMessage("test")
	c.Close()
	if !c.Flush(0) {
		t.Error("expected Flush to return true on disabled client")
	}
}

func TestInit_InvalidDSNReturnsError(t *testing.T) {
	cfg := config.Defaults()
	cfg.Sentry.DSN = "not-a-valid-dsn"
	c, err := Init(cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid DSN")
	}
	if c != nil {
		t.Error("expected nil client on error")
	}
}

func TestInit_ScrubberPopulated(t *testing.T) {
	cfg := config.Defaults()
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
	cfg := config.Defaults()
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
	cfg := config.Defaults()
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
	cfg := config.Defaults()
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
	cfg := config.Defaults()
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
