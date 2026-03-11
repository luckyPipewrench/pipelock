package plsentry

import (
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

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
