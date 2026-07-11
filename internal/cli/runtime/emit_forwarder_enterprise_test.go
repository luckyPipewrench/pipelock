//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestBuildEmitSinksCreatesDormantEnterpriseForwarder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var delivered atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cfg := config.Defaults()
	cfg.Emit.Forwarder = config.ForwarderConfig{
		URL: srv.URL + "/events", DestinationAllowlist: []string{"127.0.0.1"},
		SpoolFile: dir + "/spool", CursorFile: dir + "/cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	sinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks: %v", err)
	}
	if len(sinks) != 1 {
		t.Fatalf("len(sinks) = %d, want 1", len(sinks))
	}
	if err := sinks[0].Emit(context.Background(), emit.Event{Severity: emit.SeverityWarn, Type: "blocked", Timestamp: time.Now()}); err != nil {
		t.Fatalf("Emit before activation: %v", err)
	}
	if delivered.Load() != 0 {
		t.Fatal("dormant forwarder delivered before activation")
	}
	info, err := os.Stat(cfg.Emit.Forwarder.SpoolFile)
	if err != nil {
		t.Fatalf("stat spool: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("dormant spool size = %d, want 0", info.Size())
	}
	activateEmitSinks(sinks)
	testwait.For(t, 2*time.Second, func() bool { return delivered.Load() == 1 }, "delivery after activation")
	if err := sinks[0].Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

type closeTrackingSink struct {
	inner  emit.Sink
	closed atomic.Bool
}

func (s *closeTrackingSink) Emit(ctx context.Context, event emit.Event) error {
	return s.inner.Emit(ctx, event)
}

func (s *closeTrackingSink) Close() error {
	s.closed.Store(true)
	return s.inner.Close()
}

func TestBuildEmitSinksClosesExistingSinkWhenForwarderConstructionFails(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cfg := config.Defaults()
	cfg.Emit.Webhook.URL = srv.URL
	cfg.Emit.Webhook.MinSeverity = config.SeverityInfo
	var existing *closeTrackingSink
	wantErr := errors.New("forwarder construction failed")
	appendFailure := func(_ *config.Config, sinks []emit.Sink, _ emitDeliveryObserver) ([]emit.Sink, error) {
		if len(sinks) != 1 {
			t.Fatalf("existing sinks = %d, want webhook sink", len(sinks))
		}
		existing = &closeTrackingSink{inner: sinks[0]}
		return []emit.Sink{existing}, wantErr
	}

	sinks, err := buildEmitSinks(cfg, nil, appendFailure)
	if !errors.Is(err, wantErr) {
		t.Fatalf("BuildEmitSinks error = %v, want %v", err, wantErr)
	}
	if sinks != nil {
		t.Fatalf("sinks = %v, want nil", sinks)
	}
	if existing == nil || !existing.closed.Load() {
		t.Fatal("existing sink was not closed after forwarder construction failure")
	}
}

func TestBuildEmitSinksForwarderKeepsSSRFFloorWhenMainScannerDisablesIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"127.0.0.1"}}
	cfg.Emit.Forwarder = config.ForwarderConfig{
		URL: "https://api.vendor.example/events", DestinationAllowlist: []string{"api.vendor.example"},
		SpoolFile: dir + "/spool", CursorFile: dir + "/cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	_, err := BuildEmitSinks(cfg)
	if err == nil || !strings.Contains(err.Error(), "internal IP") {
		t.Fatalf("BuildEmitSinks error = %v, want internal-IP denial", err)
	}
}
