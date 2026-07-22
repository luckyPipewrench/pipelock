//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/siemforward"
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
	if err := activateEmitSinks(sinks); err != nil {
		t.Fatalf("activateEmitSinks: %v", err)
	}
	testwait.For(t, 2*time.Second, func() bool { return delivered.Load() == 1 }, "delivery after activation")
	if err := sinks[0].Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewServerHardFailsLoudlyWhenAuditSinkActivationFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	forwarderCfg := config.ForwarderConfig{
		URL: "http://127.0.0.1/events", DestinationAllowlist: []string{"127.0.0.1"},
		SpoolFile: dir + "/spool", CursorFile: dir + "/cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	holderCfg := config.Defaults()
	holderCfg.Emit.Forwarder = forwarderCfg
	holder, err := BuildEmitSinks(holderCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks holder: %v", err)
	}
	if err := activateEmitSinks(holder); err != nil {
		t.Fatalf("activate holder: %v", err)
	}
	t.Cleanup(func() {
		for _, sink := range holder {
			_ = sink.Close()
		}
	})
	cfgPath := writeServerTestConfig(t, fmt.Sprintf(`
emit:
  forwarder:
    url: %q
    destination_allowlist: ["127.0.0.1"]
    spool_file: %q
    cursor_file: %q
`, forwarderCfg.URL, forwarderCfg.SpoolFile, forwarderCfg.CursorFile))
	buf := &syncBuffer{}
	server, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: buf, Stderr: buf, allowEphemeralListenersForTesting: true})
	if server != nil {
		server.cleanup()
	}
	if !errors.Is(err, siemforward.ErrActivationFailed) {
		t.Fatalf("NewServer error = %v, want ErrActivationFailed", err)
	}
	if output := buf.String(); !strings.Contains(output, "WARNING: audit sink activation failed") || !strings.Contains(output, "startup aborted") {
		t.Fatalf("startup output did not loudly surface activation failure:\n%s", output)
	}
}

func TestServerReloadActivationFailureRetainsOldSinkAndReportsFailure(t *testing.T) {
	t.Parallel()
	s, buf := newTestServer(t, nil)
	oldSink := &runtimeActivationSink{}
	for _, sink := range s.emitter.ReloadSinks([]emit.Sink{oldSink}) {
		_ = sink.Close()
	}
	s.emitSinks = []emit.Sink{oldSink}

	dir := t.TempDir()
	forwarderCfg := config.ForwarderConfig{
		URL: "http://127.0.0.1/events", DestinationAllowlist: []string{"127.0.0.1"},
		SpoolFile: dir + "/spool", CursorFile: dir + "/cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	holderCfg := config.Defaults()
	holderCfg.Emit.Forwarder = forwarderCfg
	holder, err := BuildEmitSinks(holderCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks holder: %v", err)
	}
	if err := activateEmitSinks(holder); err != nil {
		t.Fatalf("activate holder: %v", err)
	}
	t.Cleanup(func() {
		for _, sink := range holder {
			_ = sink.Close()
		}
	})

	reloaded := s.proxy.CurrentConfig().Clone()
	reloaded.Emit.Forwarder = forwarderCfg
	buf.reset()
	err = s.Reload(reloaded)
	if !errors.Is(err, siemforward.ErrActivationFailed) {
		t.Fatalf("Reload error = %v, want ErrActivationFailed", err)
	}
	if !strings.Contains(buf.String(), "WARNING: config reload degraded") || !strings.Contains(buf.String(), "previous sink set not swapped") {
		t.Fatalf("reload output did not report degraded activation:\n%s", buf.String())
	}
	before := oldSink.emitted.Load()
	s.emitter.EmitWithSeverity(t.Context(), emit.SeverityWarn, "post-reload", nil)
	if got := oldSink.emitted.Load(); got != before+1 {
		t.Fatalf("old sink emitted = %d after baseline %d, want retained sink to serve once", got, before)
	}
}

func TestActivateReplacementEmitSinksSequencesSameSpoolLock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Emit.Forwarder = config.ForwarderConfig{
		URL: "http://127.0.0.1/events", DestinationAllowlist: []string{"127.0.0.1"},
		SpoolFile: dir + "/spool", CursorFile: dir + "/cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	oldSinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks old: %v", err)
	}
	if err := activateEmitSinks(oldSinks); err != nil {
		t.Fatalf("activate old: %v", err)
	}
	newSinks, err := BuildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks replacement: %v", err)
	}
	t.Cleanup(func() {
		for _, sink := range oldSinks {
			_ = sink.Close()
		}
		for _, sink := range newSinks {
			_ = sink.Close()
		}
	})
	preclosed, err := activateReplacementEmitSinks(oldSinks, newSinks)
	if err != nil {
		t.Fatalf("activateReplacementEmitSinks: %v", err)
	}
	if !preclosed[0] {
		t.Fatal("same-spool old sink was not closed before replacement activation")
	}
	event := emit.Event{Severity: emit.SeverityWarn, Type: "blocked", Timestamp: time.Now()}
	if err := oldSinks[0].Emit(t.Context(), event); err == nil {
		t.Fatal("old same-spool sink still accepted events after lock handoff")
	}
	if err := newSinks[0].Emit(t.Context(), event); err != nil {
		t.Fatalf("replacement Emit after lock handoff: %v", err)
	}
}

func TestActivateReplacementEmitSinksSequencesSharedCursor(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	oldCfg := config.Defaults()
	oldCfg.Emit.Forwarder = config.ForwarderConfig{
		URL: "http://127.0.0.1/events", DestinationAllowlist: []string{"127.0.0.1"},
		SpoolFile: dir + "/old.spool", CursorFile: dir + "/shared.cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	oldCfg.Emit.Filter.Actions = []string{"block"}
	oldSinks, err := BuildEmitSinks(oldCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks old: %v", err)
	}
	if err := activateEmitSinks(oldSinks); err != nil {
		t.Fatalf("activate old: %v", err)
	}

	newCfg := oldCfg.Clone()
	newCfg.Emit.Forwarder.SpoolFile = dir + "/new.spool"
	newSinks, err := BuildEmitSinks(newCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks replacement: %v", err)
	}
	t.Cleanup(func() {
		for _, sink := range oldSinks {
			_ = sink.Close()
		}
		for _, sink := range newSinks {
			_ = sink.Close()
		}
	})

	preclosed, err := activateReplacementEmitSinks(oldSinks, newSinks)
	if err != nil {
		t.Fatalf("activateReplacementEmitSinks: %v", err)
	}
	if !preclosed[0] {
		t.Fatal("shared-cursor old sink was not closed before replacement activation")
	}
	event := emit.Event{Severity: emit.SeverityWarn, Type: "blocked", Timestamp: time.Now()}
	if err := oldSinks[0].Emit(t.Context(), event); err == nil {
		t.Fatal("old shared-cursor sink still accepted events after state handoff")
	}
	if err := newSinks[0].Emit(t.Context(), event); err != nil {
		t.Fatalf("replacement Emit after state handoff: %v", err)
	}
}

func TestActivateReplacementEmitSinksSequencesCrossRoleStateReuse(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sharedPath := dir + "/shared.state"
	oldCfg := config.Defaults()
	oldCfg.Emit.Forwarder = config.ForwarderConfig{
		URL: "http://127.0.0.1/events", DestinationAllowlist: []string{"127.0.0.1"},
		SpoolFile: dir + "/old.spool", CursorFile: sharedPath, MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	oldSinks, err := BuildEmitSinks(oldCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks old: %v", err)
	}
	if err := activateEmitSinks(oldSinks); err != nil {
		t.Fatalf("activate old: %v", err)
	}

	newCfg := oldCfg.Clone()
	newCfg.Emit.Forwarder.SpoolFile = sharedPath
	newCfg.Emit.Forwarder.CursorFile = dir + "/new.cursor"
	newSinks, err := BuildEmitSinks(newCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks replacement: %v", err)
	}
	t.Cleanup(func() {
		for _, sink := range oldSinks {
			_ = sink.Close()
		}
		for _, sink := range newSinks {
			_ = sink.Close()
		}
	})

	preclosed, err := activateReplacementEmitSinks(oldSinks, newSinks)
	if err != nil {
		t.Fatalf("activateReplacementEmitSinks: %v", err)
	}
	if !preclosed[0] {
		t.Fatal("cross-role shared state path did not close the old sink before replacement activation")
	}
}

func TestActivateReplacementEmitSinksSequencesLockFileCrossRoleReuse(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	oldCfg := config.Defaults()
	oldCfg.Emit.Forwarder = config.ForwarderConfig{
		URL: "http://127.0.0.1/events", DestinationAllowlist: []string{"127.0.0.1"},
		SpoolFile: dir + "/old.spool", CursorFile: dir + "/old.cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	oldSinks, err := BuildEmitSinks(oldCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks old: %v", err)
	}
	if err := activateEmitSinks(oldSinks); err != nil {
		t.Fatalf("activate old: %v", err)
	}

	newCfg := oldCfg.Clone()
	newCfg.Emit.Forwarder.SpoolFile = oldCfg.Emit.Forwarder.SpoolFile + ".lock"
	newCfg.Emit.Forwarder.CursorFile = dir + "/new.cursor"
	newSinks, err := BuildEmitSinks(newCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks replacement: %v", err)
	}
	t.Cleanup(func() {
		for _, sink := range oldSinks {
			_ = sink.Close()
		}
		for _, sink := range newSinks {
			_ = sink.Close()
		}
	})

	preclosed, err := activateReplacementEmitSinks(oldSinks, newSinks)
	if err != nil {
		t.Fatalf("activateReplacementEmitSinks: %v", err)
	}
	if !preclosed[0] {
		t.Fatal("lock-file cross-role reuse did not close the old sink before replacement activation")
	}
}

func TestActivateReplacementEmitSinksSequencesHardLinkedSpool(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	oldCfg := config.Defaults()
	oldCfg.Emit.Forwarder = config.ForwarderConfig{
		URL: "http://127.0.0.1/events", DestinationAllowlist: []string{"127.0.0.1"},
		SpoolFile: dir + "/old.spool", CursorFile: dir + "/old.cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	oldSinks, err := BuildEmitSinks(oldCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks old: %v", err)
	}
	if err := activateEmitSinks(oldSinks); err != nil {
		t.Fatalf("activate old: %v", err)
	}

	aliasSpool := dir + "/alias.spool"
	if err := os.Link(oldCfg.Emit.Forwarder.SpoolFile, aliasSpool); err != nil {
		t.Fatalf("hard-link spool alias: %v", err)
	}
	newCfg := oldCfg.Clone()
	newCfg.Emit.Forwarder.SpoolFile = aliasSpool
	newCfg.Emit.Forwarder.CursorFile = dir + "/new.cursor"
	newSinks, err := BuildEmitSinks(newCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks replacement: %v", err)
	}
	t.Cleanup(func() {
		for _, sink := range oldSinks {
			_ = sink.Close()
		}
		for _, sink := range newSinks {
			_ = sink.Close()
		}
	})

	preclosed, err := activateReplacementEmitSinks(oldSinks, newSinks)
	if err != nil {
		t.Fatalf("activateReplacementEmitSinks: %v", err)
	}
	if !preclosed[0] {
		t.Fatal("hard-linked spool did not close the old sink before replacement activation")
	}
}

func TestActivateReplacementEmitSinksSequencesMissingCursorThroughSymlinkedParent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	realDir := dir + "/real"
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatalf("create real state directory: %v", err)
	}
	aliasDir := dir + "/alias"
	if err := os.Symlink(realDir, aliasDir); err != nil {
		t.Skipf("symlink state directory unsupported: %v", err)
	}

	oldCfg := config.Defaults()
	oldCfg.Emit.Forwarder = config.ForwarderConfig{
		URL: "http://127.0.0.1/events", DestinationAllowlist: []string{"127.0.0.1"},
		SpoolFile: realDir + "/old.spool", CursorFile: realDir + "/shared.cursor", MinSeverity: config.SeverityWarn,
		TimeoutSeconds: 1, QueueSize: 4,
	}
	oldSinks, err := BuildEmitSinks(oldCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks old: %v", err)
	}
	if err := activateEmitSinks(oldSinks); err != nil {
		t.Fatalf("activate old: %v", err)
	}

	newCfg := oldCfg.Clone()
	newCfg.Emit.Forwarder.SpoolFile = realDir + "/new.spool"
	newCfg.Emit.Forwarder.CursorFile = aliasDir + "/shared.cursor"
	newSinks, err := BuildEmitSinks(newCfg)
	if err != nil {
		t.Fatalf("BuildEmitSinks replacement: %v", err)
	}
	t.Cleanup(func() {
		for _, sink := range oldSinks {
			_ = sink.Close()
		}
		for _, sink := range newSinks {
			_ = sink.Close()
		}
	})

	preclosed, err := activateReplacementEmitSinks(oldSinks, newSinks)
	if err != nil {
		t.Fatalf("activateReplacementEmitSinks: %v", err)
	}
	if !preclosed[0] {
		t.Fatal("symlink-aliased missing cursor did not close the old sink before replacement activation")
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
