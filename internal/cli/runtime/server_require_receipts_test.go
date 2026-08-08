// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestNewServer_RequireReceiptsWithoutEmitterFailsClosed pins the startup
// guard: require_receipts escalates a missing receipt to a block, so an
// inert recorder (no dir / no signing key) would fail-close every request
// with receipt_emission_failed. NewServer must refuse to start instead of
// bringing up a silently all-blocking proxy.
func TestNewServer_RequireReceiptsWithoutEmitterFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		section []string
	}{
		{
			name: "no_dir",
			section: []string{
				"flight_recorder:",
				"  enabled: true",
				"  require_receipts: true",
			},
		},
		{
			name: "dir_without_signing_key",
			section: []string{
				"flight_recorder:",
				"  enabled: true",
				"  require_receipts: true",
				// sign_checkpoints: false isolates this case to the
				// require_receipts guard: without it, the recorder's own
				// sign-without-a-key fail-closed fires first (its own test).
				// require_receipts still fails here because no signing key means
				// no live signed receipt emitter.
				"  sign_checkpoints: false",
				"  dir: " + strconv.Quote(t.TempDir()),
			},
		},
		{
			name: "recorder_disabled",
			section: []string{
				"flight_recorder:",
				"  enabled: false",
				"  require_receipts: true",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := writeServerTestConfig(t, strings.Join(append([]string{"mode: balanced"}, tc.section...), "\n")+"\n")
			s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
			if err == nil {
				s.cleanup()
				t.Fatal("expected NewServer to fail when require_receipts is set without a live signed emitter")
			}
			if !strings.Contains(err.Error(), "require_receipts") {
				t.Fatalf("error = %q, want it to mention require_receipts", err)
			}
		})
	}
}

// TestNewServer_RequireReceiptsWithLiveEmitterStarts proves the guard is not
// over-broad: with a real recorder dir + signing key the emitter is live, so
// require_receipts is a valid configuration and NewServer succeeds.
func TestNewServer_RequireReceiptsWithLiveEmitterStarts(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))

	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatalf("NewServer with live signed emitter and require_receipts: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })
	if s.receiptEmitter == nil {
		t.Fatal("receiptEmitter nil despite configured recorder + signing key")
	}
}

func TestNewServer_RequireReceiptsWithBrickedEmitterFails(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	seedTamperedReceiptTail(t, recorderDir, priv)

	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))

	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err == nil {
		s.cleanup()
		t.Fatal("expected NewServer to fail when require_receipts has a bricked emitter")
	}
	if !strings.Contains(err.Error(), "require_receipts") || !strings.Contains(err.Error(), "resume") {
		t.Fatalf("error = %q, want require_receipts and resume context", err)
	}
}

func TestNewServer_RequireReceiptsSessionOpenEmitFailureFailsClosed(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))

	forcedErr := errors.New("forced session_open emit failure")
	beforeStartupSessionOpenForTest = func(*receipt.Emitter) error {
		return forcedErr
	}
	t.Cleanup(func() {
		beforeStartupSessionOpenForTest = nil
	})

	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err == nil {
		s.cleanup()
		t.Fatal("expected NewServer to fail when required session_open emission fails")
	}
	if !strings.Contains(err.Error(), "require_receipts") ||
		!strings.Contains(err.Error(), "session_open") ||
		!errors.Is(err, forcedErr) {
		t.Fatalf("error = %q, want require_receipts session_open context wrapping forced error", err)
	}
}

func TestServer_StartReturnsRequiredReceiptHeartbeatFailure(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"  completeness:",
		"    heartbeat_interval: 1ms",
		"",
	}, "\n"))

	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.ConfigFile = cfgPath
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})
	if err := s.recorder.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Start returned nil, want required heartbeat failure")
		}
		if !strings.Contains(err.Error(), "require_receipts") ||
			!strings.Contains(err.Error(), "receipt heartbeat emission failed") ||
			!strings.Contains(err.Error(), "recorder is closed") {
			t.Fatalf("Start error = %q, want required heartbeat recorder-closed failure", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for Start to return required heartbeat failure")
	}
}

func seedTamperedReceiptTail(t *testing.T, dir string, priv ed25519.PrivateKey) {
	t.Helper()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "test",
		Principal:  "test",
		Actor:      "test",
	})
	if err := emitter.Emit(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   "allow",
		Transport: "fetch",
		Method:    http.MethodGet,
		Target:    "https://example.com",
	}); err != nil {
		t.Fatalf("seed Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	tamperLastActionReceipt(t, dir)
}

func tamperLastActionReceipt(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var target string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".jsonl") {
			target = filepath.Join(dir, entry.Name())
		}
	}
	if target == "" {
		t.Fatal("no evidence file found")
	}
	raw, err := os.ReadFile(filepath.Clean(target))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
			continue
		}
		var entryType string
		if err := json.Unmarshal(entry["type"], &entryType); err != nil || entryType != "action_receipt" {
			continue
		}
		rcpt, err := receipt.Unmarshal(entry["detail"])
		if err != nil {
			t.Fatalf("receipt.Unmarshal: %v", err)
		}
		rcpt.ActionRecord.Verdict = "block"
		detail, err := receipt.Marshal(rcpt)
		if err != nil {
			t.Fatalf("receipt.Marshal: %v", err)
		}
		entry["detail"] = detail
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		lines[i] = string(line)
		if err := os.WriteFile(filepath.Clean(target), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return
	}
	t.Fatal("no action_receipt entry found")
}

// newRequireReceiptsReloadServer builds a server whose recorder state matches
// withEmitter, so a reload can be exercised against both the live-emitter and
// no-emitter cases. The no-emitter server is the realistic operator shape: the
// process started without a configured recorder, and the edited config that
// arrives at reload names a dir and key (which config validation requires
// before require_receipts is accepted at all) while the restart-only recorder
// itself is still absent.
// newRequireReceiptsReloadServer builds a recorder-backed server for the cases
// that do not inspect the audit channel. The no-recorder shape is only needed by
// the ignored-enable test, which reads the audit log and uses the WithAudit form.
func newRequireReceiptsReloadServer(t *testing.T) (*Server, *syncBuffer) {
	t.Helper()
	s, stderr, _ := newRequireReceiptsReloadServerWithAudit(t, true)
	return s, stderr
}

// newRequireReceiptsReloadServerWithAudit also returns the path the audit
// channel writes to, so a test can assert the event an operator's monitoring
// tool would see rather than only the process stderr.
func newRequireReceiptsReloadServerWithAudit(t *testing.T, withEmitter bool) (*Server, *syncBuffer, string) {
	t.Helper()
	auditLog := filepath.Join(t.TempDir(), "audit.jsonl")
	lines := []string{
		"mode: balanced",
		"logging:",
		"  format: json",
		"  output: file",
		"  file: " + strconv.Quote(auditLog),
		"flight_recorder:",
	}
	if withEmitter {
		recorderDir := t.TempDir()
		keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
		_, priv, err := signing.GenerateKeyPair()
		if err != nil {
			t.Fatalf("generate signing key: %v", err)
		}
		if err := signing.SavePrivateKey(priv, keyPath); err != nil {
			t.Fatalf("save signing key: %v", err)
		}
		lines = append(lines,
			"  enabled: true",
			"  dir: "+strconv.Quote(recorderDir),
			"  signing_key_path: "+strconv.Quote(keyPath),
		)
	} else {
		lines = append(lines, "  enabled: false")
	}
	cfgPath := writeServerTestConfig(t, strings.Join(append(lines, ""), "\n"))
	stderr := &syncBuffer{}
	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: stderr})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })
	if ready := s.liveReceiptEmitterReady(); ready != withEmitter {
		t.Fatalf("liveReceiptEmitterReady() = %v, want %v", ready, withEmitter)
	}
	return s, stderr, auditLog
}

// TestServer_Reload_RequireReceiptsEnableWithoutEmitterIsIgnored pins the
// reload half of the startup guard. NewServer REFUSES to boot when
// require_receipts is set with no live signed emitter, precisely so the
// misconfiguration does not surface as an all-403 outage at runtime. Honouring
// the same change on reload produced that outage from a config edit, because
// the recorder is restart-only and cannot be built mid-flight. The enable is
// ignored, warned, and recorded on the audit channel instead.
func TestServer_Reload_RequireReceiptsEnableWithoutEmitterIsIgnored(t *testing.T) {
	s, stderr, auditLog := newRequireReceiptsReloadServerWithAudit(t, false)

	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.FlightRecorder.RequireReceipts = true
	newCfg.FetchProxy.Monitoring.MaxURLLength = 4321
	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("require_receipts was enabled by reload with no live emitter: every request would fail closed with receipt_emission_failed")
	}
	if !stderr.contains("require_receipts cannot be enabled at runtime") {
		t.Fatal("no stderr warning explaining the ignored require_receipts enable")
	}
	if !stderr.contains("restart required") {
		t.Fatal("warning does not tell the operator that a restart is the fix")
	}
	if got := s.proxy.CurrentConfig().FetchProxy.Monitoring.MaxURLLength; got != 4321 {
		t.Fatalf("ignored require_receipts enable blocked an unrelated hot-reloadable change: max_url_length = %d, want 4321", got)
	}
	// stderr alone is not the contract. An operator who asked for receipt
	// enforcement and did not get it has to be able to see that from a
	// monitoring tool, so the audit event is the load-bearing signal and a
	// regression that drops the LogConfigReload call must fail here.
	audit, readErr := os.ReadFile(filepath.Clean(auditLog))
	if readErr != nil {
		t.Fatalf("read audit log: %v", readErr)
	}
	if !strings.Contains(string(audit), `"event":"config_reload"`) ||
		!strings.Contains(string(audit), `"status":"ignored"`) ||
		!strings.Contains(string(audit), "require_receipts enable without live receipt emitter") {
		t.Fatalf("audit log did not record the ignored require_receipts enable:\n%s", audit)
	}
}

// TestServer_Reload_RequireReceiptsEnableWithLiveEmitterApplies keeps the
// carve-out honest. require_receipts is deliberately reloadable among the
// restart-only recorder fields, and the guard above must not regress that
// normal case: with a live emitter the enable still takes effect.
func TestServer_Reload_RequireReceiptsEnableWithLiveEmitterApplies(t *testing.T) {
	s, stderr := newRequireReceiptsReloadServer(t)

	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.FlightRecorder.RequireReceipts = true
	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("require_receipts enable was ignored despite a live signed emitter")
	}
	if stderr.contains("require_receipts cannot be enabled at runtime") {
		t.Fatal("emitted the no-emitter warning while an emitter was live")
	}
}

// TestServer_Reload_RequireReceiptsEnableWithUnhealthyEmitterRecovers covers
// the ordering boundary between Server.Reload and proxy.Reload. The guard runs
// before proxy.Reload stages its receipt-emitter replacement, so a currently
// unhealthy emitter must not make a legitimate enable look structurally
// impossible when the already-bound recorder and signing key can rebuild it.
func TestServer_Reload_RequireReceiptsEnableWithUnhealthyEmitterRecovers(t *testing.T) {
	s, stderr := newRequireReceiptsReloadServer(t)
	oldEmitter := s.liveReceiptEmitter()
	oldEmitter.MarkUnhealthy(errors.New("forced runtime receipt failure"))
	if s.liveReceiptEmitterReady() {
		t.Fatal("runtime-unhealthy emitter reported ready")
	}

	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.FlightRecorder.RequireReceipts = true
	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("require_receipts enable was ignored even though reload could rebuild the emitter")
	}
	if !s.liveReceiptEmitterReady() {
		t.Fatal("reload applied require_receipts without a healthy rebuilt emitter")
	}
	if s.liveReceiptEmitter() == oldEmitter {
		t.Fatal("reload reused the runtime-unhealthy receipt emitter")
	}
	if stderr.contains("cannot be enabled at runtime") {
		t.Fatal("treated a recoverable emitter failure as a restart-only enable")
	}
}

func TestServer_Reload_RequireReceiptsRecoveryFailureKeepsOldPosture(t *testing.T) {
	// The old posture has to be the SECURITY-SENSITIVE one, which means
	// receipts already required. Starting from the default (not required) only
	// proves a failed recovery does not ENABLE receipts, and would still pass if
	// a failed rebuild cleared an active fail-closed requirement or published
	// the rest of the candidate config.
	s, _ := newRequireReceiptsReloadServer(t)

	enable := s.proxy.CurrentConfig().Clone()
	enable.FlightRecorder.RequireReceipts = true
	if err := s.Reload(enable); err != nil {
		t.Fatalf("Reload enabling require_receipts: %v", err)
	}
	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("setup failed: require_receipts not in force before recovery was broken")
	}
	liveAnchor := s.proxy.CurrentConfig().FlightRecorder.Anchor.Interval

	oldEmitter := s.liveReceiptEmitter()
	oldEmitter.MarkUnhealthy(errors.New("forced runtime receipt failure"))
	if err := os.Remove(s.proxy.CurrentConfig().FlightRecorder.SigningKeyPath); err != nil {
		t.Fatalf("remove signing key: %v", err)
	}

	// Receipts stay required across this reload; only an unrelated field moves.
	// Anchor.Interval is the field that also sets the dedupe bypass, without
	// which a Clone shares its Hash() with the live config and the reload is
	// skipped outright.
	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.FlightRecorder.Anchor.Interval = "2h"
	if err := s.Reload(newCfg); err == nil {
		t.Fatal("Reload recovered an unhealthy emitter after its signing key was removed")
	}

	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("failed emitter recovery cleared an active fail-closed requirement")
	}
	if s.liveReceiptEmitter() != oldEmitter {
		t.Fatal("failed emitter recovery replaced the old runtime emitter")
	}
	if got := s.proxy.CurrentConfig().FlightRecorder.Anchor.Interval; got != liveAnchor {
		t.Fatalf("rejected reload published its unrelated changes: anchor interval = %q, want %q", got, liveAnchor)
	}
}

// TestServer_Reload_RequireReceiptsStaysOnWhenEmitterUnhealthy covers the
// direction the guard must NOT take. An already-required posture whose emitter
// is not live stays required: preserving fail-closed is correct there, and
// clearing it would be a silent downgrade of a control the operator already
// had in force. Only the enable transition is ignored.
func TestServer_Reload_RequireReceiptsStaysOnWhenEmitterUnhealthy(t *testing.T) {
	// Reach the state the way production does. The startup guard means an
	// already-required posture always began with a healthy emitter, so start
	// with one, enable require_receipts, then mark the emitter unhealthy the
	// same way a required heartbeat failure does in production.
	s, stderr := newRequireReceiptsReloadServer(t)

	enable := s.proxy.CurrentConfig().Clone()
	enable.FlightRecorder.RequireReceipts = true
	if err := s.Reload(enable); err != nil {
		t.Fatalf("Reload enabling require_receipts: %v", err)
	}
	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("setup failed: require_receipts not in force before the emitter was dropped")
	}
	oldEmitter := s.liveReceiptEmitter()
	oldEmitter.MarkUnhealthy(errors.New("forced required heartbeat failure"))
	if s.liveReceiptEmitterReady() {
		t.Fatal("runtime-unhealthy emitter reported ready")
	}

	// Clone copies rawBytes, so this candidate shares its Hash() with the live
	// config and the 2s dedupe would skip it outright. It survives only because
	// changing Anchor.Interval sets the flightRecorderAnchorChanged bypass. That
	// dependency is load-bearing and invisible: if the bypass ever stops
	// covering anchor changes, Reload returns nil early, every assertion below
	// runs against an unchanged live config, and this test keeps passing while
	// testing nothing.
	newCfg := s.proxy.CurrentConfig().Clone()
	newCfg.FlightRecorder.Anchor.Interval = "2h"
	if err := s.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("an already-required receipt posture was cleared by reload: silent downgrade of a live control")
	}
	if !s.liveReceiptEmitterReady() {
		t.Fatal("reload preserved require_receipts without recovering the unhealthy emitter")
	}
	if s.liveReceiptEmitter() == oldEmitter {
		t.Fatal("reload reused the runtime-unhealthy receipt emitter")
	}
	if stderr.contains("cannot be enabled at runtime") {
		t.Fatal("treated an unchanged require_receipts as an enable transition")
	}
	if !stderr.contains("current signed receipt emitter is unhealthy") {
		t.Fatal("no warning that the required posture entered reload unhealthy")
	}
}

// TestServer_Reload_RequireReceiptsDowngradeIsRejected closes the opposite
// direction from the enable guard. reloadDowngradeRejectReason already NAMED
// flight_recorder.require_receipts in its "required security mode" reason, but
// nothing emitted a ReloadWarning for the field, so hasRejectableDowngradeWarning
// never saw one and the rejection could not fire outside strict mode. A plain
// balanced-mode reload therefore cleared an active fail-closed receipt
// requirement silently, with no error and no warning: a guard that read as
// coverage and checked nothing. The whole reload must be rejected and the live
// posture preserved, which is how every sibling security toggle already behaves.
func TestServer_Reload_RequireReceiptsDowngradeIsRejected(t *testing.T) {
	// Start with the requirement already in force from the config file. That is
	// the production shape, and it avoids enabling it via a first reload: two
	// reloads in a row share the synthetic "defaults" config hash here, so the
	// second would be swallowed by the reload dedupe and prove nothing.
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))
	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })
	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("setup failed: require_receipts not in force before the downgrade")
	}

	off := s.proxy.CurrentConfig().Clone()
	off.FlightRecorder.Enabled = false
	off.FlightRecorder.RequireReceipts = false
	// A second, unrelated and genuinely hot-reloadable change proves the whole
	// reload was rejected rather than the one field being quietly preserved.
	off.FetchProxy.Monitoring.MaxURLLength = 4321

	reloadErr := s.Reload(off)
	if reloadErr == nil {
		t.Fatal("reload silently cleared an active fail-closed receipt requirement")
	}
	if !strings.Contains(reloadErr.Error(), "require_receipts") {
		t.Fatalf("rejection = %q, want it to name flight_recorder.require_receipts", reloadErr)
	}
	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("require_receipts was cleared despite the reload being rejected")
	}
	if s.proxy.CurrentConfig().FetchProxy.Monitoring.MaxURLLength == 4321 {
		t.Fatal("rejected reload still published its other changes")
	}
	if !s.proxy.CurrentConfig().FlightRecorder.Enabled {
		t.Fatal("rejected whole-recorder disable changed the live recorder state")
	}

	// Positive control for the unrelated field above: with the required
	// posture preserved, the exact same max_url_length edit must apply. Without
	// this probe, the rejection assertion could pass merely because the field
	// was itself restart-only or otherwise ignored by reload.
	allowed := s.proxy.CurrentConfig().Clone()
	allowed.FetchProxy.Monitoring.MaxURLLength = 4321
	if err := s.Reload(allowed); err != nil {
		t.Fatalf("Reload preserving require_receipts: %v", err)
	}
	if got := s.proxy.CurrentConfig().FetchProxy.Monitoring.MaxURLLength; got != 4321 {
		t.Fatalf("positive-control max_url_length reload = %d, want 4321", got)
	}
}
