// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBuildRedactionRuntime_DisabledReturnsNil(t *testing.T) {
	cfg := config.Defaults()
	p := &Proxy{}

	rt, err := p.buildRedactionRuntimeWithScanner(cfg, nil)
	if err != nil {
		t.Fatalf("buildRedactionRuntime: %v", err)
	}
	if rt != nil {
		t.Fatalf("disabled redaction should return nil runtime, got %+v", rt)
	}
}

func TestRedactionRuntimePtr_ReturnsStoredPointer(t *testing.T) {
	p := &Proxy{}
	rt := &redactionRuntime{}
	p.RedactionRuntimePtr().Store(rt)

	if got := p.RedactionRuntimePtr().Load(); got != rt {
		t.Fatalf("RedactionRuntimePtr().Load() = %p, want %p", got, rt)
	}
}

func TestCurrentRedactionRuntimeForConfig_MatchingRuntime(t *testing.T) {
	cfg := config.Defaults()
	applyRedactionTestProfile(cfg)
	rt := &redactionRuntime{
		matcher:   &redact.Matcher{},
		configKey: redactionConfigKey(cfg),
		required:  true,
	}

	var ptr atomic.Pointer[redactionRuntime]
	ptr.Store(rt)

	if got := currentRedactionRuntimeForConfig(cfg, &ptr); got != rt {
		t.Fatalf("currentRedactionRuntimeForConfig() = %p, want %p", got, rt)
	}
}

func TestCurrentRedactionRuntimeForConfig_MismatchFailsClosed(t *testing.T) {
	// The request-scoped cfg drives receipt policy hashes. If the stored
	// runtime was built from a different config, returning it would mix one
	// policy's matcher with another policy's signed evidence.
	cfg := config.Defaults()
	applyRedactionTestProfile(cfg)

	stored := &redactionRuntime{
		matcher:   &redact.Matcher{},
		configKey: "old-policy",
		required:  true,
	}
	var ptr atomic.Pointer[redactionRuntime]
	ptr.Store(stored)

	got := currentRedactionRuntimeForConfig(cfg, &ptr)
	if got == nil {
		t.Fatal("expected fail-closed sentinel on runtime/config mismatch")
	}
	if got == stored {
		t.Fatal("mismatched runtime must not be returned")
	}
	if got.matcher != nil {
		t.Fatal("sentinel must not expose a matcher")
	}
	if !got.required {
		t.Fatal("sentinel must require redaction")
	}
}

func TestCurrentRedactionConfigFor_MismatchFailsClosed(t *testing.T) {
	cfg := config.Defaults()
	applyRedactionTestProfile(cfg)

	matcherInstance := &redact.Matcher{}
	p := &Proxy{}
	p.redactionRuntimePtr.Store(&redactionRuntime{
		matcher:   matcherInstance,
		configKey: "old-policy",
		required:  true,
	})

	matcher, _, required := p.CurrentRedactionConfigFor(cfg)
	if matcher != nil {
		t.Fatalf("mismatched runtime exposed matcher %p", matcher)
	}
	if !required {
		t.Fatal("mismatched enabled config must fail closed")
	}
}

func TestCurrentRedactionRuntimeForConfig_ScannerSecretMismatchFailsClosed(t *testing.T) {
	cfg := config.Defaults()
	applyRedactionTestProfile(cfg)

	oldScannerCfg := config.Defaults()
	oldScannerCfg.Internal = nil
	oldScannerCfg.DLP.SecretsFile = writeRedactionRuntimeSecretFile(t, "old-secret-value-1234")
	oldScanner := scanner.New(oldScannerCfg)
	t.Cleanup(oldScanner.Close)

	newScannerCfg := config.Defaults()
	newScannerCfg.Internal = nil
	newScannerCfg.DLP.SecretsFile = writeRedactionRuntimeSecretFile(t, "new-secret-value-1234")
	newScanner := scanner.New(newScannerCfg)
	t.Cleanup(newScanner.Close)

	stored := &redactionRuntime{
		matcher:   &redact.Matcher{},
		configKey: redactionConfigKeyForScanner(cfg, oldScanner),
		required:  true,
	}
	var ptr atomic.Pointer[redactionRuntime]
	ptr.Store(stored)

	got := currentRedactionRuntimeForConfig(cfg, &ptr, newScanner)
	if got == nil {
		t.Fatal("expected fail-closed sentinel on scanner secret mismatch")
	}
	if got == stored {
		t.Fatal("runtime built from stale scanner secrets must not be returned")
	}
	if got.matcher != nil {
		t.Fatal("sentinel must not expose a matcher")
	}
	if !got.required {
		t.Fatal("sentinel must require redaction")
	}
}

func TestSetupRedaction_UsesInstalledScannerWithSecretRuntime(t *testing.T) {
	cfg := config.Defaults()
	applyKnownSecretRedactionTestProfile(cfg)

	staleValue := redactionRuntimeFixtureValue("old")
	startupValue := redactionRuntimeFixtureValue("startup")
	staleScanner := redactionRuntimeScannerWithSecret(t, staleValue)
	liveScanner := redactionRuntimeScannerWithSecret(t, startupValue)

	p := &Proxy{}
	p.scannerPtr.Store(staleScanner)
	if err := p.setupRedaction(cfg, liveScanner); err != nil {
		t.Fatalf("setupRedaction: %v", err)
	}
	p.scannerPtr.Store(liveScanner)

	rt := p.currentRedactionRuntimeFor(cfg)
	assertRedactionRuntimeMatchesScanner(t, cfg, liveScanner, rt)
	assertKnownSecretBodyRedacted(t, liveScanner, rt, startupValue)
}

func TestCurrentRedactionRuntimeForConfig_ReloadWindowSelectsPreviousRuntimeForOldScanner(t *testing.T) {
	cfg := config.Defaults()
	applyKnownSecretRedactionTestProfile(cfg)

	oldValue := redactionRuntimeFixtureValue("old")
	newValue := redactionRuntimeFixtureValue("new")
	oldScanner := redactionRuntimeScannerWithSecret(t, oldValue)
	newScanner := redactionRuntimeScannerWithSecret(t, newValue)

	p := &Proxy{}
	oldRuntime, err := p.buildRedactionRuntimeWithScanner(cfg, oldScanner)
	if err != nil {
		t.Fatalf("build old redaction runtime: %v", err)
	}
	p.redactionRuntimePtr.Store(oldRuntime)

	newRuntime, err := p.buildRedactionRuntimeWithScanner(cfg, newScanner)
	if err != nil {
		t.Fatalf("build new redaction runtime: %v", err)
	}
	p.redactionRuntimePtr.Store(newRuntime)

	got := currentRedactionRuntimeForConfig(cfg, &p.redactionRuntimePtr, oldScanner)
	if got == nil {
		t.Fatal("reload window selected no runtime, want previous-runtime fallback")
	}
	if got.configKey != oldRuntime.configKey {
		t.Fatalf("reload window selected runtime with configKey %q, want %q", got.configKey, oldRuntime.configKey)
	}
	// Shallow copy preserves matcher pointer identity so the old matcher is
	// reused (no double-compile) even though the carrying struct is fresh.
	if got.matcher != oldRuntime.matcher {
		t.Fatal("reload window selected a different matcher than the previous runtime's")
	}
	// Chain depth must be bounded at 1 so long-running pods that rotate
	// scanner secrets don't accumulate every prior matcher across reloads.
	if newRuntime.previous == nil {
		t.Fatal("new runtime did not chain the previous runtime as a one-hop fallback")
	}
	if newRuntime.previous.previous != nil {
		t.Fatal("previous-chain depth > 1; expected bounded at 1 to prevent unbounded memory growth")
	}
	assertKnownSecretBodyRedacted(t, oldScanner, got, oldValue)
}

func TestProxyRedactionRuntime_ReloadStateMatrixMaintainsScannerInvariant(t *testing.T) {
	oldValue := redactionRuntimeFixtureValue("old")
	newValue := redactionRuntimeFixtureValue("new")
	startupValue := redactionRuntimeFixtureValue("startup")

	cfg := redactionRuntimeConfigWithSecret(t, oldValue, true)
	initialScanner := scanner.New(cfg)
	t.Cleanup(initialScanner.Close)

	p, err := New(cfg, audit.NewNop(), initialScanner, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	assertProxyRedactionInvariant(t, p, cfg, initialScanner, true)

	tests := []struct {
		name             string
		secret           string
		redactionEnabled bool
		expectRuntime    bool
	}{
		{
			name:             "reload-with-change",
			secret:           newValue,
			redactionEnabled: true,
			expectRuntime:    true,
		},
		{
			name:             "reload-no-change",
			secret:           newValue,
			redactionEnabled: true,
			expectRuntime:    true,
		},
		{
			name:             "disable",
			secret:           newValue,
			redactionEnabled: false,
			expectRuntime:    false,
		},
		{
			name:             "re-enable",
			secret:           startupValue,
			redactionEnabled: true,
			expectRuntime:    true,
		},
		{
			name:             "downgrade",
			secret:           oldValue,
			redactionEnabled: true,
			expectRuntime:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCfg := redactionRuntimeConfigWithSecret(t, tt.secret, tt.redactionEnabled)
			nextScanner := scanner.New(nextCfg)
			t.Cleanup(nextScanner.Close)

			if ok := p.Reload(nextCfg, nextScanner); !ok {
				t.Fatal("Reload returned false")
			}
			assertProxyRedactionInvariant(t, p, nextCfg, nextScanner, tt.expectRuntime)
		})
	}
}

func TestCurrentRedactionRuntimeForConfig_StaleScannerStillBlocksBodyScan(t *testing.T) {
	cfg := config.Defaults()
	applyKnownSecretRedactionTestProfile(cfg)

	oldValue := redactionRuntimeFixtureValue("old")
	newValue := redactionRuntimeFixtureValue("new")
	oldScanner := redactionRuntimeScannerWithSecret(t, oldValue)
	newScanner := redactionRuntimeScannerWithSecret(t, newValue)

	p := &Proxy{}
	oldRuntime, err := p.buildRedactionRuntimeWithScanner(cfg, oldScanner)
	if err != nil {
		t.Fatalf("build redaction runtime: %v", err)
	}
	p.redactionRuntimePtr.Store(oldRuntime)

	got := currentRedactionRuntimeForConfig(cfg, &p.redactionRuntimePtr, newScanner)
	if got == oldRuntime {
		t.Fatal("stale scanner secret change returned old runtime")
	}
	if got == nil || got.matcher != nil || !got.required {
		t.Fatalf("stale scanner mismatch returned %+v, want required nil-matcher sentinel", got)
	}

	_, result := scanKnownSecretBody(t, newScanner, got, newValue)
	if result.Clean {
		t.Fatal("stale scanner mismatch body scan was clean, want fail-closed block")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("Action = %q, want %q", result.Action, config.ActionBlock)
	}
	if !strings.Contains(result.Reason, "redaction runtime unavailable") {
		t.Fatalf("Reason = %q, want redaction runtime unavailable", result.Reason)
	}
}

func writeRedactionRuntimeSecretFile(t *testing.T, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.txt")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write secrets file: %v", err)
	}
	return path
}

func applyKnownSecretRedactionTestProfile(cfg *config.Config) {
	cfg.Redaction = redact.Config{
		Enabled:        true,
		DefaultProfile: "known",
		Profiles: map[string]redact.ProfileSpec{
			"known": {Classes: []string{string(redact.ClassKnownSecret)}},
		},
		Limits: redact.DefaultLimits(),
	}
}

func redactionRuntimeConfigWithSecret(t *testing.T, secret string, redactionEnabled bool) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.SecretsFile = writeRedactionRuntimeSecretFile(t, secret)
	applyKnownSecretRedactionTestProfile(cfg)
	cfg.Redaction.Enabled = redactionEnabled
	return cfg
}

func redactionRuntimeScannerWithSecret(t *testing.T, secret string) *scanner.Scanner {
	t.Helper()
	cfg := redactionRuntimeConfigWithSecret(t, secret, true)
	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func redactionRuntimeFixtureValue(label string) string {
	return strings.Join([]string{label, "redaction", "runtime", "value", "1234"}, "-")
}

func assertProxyRedactionInvariant(t *testing.T, p *Proxy, cfg *config.Config, sc *scanner.Scanner, expectRuntime bool) {
	t.Helper()
	got := p.currentRedactionRuntimeFor(cfg)
	if !expectRuntime {
		if got != nil {
			t.Fatalf("current redaction runtime = %+v, want nil when disabled", got)
		}
		return
	}
	assertRedactionRuntimeMatchesScanner(t, cfg, sc, got)
}

func assertRedactionRuntimeMatchesScanner(t *testing.T, cfg *config.Config, sc *scanner.Scanner, rt *redactionRuntime) {
	t.Helper()
	if rt == nil {
		t.Fatal("current redaction runtime is nil")
	}
	if rt.matcher == nil {
		t.Fatal("current redaction runtime has nil matcher")
	}
	want := redactionConfigKeyForScanner(cfg, sc)
	if rt.configKey != want {
		t.Fatalf("redaction runtime configKey = %q, want %q", rt.configKey, want)
	}
}

func assertKnownSecretBodyRedacted(t *testing.T, sc *scanner.Scanner, rt *redactionRuntime, secret string) {
	t.Helper()
	buf, result := scanKnownSecretBody(t, sc, rt, secret)
	if result.Action == config.ActionBlock {
		t.Fatalf("body scan result = %+v, want redaction without fail-closed block", result)
	}
	if result.RedactionBlockReason != "" {
		t.Fatalf("RedactionBlockReason = %q, want empty", result.RedactionBlockReason)
	}
	if result.RedactionReport == nil {
		t.Fatal("RedactionReport is nil, want known secret redaction")
	}
	if bytes.Contains(buf, []byte(secret)) {
		t.Fatalf("redacted body still contains known secret %q: %s", secret, string(buf))
	}
	if !bytes.Contains(buf, []byte("<pl:known-secret:1>")) {
		t.Fatalf("redacted body = %s, want known-secret placeholder", string(buf))
	}
}

func scanKnownSecretBody(t *testing.T, sc *scanner.Scanner, rt *redactionRuntime, secret string) ([]byte, BodyScanResult) {
	t.Helper()
	bodyReq := BodyScanRequest{
		Body:        bytes.NewReader([]byte(`{"secret":"` + secret + `"}`)),
		Method:      http.MethodPost,
		ContentType: contentTypeJSON,
		MaxBytes:    4096,
		Scanner:     sc,
	}
	applyBodyScanRedaction(&bodyReq, rt)
	return scanRequestBody(context.Background(), bodyReq)
}

// TestCurrentRedactionRuntimeForConfig_NoStoredRuntime_FailsClosed covers
// the remaining fail-closed case: cfg says redaction is required but no
// runtime has been published (startup ordering error or equivalent). The
// factory must emit the nil-matcher sentinel so callers block rather than
// silently skipping the redaction step.
func TestCurrentRedactionRuntimeForConfig_NoStoredRuntime_FailsClosed(t *testing.T) {
	cfg := config.Defaults()
	applyRedactionTestProfile(cfg)

	var ptr atomic.Pointer[redactionRuntime]
	got := currentRedactionRuntimeForConfig(cfg, &ptr)
	if got == nil {
		t.Fatal("expected fail-closed sentinel when no runtime is published")
	}
	if got.matcher != nil {
		t.Fatal("sentinel must not expose a matcher")
	}
	if !got.required {
		t.Fatal("sentinel must require redaction so callers block")
	}
}

func TestCurrentRedactionConfigFor_DisabledReturnsEmpty(t *testing.T) {
	p := &Proxy{}
	matcher, limits, required := p.CurrentRedactionConfigFor(config.Defaults())
	if matcher != nil {
		t.Fatal("disabled redaction should not expose a matcher")
	}
	if limits != (redact.Limits{}) {
		t.Fatalf("limits = %+v, want empty", limits)
	}
	if required {
		t.Fatal("disabled redaction should not be required")
	}
}

func TestProxyRuntimeAccessors(t *testing.T) {
	p := &Proxy{}
	if p.ReloadLock() == nil {
		t.Fatal("ReloadLock returned nil")
	}
	if p.ReceiptEmitterPtr() != &p.receiptEmitterPtr {
		t.Fatal("ReceiptEmitterPtr did not return proxy receipt emitter pointer")
	}
	if p.RedactMatcherPtr() != &p.redactMatcherPtr {
		t.Fatal("RedactMatcherPtr did not return proxy redaction matcher pointer")
	}
}
