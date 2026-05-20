// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBuildRedactionRuntime_DisabledReturnsNil(t *testing.T) {
	cfg := config.Defaults()
	p := &Proxy{}

	rt, err := p.buildRedactionRuntime(cfg)
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

func writeRedactionRuntimeSecretFile(t *testing.T, secret string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.txt")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write secrets file: %v", err)
	}
	return path
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
