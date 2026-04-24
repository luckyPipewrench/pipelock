// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
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

func TestCurrentRedactionRuntimeForConfig_MismatchUsesStoredRuntime(t *testing.T) {
	// Regression for CC-4: during the hot-reload window the atomic may hold
	// a runtime whose configKey was computed from a config that the caller
	// has not yet observed. The previous behavior was to fail-closed with a
	// nil-matcher sentinel, which meant requests landing in a
	// sub-millisecond window during reload were blocked with
	// "redaction runtime unavailable". The corrected behavior is to trust
	// the atomically-stored runtime (the reload path only publishes a
	// non-nil runtime when the matcher is populated and the policy is
	// enabled), which keeps redaction running through the reload window
	// instead of flipping to fail-closed.
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
	if got != stored {
		t.Fatalf("expected stored runtime to win during reload window, got %p (want %p)", got, stored)
	}
}

func TestCurrentRedactionConfigFor_ReloadWindowStillPropagatesMatcher(t *testing.T) {
	// Paired with TestCurrentRedactionRuntimeForConfig_MismatchUsesStoredRuntime:
	// when the atomic holds a populated runtime the public accessor must
	// expose its matcher even if the caller's cfg has not yet been swapped
	// in. Previously this path returned (nil, limits, true) as a
	// fail-closed sentinel, which was spurious during hot reload.
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
	if matcher != matcherInstance {
		t.Fatalf("expected stored matcher (%p), got %p", matcherInstance, matcher)
	}
	if !required {
		t.Fatal("stored runtime had required=true; must be preserved")
	}
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
