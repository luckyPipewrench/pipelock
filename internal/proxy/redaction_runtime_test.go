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

func TestCurrentRedactionRuntimeForConfig_MismatchReturnsFailClosedSentinel(t *testing.T) {
	cfg := config.Defaults()
	applyRedactionTestProfile(cfg)

	var ptr atomic.Pointer[redactionRuntime]
	ptr.Store(&redactionRuntime{
		matcher:   &redact.Matcher{},
		configKey: "old-policy",
		required:  true,
	})

	got := currentRedactionRuntimeForConfig(cfg, &ptr)
	if got == nil {
		t.Fatal("expected fail-closed sentinel")
	}
	if got.matcher != nil {
		t.Fatal("mismatch sentinel should not expose a matcher")
	}
	if !got.required {
		t.Fatal("mismatch sentinel should require redaction")
	}
	if got.configKey != redactionConfigKey(cfg) {
		t.Fatalf("configKey = %q, want %q", got.configKey, redactionConfigKey(cfg))
	}
}

func TestCurrentRedactionConfigFor_PropagatesRequiredSentinel(t *testing.T) {
	cfg := config.Defaults()
	applyRedactionTestProfile(cfg)

	p := &Proxy{}
	p.redactionRuntimePtr.Store(&redactionRuntime{
		matcher:   &redact.Matcher{},
		configKey: "old-policy",
		required:  true,
	})

	matcher, limits, required := p.CurrentRedactionConfigFor(cfg)
	if matcher != nil {
		t.Fatal("mismatch sentinel should not expose a matcher")
	}
	if !required {
		t.Fatal("mismatch sentinel must preserve required=true")
	}
	if limits != cfg.Redaction.Limits.ToLimits() {
		t.Fatalf("limits = %+v, want %+v", limits, cfg.Redaction.Limits.ToLimits())
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
