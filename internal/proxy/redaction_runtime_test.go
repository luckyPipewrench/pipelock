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
