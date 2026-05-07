// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package contractruntimetest is a test-only support package consumed by
// loader_test.go in the contract/runtime package and by the forward-proxy
// contract gate tests in the proxy package. The smoke tests below
// exercise the public surface so the cover profile records the package
// — without them, go test ./... skips instrumentation here because the
// package has no callers in its own _test files. Cross-package callers
// in proxy and contract/runtime do exercise these helpers, but the
// default Go cover mode only counts hits on packages with their own
// tests.
package contractruntimetest

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

func TestFixture_AccessorsExposeRosterAndRoot(t *testing.T) {
	t.Parallel()
	f := NewFixture(t)
	if f.RosterPath() == "" {
		t.Fatal("RosterPath empty")
	}
	if f.RootFingerprint() == "" {
		t.Fatal("RootFingerprint empty")
	}
	if f.Root() == "" {
		t.Fatal("Root empty")
	}
	if Env() != (contract.Environment{ID: "prod"}) {
		t.Fatalf("Env() = %v, want prod", Env())
	}
}

func TestWriteSignedActiveStore_WritesActiveJSON(t *testing.T) {
	t.Parallel()
	f := NewFixture(t)
	storeDir := filepath.Join(f.Root(), "store")
	WriteSignedActiveStore(t, f, storeDir, ActiveStoreOptions{
		Generation:  1,
		PriorHash:   "sha256:genesis",
		Environment: Env(),
	})
}

func TestWriteAcceptedActiveStore_ReturnsManifestHash(t *testing.T) {
	t.Parallel()
	f := NewFixture(t)
	storeDir := filepath.Join(f.Root(), "store")
	hash := WriteAcceptedActiveStore(t, f, storeDir, ActiveStoreOptions{
		Generation:  1,
		PriorHash:   "sha256:genesis",
		Environment: Env(),
	})
	if hash == "" {
		t.Fatal("WriteAcceptedActiveStore returned empty hash")
	}
}

func TestHTTPEnforceRule_ReturnsValidEnforceRule(t *testing.T) {
	t.Parallel()
	rule := HTTPEnforceRule("r-test", "api.example.com", "/v1/chat", http.MethodPost)
	if rule.RuleID != "r-test" || rule.LifecycleState != contract.LifecycleEnforce {
		t.Fatalf("rule = %+v", rule)
	}
	if rule.RuleKind != contract.RuleKindHTTPDestination {
		t.Fatalf("rule_kind = %q", rule.RuleKind)
	}
}
