// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestResponseTaintSessionKey_UsesAuthenticatedIdentityBoundary(t *testing.T) {
	const clientIP = "203.0.113.10"
	if first, second := responseTaintSessionKey("rotated-a", clientIP, envelope.ActorAuthSelfDeclared), responseTaintSessionKey("rotated-b", clientIP, envelope.ActorAuthSelfDeclared); first != second {
		t.Fatalf("self-declared agent rotation split taint state: %q != %q", first, second)
	}
	if first, second := responseTaintSessionKey("bound-a", clientIP, envelope.ActorAuthBound), responseTaintSessionKey("bound-b", clientIP, envelope.ActorAuthBound); first == second {
		t.Fatalf("bound identities shared taint state: %q", first)
	}
}

func TestEvaluateHTTPTaintDisabledAndNil(t *testing.T) {
	t.Parallel()

	parsed, err := url.Parse("https://api.vendor.example/write")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg := config.Defaults()
	cfg.Taint.Enabled = false

	got := evaluateHTTPTaint(cfg, &SessionState{}, http.MethodPost, parsed)
	if got.Result.Decision != session.PolicyAllow || got.Result.Reason != "taint_disabled" {
		t.Fatalf("disabled taint = %+v, want allow/taint_disabled", got.Result)
	}

	cfg.Taint.Enabled = true
	if got := evaluateHTTPTaint(cfg, &SessionState{}, http.MethodPost, nil); got.Result.Reason != "taint_disabled" {
		t.Fatalf("nil URL = %+v, want taint_disabled", got.Result)
	}
	if got := evaluateHTTPTaint(nil, &SessionState{}, http.MethodPost, parsed); got.Result.Reason != "taint_disabled" {
		t.Fatalf("nil cfg = %+v, want taint_disabled", got.Result)
	}
}

func TestObserveHTTPResponseTaintNoopWhenDisabled(t *testing.T) {
	t.Parallel()

	sess := &SessionState{}
	cfg := config.Defaults()
	cfg.Taint.Enabled = false
	observeHTTPResponseTaint(sess, cfg, "https://evil.example/issue", "text/html", "fetch_response", true)
	if sess.RiskSnapshot().Contaminated {
		t.Fatal("disabled taint contaminated the session")
	}
	observeHTTPResponseTaint(sess, nil, "https://evil.example/issue", "text/html", "fetch_response", true)
	if sess.RiskSnapshot().Contaminated {
		t.Fatal("nil config contaminated the session")
	}
}

func TestHTTPActionRefNilAndEmptyURI(t *testing.T) {
	t.Parallel()

	if got := httpActionRef(session.ActionClassRead, http.MethodGet, nil); got != "read:get" {
		t.Fatalf("nil URL ref = %q", got)
	}
	parsed := &url.URL{Scheme: "HTTPS", Host: "API.Vendor.Example"}
	got := httpActionRef(session.ActionClassWrite, http.MethodPost, parsed)
	if got != "write:post:https://api.vendor.example/" {
		t.Fatalf("empty URI ref = %q", got)
	}
}

func TestTrustOverrideExpiredAndUnknownScope(t *testing.T) {
	t.Parallel()

	risk := session.SessionRisk{LastExternalURL: "https://evil.example/x"}
	actionRef := "write:post:https://api.vendor.example/auth"
	if trustOverrideApplies([]config.TaintTrustOverride{{
		Scope:       taintScopeAction,
		ActionMatch: "write:post:*",
		ExpiresAt:   time.Now().UTC().Add(-time.Hour),
	}}, risk, actionRef) {
		t.Fatal("expired override applied")
	}
	if overrideMatches(config.TaintTrustOverride{Scope: taintScopeTask}, risk, actionRef) {
		t.Fatal("unknown scope matched")
	}
	if !trustOverrideApplies([]config.TaintTrustOverride{{
		Scope:       taintScopeAction,
		ActionMatch: "write:post:*",
	}}, risk, actionRef) {
		t.Fatal("unexpired action override did not apply")
	}
}

func TestWildcardMatchRejectsAndAccepts(t *testing.T) {
	t.Parallel()

	if !wildcardMatch("https://evil.example/issue", "https://evil.example/*") {
		t.Fatal("suffix wildcard did not match")
	}
	if wildcardMatch("https://cdn.evil.example/issue", "evil.example/*") {
		t.Fatal("mid-string host matched a non-star prefix")
	}
	if !wildcardMatch("https://evil.example/issue", "https://evil.example/issue") {
		t.Fatal("exact match failed")
	}
	if wildcardMatch("foobarx", "foo*bar") {
		t.Fatal("value that does not end with the last wildcard part matched")
	}
}

func TestOverrideMatchesSourceScope(t *testing.T) {
	t.Parallel()

	risk := session.SessionRisk{LastExternalURL: "https://evil.example/issue"}
	actionRef := "write:post:https://api.vendor.example/auth"
	if !overrideMatches(config.TaintTrustOverride{
		Scope:       taintScopeSource,
		SourceMatch: "https://evil.example/*",
	}, risk, actionRef) {
		t.Fatal("source-scope override did not match last external URL")
	}
	if overrideMatches(config.TaintTrustOverride{
		Scope:       taintScopeSource,
		SourceMatch: "https://evil.example/*",
		ActionMatch: "read:get:*",
	}, risk, actionRef) {
		t.Fatal("source-scope override ignored a mismatched action")
	}
	if overrideMatches(config.TaintTrustOverride{
		Scope: taintScopeSource,
	}, risk, actionRef) {
		t.Fatal("source-scope override with empty source matched")
	}
}

func TestRuntimeTrustOverrideAppliesTaskScope(t *testing.T) {
	t.Parallel()

	task := session.TaskContext{CurrentTaskID: "task-abc"}
	risk := session.SessionRisk{LastExternalURL: "https://evil.example/issue"}
	actionRef := "write:post:https://api.vendor.example/auth"
	if !runtimeTrustOverrideApplies([]session.TrustOverride{{
		Scope:  taintScopeTask,
		TaskID: "task-abc",
	}}, task, risk, actionRef) {
		t.Fatal("matching task override did not apply")
	}
	if runtimeTrustOverrideApplies([]session.TrustOverride{{
		Scope:     taintScopeTask,
		TaskID:    "task-abc",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}}, task, risk, actionRef) {
		t.Fatal("expired task override applied")
	}
	if runtimeTrustOverrideApplies([]session.TrustOverride{{
		Scope:  taintScopeAction,
		TaskID: "task-abc",
	}}, task, risk, actionRef) {
		t.Fatal("non-task scope applied as a runtime task override")
	}
	if runtimeTrustOverrideApplies([]session.TrustOverride{{
		Scope:  taintScopeTask,
		TaskID: "task-other",
	}}, task, risk, actionRef) {
		t.Fatal("wrong task id applied")
	}
	if runtimeTrustOverrideApplies([]session.TrustOverride{{
		Scope:       taintScopeTask,
		TaskID:      "task-abc",
		ActionMatch: "read:get:*",
	}}, task, risk, actionRef) {
		t.Fatal("task override ignored a mismatched action")
	}
	if runtimeTrustOverrideApplies([]session.TrustOverride{{
		Scope:       taintScopeTask,
		TaskID:      "task-abc",
		SourceMatch: "https://other.example/*",
	}}, task, risk, actionRef) {
		t.Fatal("task override ignored a mismatched source")
	}
}
