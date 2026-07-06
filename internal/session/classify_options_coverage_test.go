// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

// TestClassifyWithOptions_BranchCoverage exercises the WithOptions classifier
// and policy-evaluation branches under both fail-safe settings, so the fail-safe
// and per-class fail-safe classification paths are covered.
func TestClassifyWithOptions_BranchCoverage(t *testing.T) {
	t.Parallel()

	protected := []string{"*/auth/*", "*/.env*"}
	elevated := []string{"*/config/*", "*/middleware*"}

	mcp := []struct {
		name string
		tool string
		args string
		want session.ActionClass
	}{
		{"write", "write_file", `{"path":"/repo/auth/middleware.go","content":"x"}`, session.ActionClassWrite},
		{"exec", "shell", `{"command":"git push origin main"}`, session.ActionClassExec},
		{"secret", "read_file", `{"path":"/home/u/.ssh/id_rsa"}`, session.ActionClassSecret},
		{"browse", "browse_url", `{"url":"https://example.com/docs"}`, session.ActionClassBrowse},
		{"unknown_read", "mystery_tool", `{}`, session.ActionClassRead},
	}
	for _, tc := range mcp {
		for _, fs := range []bool{false, true} {
			got := session.ClassifyMCPToolCallWithOptions(tc.tool, tc.args, protected, elevated, session.ClassificationOptions{FailSafe: fs})
			if got.Class != tc.want {
				t.Fatalf("mcp %s (failsafe=%v): class=%v want %v", tc.name, fs, got.Class, tc.want)
			}
		}
	}

	httpCases := []struct {
		name   string
		method string
		path   string
		want   session.ActionClass
	}{
		{"get_read", "GET", "/repo/readme.md", session.ActionClassRead},
		{"post_publish", "POST", "/repo/config/app.yaml", session.ActionClassPublish},
		{"delete_publish", "DELETE", "/repo/auth/token", session.ActionClassPublish},
		{"unknown_method_network", "PROPFIND", "/x", session.ActionClassNetwork},
	}
	for _, tc := range httpCases {
		for _, fs := range []bool{false, true} {
			got := session.ClassifyHTTPActionWithOptions(tc.method, tc.path, protected, elevated, session.ClassificationOptions{FailSafe: fs})
			if got.Class != tc.want {
				t.Fatalf("http %s (failsafe=%v): class=%v want %v", tc.name, fs, got.Class, tc.want)
			}
		}
	}

	// Exercise the untrusted policy switch branches (write/exec/secret/network)
	// plus the trusted early-return, under strict profile.
	pm := session.PolicyMatrix{Profile: "strict"}
	combos := []struct {
		taint session.TaintLevel
		act   session.ActionClass
		sens  session.ActionSensitivity
		auth  session.AuthorityKind
	}{
		{session.TaintExternalUntrusted, session.ActionClassWrite, session.SensitivityProtected, session.AuthorityUserBroad},
		{session.TaintExternalUntrusted, session.ActionClassExec, session.SensitivityElevated, session.AuthorityUserBroad},
		{session.TaintExternalUntrusted, session.ActionClassSecret, session.SensitivityProtected, session.AuthorityUserBroad},
		{session.TaintExternalUntrusted, session.ActionClassNetwork, session.SensitivityElevated, session.AuthorityUserBroad},
		{session.TaintTrusted, session.ActionClassWrite, session.SensitivityProtected, session.AuthorityUserBroad},
	}
	for _, c := range combos {
		_ = pm.EvaluateWithOptions(c.taint, c.act, c.sens, c.auth, session.PolicyEvaluateOptions{ClassificationConfident: true})
	}
}
