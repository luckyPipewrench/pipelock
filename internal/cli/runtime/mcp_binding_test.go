// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp"
)

func fakeLookup(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

func mustHeaders(t *testing.T, lines ...string) http.Header {
	t.Helper()
	h, err := parseHeaderFlags(lines)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func upstreamBinding(t *testing.T, url string, lines ...string) string {
	t.Helper()
	return mcpServerBinding(mcpBindingInputs{UpstreamURL: url, Headers: mustHeaders(t, lines...)})
}

func childBinding(t *testing.T, resolved, envVars []string, host map[string]string) string {
	t.Helper()
	env, err := buildChildExtraEnv(resolved, envVars, fakeLookup(host))
	if err != nil {
		t.Fatal(err)
	}
	return mcpServerBinding(mcpBindingInputs{Command: []string{"server", "--port", "1"}, ChildEnv: env})
}

const bindingURL = "https://mcp.vendor.example/mcp"

func TestMCPServerBindingFollowsEffectiveHeaders(t *testing.T) {
	base := upstreamBinding(t, bindingURL, "X-Tenant: alpha", "Authorization: Bearer synthetic-a")
	for name, lines := range map[string][]string{
		"name case":           {"x-tenant: alpha", "Authorization: Bearer synthetic-a"},
		"spacing":             {"X-Tenant:alpha  ", "Authorization: Bearer synthetic-a"},
		"distinct name order": {"Authorization: Bearer synthetic-a", "X-Tenant: alpha"},
	} {
		if got := upstreamBinding(t, bindingURL, lines...); got != base {
			t.Errorf("%s changed the binding", name)
		}
	}
	seen := map[string]string{base: "base"}
	for name, lines := range map[string][]string{
		"tenant value":       {"X-Tenant: beta", "Authorization: Bearer synthetic-a"},
		"credential":         {"X-Tenant: alpha", "Authorization: Bearer synthetic-b"},
		"header added":       {"X-Tenant: alpha", "Authorization: Bearer synthetic-a", "X-Org: one"},
		"header removed":     {"X-Tenant: alpha"},
		"repeated forward":   {"X-Tenant: alpha", "X-Tenant: beta", "Authorization: Bearer synthetic-a"},
		"repeated reversed":  {"X-Tenant: beta", "X-Tenant: alpha", "Authorization: Bearer synthetic-a"},
		"value names header": {"X-Tenant: header:Authorization", "Authorization: Bearer synthetic-a"},
	} {
		got := upstreamBinding(t, bindingURL, lines...)
		if prior, dup := seen[got]; dup {
			t.Errorf("%s shares a binding with %s", name, prior)
		}
		seen[got] = name
	}
}

func TestMCPServerBindingFollowsEffectiveChildEnvironment(t *testing.T) {
	host := map[string]string{"PROFILE": "work"}
	resolved := []string{"API_BASE=https://api.vendor.example", "DEBUG"}
	base := childBinding(t, resolved, []string{"REGION=eu", "PROFILE"}, host)
	if got := childBinding(t, resolved, []string{"REGION=eu", "PROFILE"}, map[string]string{"PROFILE": "work", "HOME": "/x"}); got != base {
		t.Error("an inherited variable the operator did not name changed the binding")
	}
	// Two writes of the same variable resolve to the last one.
	if childBinding(t, nil, []string{"ENDPOINT=a", "ENDPOINT=b"}, nil) == childBinding(t, nil, []string{"ENDPOINT=b", "ENDPOINT=a"}, nil) {
		t.Error("reversing repeated writes of one variable kept the binding, though the effective value changed")
	}
	if childBinding(t, nil, []string{"ENDPOINT=a", "ENDPOINT=b"}, nil) != childBinding(t, nil, []string{"ENDPOINT=b"}, nil) {
		t.Error("an overwritten value still counted in the binding")
	}
	seen := map[string]string{base: "base"}
	for name, b := range map[string]string{
		"env value":         childBinding(t, resolved, []string{"REGION=us", "PROFILE"}, host),
		"passed host value": childBinding(t, resolved, []string{"REGION=eu", "PROFILE"}, map[string]string{"PROFILE": "personal"}),
		"passed var absent": childBinding(t, resolved, []string{"REGION=eu", "PROFILE"}, nil),
		"carrier value":     childBinding(t, []string{"API_BASE=https://api2.vendor.example", "DEBUG"}, []string{"REGION=eu", "PROFILE"}, host),
		"unset dropped":     childBinding(t, []string{"API_BASE=https://api.vendor.example"}, []string{"REGION=eu", "PROFILE"}, host),
		"env added":         childBinding(t, resolved, []string{"REGION=eu", "PROFILE", "EXTRA=1"}, host),
	} {
		if prior, dup := seen[b]; dup {
			t.Errorf("%s shares a binding with %s", name, prior)
		}
		seen[b] = name
	}
}

func TestChildEnvOverrideIdentityMatchesMergeRules(t *testing.T) {
	got := mcp.ChildEnvOverrideIdentity([]string{"A=1", "B", "A=2", "B=3", "C=4", "C"})
	want := []string{"set:A=2", "set:B=3", "unset:C"}
	if len(got) != len(want) {
		t.Fatalf("identity = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("identity = %v, want %v", got, want)
		}
	}
}
