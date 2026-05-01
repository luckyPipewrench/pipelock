// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractstore "github.com/luckyPipewrench/pipelock/internal/contract/store"
)

func TestLearnCmdRegistersPromoteAndRollback(t *testing.T) {
	cmd := Cmd()
	for _, name := range []string{"promote", "rollback"} {
		t.Run(name, func(t *testing.T) {
			found := false
			for _, child := range cmd.Commands() {
				if child.Name() == name {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("learn command missing %q", name)
			}
		})
	}
}

func TestBuildManifestSelectorComputesStableIDs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		input     string
		wantAgent string
		wantGlob  string
		wantDef   bool
	}{
		{name: "agent", input: "worker-a", wantAgent: "worker-a"},
		{name: "glob", input: "worker-*", wantGlob: "worker-*"},
		{name: "default", input: "default", wantDef: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selector, err := buildManifestSelector(tc.input, "sha256:contract")
			if err != nil {
				t.Fatalf("buildManifestSelector: %v", err)
			}
			if selector.Agent != tc.wantAgent || selector.AgentGlob != tc.wantGlob || selector.Default != tc.wantDef {
				t.Fatalf("selector = %+v", selector)
			}
			recomputed, err := selector.ComputeSelectorID()
			if err != nil {
				t.Fatalf("ComputeSelectorID: %v", err)
			}
			if selector.SelectorID == "" || selector.SelectorID != recomputed {
				t.Fatalf("selector_id = %q recomputed=%q", selector.SelectorID, recomputed)
			}
		})
	}

	if _, err := buildManifestSelector("", "sha256:contract"); err == nil || !strings.Contains(err.Error(), "--selector") {
		t.Fatalf("empty selector err = %v, want --selector", err)
	}
	if _, err := buildManifestSelector("worker-a", ""); err == nil || !strings.Contains(err.Error(), "--contract") {
		t.Fatalf("empty contract err = %v, want --contract", err)
	}
}

func TestResolveLifecycleEnvironmentInheritsOrRequiresExplicit(t *testing.T) {
	env := contract.Environment{ID: "prod", Tenant: "tenant", DeploymentID: "dep"}
	got, err := resolveLifecycleEnvironment(lifecycleFlags{}, contractstore.State{
		Envelope: contract.ActiveManifestEnvelope{Body: contract.ActiveManifest{Environment: env}},
	}, true)
	if err != nil {
		t.Fatalf("resolve inherited environment: %v", err)
	}
	if got != env {
		t.Fatalf("environment = %+v, want %+v", got, env)
	}

	got, err = resolveLifecycleEnvironment(lifecycleFlags{
		environmentID: "stage",
		tenant:        "tenant",
		deploymentID:  "dep",
	}, contractstore.State{}, false)
	if err != nil {
		t.Fatalf("resolve explicit environment: %v", err)
	}
	if got.ID != "stage" || got.Tenant != "tenant" || got.DeploymentID != "dep" {
		t.Fatalf("explicit environment = %+v", got)
	}

	_, err = resolveLifecycleEnvironment(lifecycleFlags{
		environmentID: "stage",
		tenant:        "tenant",
		deploymentID:  "dep",
	}, contractstore.State{
		Envelope: contract.ActiveManifestEnvelope{Body: contract.ActiveManifest{Environment: env}},
	}, true)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched environment err = %v, want mismatch", err)
	}

	_, err = resolveLifecycleEnvironment(lifecycleFlags{environmentID: "stage"}, contractstore.State{}, false)
	if err == nil || !strings.Contains(err.Error(), "--tenant") {
		t.Fatalf("partial environment err = %v, want missing flag error", err)
	}
}

func TestLifecycleIDDeterministicAndExplicit(t *testing.T) {
	if got := lifecycleID("provided", true, "label"); got != "provided" {
		t.Fatalf("explicit id = %q", got)
	}
	if got := lifecycleID("", true, "label"); got != "label-deterministic" {
		t.Fatalf("deterministic id = %q", got)
	}
	if got := lifecycleID("", false, "label"); got == "" {
		t.Fatal("generated lifecycle id is empty")
	}
}
