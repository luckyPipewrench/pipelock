// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"testing"
)

func TestPreserveConductorBundleLocalRuntimeStateNilInputs(t *testing.T) {
	t.Parallel()

	PreserveConductorBundleLocalRuntimeState(nil, &Config{})
	PreserveConductorBundleLocalRuntimeState(&Config{}, nil)
}

func TestPreserveConductorBundleLocalRuntimeStateCopiesFollowerLocalFields(t *testing.T) {
	t.Parallel()

	oldCfg := &Config{
		FetchProxy:           FetchProxy{Listen: "127.0.0.1:18080", TimeoutSeconds: 12},
		MetricsListen:        "127.0.0.1:19090",
		Internal:             []string{"10.0.0.0/8"},
		TrustedDomains:       []string{"trusted.example"},
		Suppress:             []SuppressEntry{{Rule: "body_dlp", Path: "api.example/*", Reason: "fixture"}},
		Agents:               map[string]AgentProfile{"builder": {Sandbox: &AgentSandboxOverride{Enabled: boolPtr(true)}}},
		LicenseKey:           "license-token",
		LicenseFile:          "/run/pipelock/license",
		DefaultAgentIdentity: "builder",
	}
	newCfg := &Config{
		FetchProxy:           FetchProxy{Listen: "127.0.0.1:28080"},
		MetricsListen:        "127.0.0.1:29090",
		Internal:             []string{"192.168.0.0/16"},
		TrustedDomains:       []string{"other.example"},
		Suppress:             []SuppressEntry{{Rule: "old", Path: "old.example/*"}},
		Agents:               map[string]AgentProfile{"other": {}},
		LicenseKey:           "new-license-token",
		LicenseFile:          "/tmp/new-license",
		DefaultAgentIdentity: "other",
		Conductor:            Conductor{Enabled: true, FleetID: "fleet-from-bundle"},
	}

	PreserveConductorBundleLocalRuntimeState(newCfg, oldCfg)

	if newCfg.FetchProxy.Listen != oldCfg.FetchProxy.Listen {
		t.Fatalf("FetchProxy.Listen = %q, want %q", newCfg.FetchProxy.Listen, oldCfg.FetchProxy.Listen)
	}
	if newCfg.MetricsListen != oldCfg.MetricsListen {
		t.Fatalf("MetricsListen = %q, want %q", newCfg.MetricsListen, oldCfg.MetricsListen)
	}
	if !reflect.DeepEqual(newCfg.Internal, oldCfg.Internal) {
		t.Fatalf("Internal = %#v, want %#v", newCfg.Internal, oldCfg.Internal)
	}
	if !reflect.DeepEqual(newCfg.TrustedDomains, oldCfg.TrustedDomains) {
		t.Fatalf("TrustedDomains = %#v, want %#v", newCfg.TrustedDomains, oldCfg.TrustedDomains)
	}
	if !reflect.DeepEqual(newCfg.Suppress, oldCfg.Suppress) {
		t.Fatalf("Suppress = %#v, want %#v", newCfg.Suppress, oldCfg.Suppress)
	}
	if newCfg.LicenseKey != oldCfg.LicenseKey || newCfg.LicenseFile != oldCfg.LicenseFile {
		t.Fatalf("license fields = (%q, %q), want (%q, %q)", newCfg.LicenseKey, newCfg.LicenseFile, oldCfg.LicenseKey, oldCfg.LicenseFile)
	}
	if newCfg.DefaultAgentIdentity != oldCfg.DefaultAgentIdentity {
		t.Fatalf("DefaultAgentIdentity = %q, want %q", newCfg.DefaultAgentIdentity, oldCfg.DefaultAgentIdentity)
	}
	if !reflect.DeepEqual(newCfg.Agents, oldCfg.Agents) {
		t.Fatalf("Agents = %#v, want %#v", newCfg.Agents, oldCfg.Agents)
	}
	if !newCfg.Conductor.Enabled || newCfg.Conductor.FleetID != "fleet-from-bundle" {
		t.Fatalf("Conductor should remain bundle-owned, got %#v", newCfg.Conductor)
	}

	oldCfg.Internal[0] = "172.16.0.0/12"
	oldCfg.TrustedDomains[0] = "mutated.example"
	oldCfg.Suppress[0].Path = "mutated.example/*"
	oldCfg.Agents["builder"] = AgentProfile{Sandbox: &AgentSandboxOverride{Enabled: boolPtr(false)}}
	if newCfg.Internal[0] == oldCfg.Internal[0] {
		t.Fatal("Internal slice aliases old config")
	}
	if newCfg.TrustedDomains[0] == oldCfg.TrustedDomains[0] {
		t.Fatal("TrustedDomains slice aliases old config")
	}
	if newCfg.Suppress[0].Path == oldCfg.Suppress[0].Path {
		t.Fatal("Suppress slice aliases old config")
	}
	if reflect.DeepEqual(newCfg.Agents["builder"], oldCfg.Agents["builder"]) {
		t.Fatal("Agents map aliases old config")
	}
}
