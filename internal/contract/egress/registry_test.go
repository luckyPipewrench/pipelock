// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bytes"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/egressevidence"
)

func sampleSite() egressevidence.Site {
	return egressevidence.Site{
		ID: "proxy.forward.body.original", Plane: egressevidence.PlaneProxy,
		Transport: egressevidence.TransportForward, Location: egressevidence.LocationBody,
		View: egressevidence.ViewOriginal, Boundary: egressevidence.BoundaryUpstreamRequest,
	}
}

func registryFor(t *testing.T, sites ...egressevidence.Site) *egressevidence.Registry {
	t.Helper()
	r, err := egressevidence.NewRegistry(sites)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegistryManifestFrozenVector(t *testing.T) {
	t.Parallel()
	r := registryFor(t, sampleSite())
	manifest, err := RegistryManifest(r)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"manifest_kind":"secret_egress_registry","manifest_version":1,"sites":[{"boundary":"upstream_request","id":"proxy.forward.body.original","location":"body","plane":"proxy","transport":"forward","view":"original"}]}`
	if string(manifest) != want {
		t.Fatalf("manifest = %s, want %s", manifest, want)
	}
	digest, err := RegistryHash(r)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256:55acfd283c284a1b11a40b95e1e5a3bec3031cd5f54278f1d34a42d003853cb9" {
		t.Fatalf("registry digest = %s", digest)
	}
}

func TestRegistryDigestStableCompleteAndImmutable(t *testing.T) {
	t.Parallel()
	a, b := sampleSite(), sampleSite()
	b.ID = "proxy.forward.body.transformed"
	b.View = egressevidence.ViewPostTransform
	sites := []egressevidence.Site{b, a}
	r := registryFor(t, sites...)
	before, err := RegistryManifest(r)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(sites)
	after, err := RegistryManifest(registryFor(t, sites...))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("input order affected manifest: %v", err)
	}
	sites[0].ID = "caller-mutated"
	copyOfSites := r.All()
	copyOfSites[0].View = egressevidence.ViewNormalized
	after, err = RegistryManifest(r)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("caller mutation affected manifest: %v", err)
	}
	want, err := RegistryHash(registryFor(t, a))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*egressevidence.Site){
		"id":        func(s *egressevidence.Site) { s.ID = "proxy.forward.body.other" },
		"transport": func(s *egressevidence.Site) { s.Transport = egressevidence.TransportFetch },
		"location":  func(s *egressevidence.Site) { s.Location = egressevidence.LocationHeader },
		"view":      func(s *egressevidence.Site) { s.View = egressevidence.ViewNormalized },
		// Plane and boundary invariants require a coherent transport change.
		"plane_and_boundary": func(s *egressevidence.Site) {
			s.Plane = egressevidence.PlaneHook
			s.Transport = egressevidence.TransportHook
			s.Boundary = egressevidence.BoundaryHookDecision
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			site := a
			mutate(&site)
			got, err := RegistryHash(registryFor(t, site))
			if err != nil || got == want {
				t.Fatalf("complete site change not bound: %s, %v", got, err)
			}
		})
	}
}

func TestRegistryManifestRejectsAbsentRegistry(t *testing.T) {
	t.Parallel()
	for _, r := range []*egressevidence.Registry{nil, {}} {
		if _, err := RegistryManifest(r); err == nil {
			t.Fatal("accepted absent registry")
		}
		if _, err := RegistryHash(r); err == nil {
			t.Fatal("hashed absent registry")
		}
	}
}
