// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package egressevidence

import (
	"strings"
	"sync"
	"testing"
)

func fixtureSite() Site {
	return Site{
		ID: "fixture.forward.body.original", Plane: PlaneProxy,
		Transport: TransportForward, Location: LocationBody, View: ViewOriginal,
		Boundary: BoundaryUpstreamRequest,
	}
}

func TestSiteValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Site)
	}{
		{"empty id", func(s *Site) { s.ID = "" }},
		{"long id", func(s *Site) { s.ID = SiteID(strings.Repeat("x", 129)) }},
		{"whitespace id", func(s *Site) { s.ID = " site" }},
		{"content id", func(s *Site) { s.ID = "header=value" }},
		{"plane", func(s *Site) { s.Plane = "unknown" }},
		{"transport", func(s *Site) { s.Transport = "unknown" }},
		{"hook transport", func(s *Site) { s.Transport = TransportHook }},
		{"proxy transport", func(s *Site) { s.Plane = PlaneHook }},
		{"location", func(s *Site) { s.Location = "unknown" }},
		{"view", func(s *Site) { s.View = "unknown" }},
		{"boundary", func(s *Site) { s.Boundary = "unknown" }},
		{"hook boundary", func(s *Site) { s.Boundary = BoundaryHookDecision }},
		{"proxy boundary", func(s *Site) { s.Plane = PlaneHook; s.Transport = TransportHook }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			site := fixtureSite()
			tt.edit(&site)
			if err := site.Validate(); err == nil {
				t.Fatal("invalid site accepted")
			}
		})
	}
	if err := fixtureSite().Validate(); err != nil {
		t.Fatal(err)
	}
	hook := fixtureSite()
	hook.Plane, hook.Transport, hook.Boundary = PlaneHook, TransportHook, BoundaryHookDecision
	if err := hook.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryIsImmutableAndOrdered(t *testing.T) {
	one := fixtureSite()
	two := one
	two.ID = "fixture.a"
	input := []Site{one, two}
	r, err := NewRegistry(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].ID = "mutated"
	all := r.All()
	if len(all) != 2 || all[0] != two || all[1] != one {
		t.Fatalf("registry ordering/content changed: %+v", all)
	}
	all[0].ID = "mutated"
	if got, ok := r.Lookup(two.ID); !ok || got != two {
		t.Fatalf("registry mutated through All: %+v, %v", got, ok)
	}
	if _, ok := r.Lookup("unknown"); ok {
		t.Fatal("unknown site accepted")
	}
	var nilRegistry *Registry
	if _, ok := nilRegistry.Lookup(one.ID); ok || nilRegistry.All() != nil {
		t.Fatal("nil registry claimed a site")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				if got, ok := r.Lookup(one.ID); !ok || got != one {
					t.Error("concurrent registry read changed")
				}
				_ = r.All()
			}
		})
	}
	wg.Wait()
}

func TestRegistryRejectsInvalidDeclarations(t *testing.T) {
	for _, sites := range [][]Site{nil, {{}}, {fixtureSite(), fixtureSite()}} {
		if _, err := NewRegistry(sites); err == nil {
			t.Fatal("invalid declaration accepted")
		}
	}
}

func TestIdentifierBounds(t *testing.T) {
	if !validIdentifier(strings.Repeat("a", 128)) || !validIdentifier("AZ09._-:az") {
		t.Fatal("valid reference rejected")
	}
	for _, value := range []string{"", "é", "api.vendor.example/path", "a b", "a\n", " a"} {
		if validIdentifier(value) {
			t.Fatalf("invalid reference accepted: %q", value)
		}
	}
}

func TestSiteTransportBoundaryMatrix(t *testing.T) {
	want := map[Transport][]Boundary{
		TransportFetch:           {BoundaryUpstreamRequest},
		TransportForward:         {BoundaryUpstreamRequest},
		TransportIntercept:       {BoundaryUpstreamRequest},
		TransportReverse:         {BoundaryUpstreamRequest},
		TransportConnect:         {BoundaryTunnel},
		TransportWebSocket:       {BoundaryUpstreamRequest, BoundaryUpstreamFrame},
		TransportMCPStdio:        {BoundaryUpstreamRequest, BoundaryToolDispatch},
		TransportMCPHTTPListener: {BoundaryUpstreamRequest, BoundaryToolDispatch},
		TransportMCPHTTPUpstream: {BoundaryUpstreamRequest, BoundaryToolDispatch},
		TransportMCPWS:           {BoundaryUpstreamRequest, BoundaryToolDispatch},
		TransportHook:            {BoundaryHookDecision},
	}
	boundaries := []Boundary{
		BoundaryUpstreamRequest, BoundaryUpstreamFrame,
		BoundaryTunnel, BoundaryToolDispatch, BoundaryHookDecision,
	}
	for transport, allowed := range want {
		for _, boundary := range boundaries {
			t.Run(string(transport)+"/"+string(boundary), func(t *testing.T) {
				site := fixtureSite()
				site.Transport, site.Boundary = transport, boundary
				if transport == TransportHook {
					site.Plane = PlaneHook
				}
				valid := false
				for _, permitted := range allowed {
					valid = valid || boundary == permitted
				}
				if err := site.Validate(); (err == nil) != valid {
					t.Fatalf("Validate = %v, want valid=%v", err, valid)
				}
			})
		}
	}
	if (Site{Transport: "unknown"}).transportAllowsBoundary() {
		t.Fatal("unknown transport accepted")
	}
}
