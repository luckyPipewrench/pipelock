// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package egressevidence defines the secret-egress evidence contract. It does
// not scan, authorize, emit receipts, or claim that a transport is instrumented.
package egressevidence

import (
	"fmt"
	"slices"
	"strings"
)

// SiteID identifies one classification boundary, including its view and mode.
// Reusing an ID for a different boundary is a contract change.
type SiteID string

type Plane string

const (
	PlaneProxy Plane = "proxy"
	PlaneHook  Plane = "hook"
)

type Transport string

const (
	TransportFetch           Transport = "fetch"
	TransportForward         Transport = "forward"
	TransportConnect         Transport = "connect"
	TransportIntercept       Transport = "intercept"
	TransportReverse         Transport = "reverse"
	TransportWebSocket       Transport = "websocket"
	TransportMCPStdio        Transport = "mcp_stdio"
	TransportMCPHTTPListener Transport = "mcp_http_listener"
	TransportMCPHTTPUpstream Transport = "mcp_http_upstream"
	TransportMCPWS           Transport = "mcp_ws"
	TransportHook            Transport = "agent_hook"
)

type Location string

const (
	LocationURL           Location = "url"
	LocationHeader        Location = "header"
	LocationBody          Location = "body"
	LocationToolArguments Location = "tool_arguments"
	LocationEnvelope      Location = "envelope"
	LocationFrame         Location = "frame"
)

// View distinguishes decisions which happen before and after transformation.
// A logical classification boundary must not silently change its view.
type View string

const (
	ViewOriginal      View = "original"
	ViewNormalized    View = "normalized"
	ViewPostTransform View = "post_transform"
	ViewReassembled   View = "reassembled"
	ViewAuthorization View = "authorization"
)

type Boundary string

const (
	BoundaryUpstreamRequest Boundary = "upstream_request"
	BoundaryUpstreamFrame   Boundary = "upstream_frame"
	BoundaryTunnel          Boundary = "tunnel_admission"
	BoundaryToolDispatch    Boundary = "tool_dispatch"
	BoundaryHookDecision    Boundary = "hook_decision"
)

// Site names an obligation, not evidence that the obligation has been met.
// Producer instrumentation and coverage declarations are independently checked.
type Site struct {
	ID        SiteID
	Plane     Plane
	Transport Transport
	Location  Location
	View      View
	Boundary  Boundary
}

func (s Site) Validate() error {
	if !validIdentifier(string(s.ID)) {
		return fmt.Errorf("invalid classification site ID")
	}
	if s.Plane != PlaneProxy && s.Plane != PlaneHook {
		return fmt.Errorf("invalid classification plane")
	}
	if !slices.Contains([]Transport{
		TransportFetch, TransportForward, TransportConnect,
		TransportIntercept, TransportReverse, TransportWebSocket, TransportMCPStdio,
		TransportMCPHTTPListener, TransportMCPHTTPUpstream, TransportMCPWS, TransportHook,
	}, s.Transport) {
		return fmt.Errorf("invalid classification transport")
	}
	if (s.Plane == PlaneHook) != (s.Transport == TransportHook) {
		return fmt.Errorf("classification plane and transport disagree")
	}
	if !slices.Contains([]Location{
		LocationURL, LocationHeader, LocationBody,
		LocationToolArguments, LocationEnvelope, LocationFrame,
	}, s.Location) {
		return fmt.Errorf("invalid classification location")
	}
	if !slices.Contains([]View{
		ViewOriginal, ViewNormalized, ViewPostTransform,
		ViewReassembled, ViewAuthorization,
	}, s.View) {
		return fmt.Errorf("invalid classification view")
	}
	if !slices.Contains([]Boundary{
		BoundaryUpstreamRequest, BoundaryUpstreamFrame,
		BoundaryTunnel, BoundaryToolDispatch, BoundaryHookDecision,
	}, s.Boundary) {
		return fmt.Errorf("invalid protected boundary")
	}
	if (s.Plane == PlaneHook) != (s.Boundary == BoundaryHookDecision) {
		return fmt.Errorf("classification plane and boundary disagree")
	}
	if !s.transportAllowsBoundary() {
		return fmt.Errorf("classification transport and boundary disagree")
	}
	return nil
}

// transportAllowsBoundary rejects category errors without claiming a complete
// production-site inventory. The maintained registry must additionally bind the
// exact protocol-specific location, view and classification mode.
func (s Site) transportAllowsBoundary() bool {
	switch s.Transport {
	case TransportFetch, TransportForward, TransportIntercept, TransportReverse:
		return s.Boundary == BoundaryUpstreamRequest
	case TransportConnect:
		return s.Boundary == BoundaryTunnel
	case TransportWebSocket:
		return s.Boundary == BoundaryUpstreamRequest || s.Boundary == BoundaryUpstreamFrame
	case TransportMCPStdio, TransportMCPHTTPListener, TransportMCPHTTPUpstream, TransportMCPWS:
		return s.Boundary == BoundaryUpstreamRequest || s.Boundary == BoundaryToolDispatch
	case TransportHook:
		return s.Boundary == BoundaryHookDecision
	default:
		return false
	}
}

// Registry is an immutable set of explicit classification-site obligations.
// There is deliberately no implicit catch-all ID or default complete registry.
type Registry struct {
	sites map[SiteID]Site
	order []SiteID
}

func NewRegistry(sites []Site) (*Registry, error) {
	if len(sites) == 0 {
		return nil, fmt.Errorf("classification registry is empty")
	}
	r := &Registry{sites: make(map[SiteID]Site, len(sites))}
	for _, site := range sites {
		if err := site.Validate(); err != nil {
			return nil, fmt.Errorf("classification registry: %w", err)
		}
		if _, exists := r.sites[site.ID]; exists {
			return nil, fmt.Errorf("duplicate classification site ID")
		}
		r.sites[site.ID] = site
		r.order = append(r.order, site.ID)
	}
	slices.Sort(r.order)
	return r, nil
}

func (r *Registry) Lookup(id SiteID) (Site, bool) {
	if r == nil {
		return Site{}, false
	}
	site, ok := r.sites[id]
	return site, ok
}

// All returns a deterministic defensive copy. Editing it cannot change a gate's
// classification-site contract or a reader's coverage obligations.
func (r *Registry) All() []Site {
	if r == nil {
		return nil
	}
	out := make([]Site, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.sites[id])
	}
	return out
}

// validIdentifier admits bounded symbolic IDs, never URLs, headers, or content.
// Producers still own ensuring that an ID is a configured/reference identifier;
// syntax cannot prove that a caller did not put secret material into a string.
func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == ':' {
			continue
		}
		return false
	}
	return true
}
