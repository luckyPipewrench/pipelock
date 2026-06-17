// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	SurfaceMCPStdio        = "mcp_stdio"
	SurfaceMCPHTTPUpstream = "mcp_http_upstream"
	SurfaceMCPHTTPListener = "mcp_http_listener"
	SurfaceMCPWS           = "mcp_ws"
	SurfaceForwardProxy    = "forward_proxy"
	SurfaceCONNECT         = "connect"
	SurfaceFetch           = "fetch"

	StatusSupported       = "supported"
	StatusNotYetSupported = "not_yet_supported"
)

// SurfaceSupport describes whether a transport can enforce per-action holds.
type SurfaceSupport struct {
	Surface          string
	SupportsDefer    bool
	Status           string
	RejectReason     string
	UnblockCondition string
}

var surfaceSupport = []SurfaceSupport{
	{
		Surface:       SurfaceMCPStdio,
		SupportsDefer: true,
		Status:        StatusSupported,
	},
	{
		Surface:       SurfaceMCPHTTPUpstream,
		SupportsDefer: true,
		Status:        StatusSupported,
	},
	{
		Surface:          SurfaceMCPHTTPListener,
		Status:           StatusNotYetSupported,
		RejectReason:     "reverse HTTP/SSE clients do not have a portable deferred-response and later-notification resume contract",
		UnblockCondition: "add a cooperative pending-response protocol with tested later delivery semantics",
	},
	{
		Surface:          SurfaceMCPWS,
		Status:           StatusNotYetSupported,
		RejectReason:     "ordered bidirectional streams need in-order buffering and backpressure before a held frame can resume without reordering",
		UnblockCondition: "add ordered hold queues with bounded backpressure and no-reorder parity tests",
	},
	{
		Surface:          SurfaceForwardProxy,
		Status:           StatusNotYetSupported,
		RejectReason:     "the client is blocked on one synchronous response and Pipelock has no later resume path",
		UnblockCondition: "use a cooperative asynchronous action protocol instead of a synchronous proxy response",
	},
	{
		Surface:          SurfaceCONNECT,
		Status:           StatusNotYetSupported,
		RejectReason:     "the client is blocked on one synchronous tunnel decision and Pipelock has no later resume path",
		UnblockCondition: "use a cooperative asynchronous action protocol instead of a synchronous proxy response",
	},
	{
		Surface:          SurfaceFetch,
		Status:           StatusNotYetSupported,
		RejectReason:     "the caller is blocked on one fetch response and Pipelock has no later resume path",
		UnblockCondition: "use a cooperative asynchronous action protocol instead of a synchronous fetch response",
	},
}

// LookupSurface returns the support record for surface. Unknown surfaces reject
// defer until they explicitly opt in.
func LookupSurface(surface string) SurfaceSupport {
	for _, support := range surfaceSupport {
		if support.Surface == surface {
			return support
		}
	}
	return SurfaceSupport{
		Surface:          surface,
		Status:           StatusNotYetSupported,
		RejectReason:     "surface is not registered for held-action resume",
		UnblockCondition: "register the surface with a tested withhold and resume path",
	}
}

// SupportedSurfaces returns a copy of the transport registry.
func SupportedSurfaces() []SurfaceSupport {
	out := make([]SurfaceSupport, len(surfaceSupport))
	copy(out, surfaceSupport)
	return out
}

// ValidateAction rejects defer on transports that cannot enforce it.
func ValidateAction(surface, action string) error {
	if action != config.ActionDefer {
		return nil
	}
	support := LookupSurface(surface)
	if support.SupportsDefer {
		return nil
	}
	return fmt.Errorf("defer is not yet supported on %s: %s", support.Surface, support.RejectReason)
}
