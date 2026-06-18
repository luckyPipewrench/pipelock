// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"net"
	"net/url"
	"strings"
)

// Destination trust classes surfaced on demo decisions. They make the demo's
// boundary honest: the model PROVIDER is the agent's own reasoning channel,
// declared trusted infrastructure and NOT treated as an exfil destination; every
// visitor-controllable destination is untrusted, where Pipelock enforces (DLP
// blocks secret exfil).
const (
	DestinationClassTrustedModel = "trusted_model"
	DestinationClassUntrusted    = "untrusted"
)

// TrustBoundaryStatement is the one-line honest framing surfaced in a bundle so
// the demo never overclaims: it does not pretend to scan the model provider, and
// it states plainly where enforcement applies.
const TrustBoundaryStatement = "The model provider is trusted infrastructure for this demo (the agent's own reasoning channel) and is not treated as an exfiltration destination. Every visitor-controllable destination is untrusted and enforced: Pipelock blocks secret exfil there."

// classifyDestination labels a decision target as trusted_model (the model
// provider) or untrusted (everything else). An empty modelHost -- the
// deterministic agent path, where there is no model provider -- classifies
// everything untrusted.
//
// SOUNDNESS (why classifying by HOST is safe here, not the bypass Codex warned
// about): the lab tools are blocked from ever reaching the model host before any
// egress (llmagent.ToolRuntimeConfig.BlockedHosts, enforced by toolTargetBlocked
// with canonicalized host matching on both fetch_url and post_data). So a proxy
// receipt whose target is the model host can ONLY have originated from the model
// transport -- a visitor-driven tool cannot reach it and therefore cannot POST
// secret-bearing content to the provider host to inherit the trusted label. The
// tool-boundary block IS the client/route scoping; the host label only reads it
// back. If that block were ever weakened, this classification would no longer be
// sound -- they must change together.
func classifyDestination(target, modelHost string) string {
	if modelHost == "" {
		return DestinationClassUntrusted
	}
	if hostFromTarget(target) == normalizeDestHost(modelHost) {
		return DestinationClassTrustedModel
	}
	return DestinationClassUntrusted
}

// hostFromTarget extracts a comparable hostname from a receipt target, which may
// be a full URL ("https://host:443/path"), an authority ("host:443"), or a bare
// host. It returns "" when no host can be parsed.
func hostFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return normalizeDestHost(u.Hostname())
		}
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		return normalizeDestHost(host)
	}
	return normalizeDestHost(target)
}

// normalizeDestHost canonicalizes a hostname for comparison: lowercased, trailing
// FQDN dot removed, IPv6 brackets stripped.
func normalizeDestHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return strings.ToLower(h)
}
