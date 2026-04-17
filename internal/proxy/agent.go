// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/edition"
)

// agentAnonymous is the fallback agent name when no header/query/context
// override identifies the caller. Used by proxy handlers for display.
// Agent resolution logic lives in internal/edition/.
const agentAnonymous = "anonymous"

// AgentHeader re-exports the canonical agent header from edition.
// Used by proxy tests and any proxy-internal code that needs it.
const AgentHeader = edition.AgentHeader

// agentQueryParam is the URL query parameter pipelock uses as a
// self-declared agent identity hint. Agent resolution in edition.Agent
// reads it alongside AgentHeader.
const agentQueryParam = "agent"

// forwardedClientHeaders are HTTP headers that allow a caller to
// assert the original client IP or routing path downstream. When
// pipelock acts as a forward proxy or TLS interception middlebox,
// pass-through of these headers lets a malicious caller poison
// destination log attribution, geo checks, abuse rate-limiters, and
// any auth heuristic that keys off "origin". Pipelock has its own
// verified client_ip available; it does not need attacker-supplied
// hints and must not forward them blindly. Stripping matches what
// production forward proxies typically do when they do NOT intend to
// re-author the headers authoritatively.
var forwardedClientHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"Forwarded",
	"Via",
}

// stripInternalIdentity removes both the X-Pipelock-Agent header and
// the ?agent= query parameter from an outbound request so
// attacker-supplied identity hints cannot bleed through to downstream
// services. It also strips forwarded client-IP assertion headers
// (X-Forwarded-For, X-Real-IP, Forwarded, Via, and the related
// X-Forwarded-* family) because pipelock knows the verified client_ip
// and must not pass an attacker-supplied lie through to the backend.
//
// Without these strips, round-2 of the pre-tag gate showed:
//   - caller sending X-Pipelock-Agent: evil-actor lands that header
//     on the destination despite bind_default_agent_identity;
//   - caller sending X-Forwarded-For: 1.2.3.4 poisons the destination's
//     `origin` attribution (httpbin reported "1.2.3.4, <real-ip>").
func stripInternalIdentity(r *http.Request) {
	if r == nil {
		return
	}
	r.Header.Del(AgentHeader)
	for _, h := range forwardedClientHeaders {
		r.Header.Del(h)
	}
	if r.URL == nil {
		return
	}
	q := r.URL.Query()
	if !q.Has(agentQueryParam) {
		return
	}
	q.Del(agentQueryParam)
	r.URL.RawQuery = q.Encode()
}
