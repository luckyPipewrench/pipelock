// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"net/http"
	"strings"

	"github.com/dunglas/httpsfv"
)

// pipelockMemberPrefix is the prefix that marks a Signature /
// Signature-Input dictionary member as belonging to pipelock. Any member
// whose name starts with this prefix (e.g. "pipelock1", "pipelock2") is
// removed on strip and replaced on redirect refresh.
const pipelockMemberPrefix = "pipelock"

// InjectHTTP serializes the envelope and sets it as the Pipelock-Mediation
// HTTP header value.
func InjectHTTP(h http.Header, env Envelope) error {
	val, err := env.Serialize()
	if err != nil {
		return err
	}
	h.Set(HeaderName, val)
	return nil
}

// StripInbound removes any inbound Pipelock-Mediation header and any
// pipelock-labeled Signature / Signature-Input dictionary members. This
// prevents header injection where an agent or upstream proxy forges
// mediation metadata or pre-populates a pipelock* signature slot that
// would otherwise survive into the outbound request.
//
// TODO(v2.2.x): inbound RFC 9421 verification + replay cache. Today we
// only strip on the assumption that any inbound pipelock* signature is
// either forged or stale. Future work will verify upstream pipelock
// signatures against a trust list before deciding to strip vs accept.
func StripInbound(h http.Header) {
	h.Del(HeaderName)
	stripPipelockSignatureMembers(h, "Signature-Input")
	stripPipelockSignatureMembers(h, "Signature")
}

// stripPipelockSignatureMembers removes dictionary members from a header
// whose key starts with pipelockMemberPrefix. It parses all header values
// as a single RFC 8941 Structured Fields dictionary so that quoted
// parameter values containing commas and multi-line dict values are
// handled correctly.
//
// An earlier implementation used strings.Split(val, ",") which treats
// commas inside quoted parameter values as top-level member separators.
// That corrupted surviving non-pipelock members and left dictionary
// residue that no longer parsed as a Structured Field — a sanitisation
// bypass vector for attacker-crafted inbound signature headers.
func stripPipelockSignatureMembers(h http.Header, headerName string) {
	values := h.Values(headerName)
	if len(values) == 0 {
		return
	}

	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		// The inbound header is not a well-formed RFC 8941 dictionary.
		// Earlier behaviour failed closed by dropping the entire header,
		// which broke legitimate (but httpsfv-picky) signatures like
		// Cloudflare Web Bot Auth sig1 members whose values were not
		// strict-base64. That turned pipelock into a signature-stripping
		// middlebox for any upstream auth scheme it could not re-parse.
		//
		// Surgical fail-closed: only drop the header if the raw bytes
		// contain the pipelock member prefix (indicating a plausible
		// forged or broken pipelock member we must not let through).
		// Otherwise, leave the header untouched — pipelock's scrubbing
		// target is pipelock-tagged members, not malformed third-party
		// signatures.
		if containsPipelockMember(values) {
			h.Del(headerName)
		}
		return
	}

	// Collect doomed member names first so we don't mutate while iterating.
	// httpsfv.Dictionary preserves insertion order via Names(), which the
	// re-serialize path below relies on for deterministic output.
	var doomed []string
	for _, name := range dict.Names() {
		if strings.HasPrefix(name, pipelockMemberPrefix) {
			doomed = append(doomed, name)
		}
	}
	if len(doomed) == 0 {
		// Nothing pipelock to strip. Leave the header values untouched —
		// re-serializing would still produce valid output, but preserving
		// the bytes avoids unnecessary churn on unrelated dictionaries.
		return
	}
	for _, name := range doomed {
		dict.Del(name)
	}

	h.Del(headerName)
	if len(dict.Names()) == 0 {
		return
	}
	out, err := httpsfv.Marshal(dict)
	if err != nil {
		// Re-serializing a dictionary we just parsed should never fail.
		// If it does, fail closed — drop the header rather than emit a
		// partially-formed residue.
		return
	}
	h.Set(headerName, out)
}

// containsPipelockMember returns true when any raw header value contains
// the byte sequence "pipelock" (case-insensitive). Used only when strict
// RFC 8941 parsing has already failed; at that point we cannot reason
// about dictionary member boundaries, so any appearance of the pipelock
// namespace is treated as sufficient reason to drop the malformed
// header. An earlier implementation required a start-of-value or
// comma-preceded match, but RFC 8941 permits OWS (spaces, tabs) and
// separator variants between members that the pattern-based checks
// missed — letting Pipelock-tagged bytes survive a parse failure. A
// case-insensitive substring check is strictly fail-closed and matches
// the same surface (any pipelock-prefixed member) the httpsfv path
// catches on well-formed input.
func containsPipelockMember(values []string) bool {
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), pipelockMemberPrefix) {
			return true
		}
	}
	return false
}

// InjectMCP adds the envelope to an MCP _meta map.
func InjectMCP(meta map[string]any, env Envelope) {
	meta[MCPMetaKey] = env.ToMCPMeta()
}

// StripInboundMCP removes any existing mediation key from an MCP _meta map.
func StripInboundMCP(meta map[string]any) {
	delete(meta, MCPMetaKey)
}
