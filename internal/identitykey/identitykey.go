// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package identitykey centralizes stable per-actor key construction for
// stateful proxy detectors.
package identitykey

import (
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

var foldedBaselineKeyRe = regexp.MustCompile(`^ip(?:4-[0-9a-f]{8}|6-[0-9a-f]{32}|-[0-9a-f]*)$`)

// AnonymousAgent is the unattributed agent name. It lives here because both
// this package and internal/proxy must agree on it exactly: if the two ever
// drift, one side would namespace an identity the other collapses to the client
// bucket, which is precisely the agent-name partitioning bypass CEESafeKey
// exists to prevent.
const AnonymousAgent = "anonymous"

// CEEIdentity is the opaque owner of cross-request detection state. It can
// only be created from an identity classification, which keeps request
// supplied labels from becoming state partitions.
type CEEIdentity struct{ key string }

// NewCEEIdentity builds the CEE owner from the actual authentication grade at
// the classification boundary. Unknown and zero-value grades deliberately
// fold to the client bucket: treating an unclassified label as trusted would
// make a missing grade a partitioning bypass.
func NewCEEIdentity(agent, client string, auth envelope.ActorAuth) CEEIdentity {
	return CEEIdentity{key: CEESafeKey(agent, client, auth)}
}

// NewMCPCEEIdentity wraps a server-owned MCP session identifier. MCP sessions
// are minted by the proxy protocol, rather than being caller-supplied actor
// labels, so they do not pass through ActorAuth classification.
func NewMCPCEEIdentity(session string) CEEIdentity {
	return CEEIdentity{key: session}
}

// CEEStream is an opaque partition within one CEE identity. A partition is
// deliberately distinct from its owner: a JSON path, query-key stream, or
// path-position stream cannot substitute for an identity.
type CEEStream struct {
	owner CEEIdentity
	key   string
}

// Stream returns a partition of this identity's CEE state.
func (id CEEIdentity) Stream(partition string) CEEStream {
	return CEEStream{owner: id, key: id.key + partition}
}

// Key returns the classified key for ledger indexing and audit correlation.
// The returned string cannot be passed back into a CEE state API.
func (id CEEIdentity) Key() string { return id.key }

// Key returns the derived stream key for ledger indexing.
func (stream CEEStream) Key() string { return stream.key }

// Owner returns the classified identity that created this stream.
func (stream CEEStream) Owner() CEEIdentity { return stream.owner }

// scanAPIIdentityNamespace prefixes every Scan API CEE identity with a
// control byte (0x1F, ASCII unit separator) that the Scan API's own
// session_id validation rejects (only visible ASCII without whitespace is
// accepted) and that no other transport's caller-supplied identity component
// intentionally contains. This keeps a Scan API session's fragment/entropy
// state in a namespace that a proxy agent|client key or an MCP session key
// can never land in, even by coincidence, without relying on caller-chosen
// values to avoid collision.
const scanAPIIdentityNamespace = "scanapi\x1f"

// NewScanAPIIdentity builds the CEE owner for one Scan API session. callerKey
// is a server-derived identifier for the authenticated caller (for example a
// hash of the bearer token); it is folded in so two different callers can
// never share or poison each other's session state even if they choose the
// same session_id. sessionID is the caller-supplied session_id request field,
// already validated by the Scan API handler.
func NewScanAPIIdentity(callerKey string) CEEIdentity {
	return CEEIdentity{key: scanAPIIdentityNamespace + callerKey}
}

// CEECandidateIdentities returns both classifications that an administrative
// reset may need when its stored session record carries no authentication grade.
func CEECandidateIdentities(agent, client string) []CEEIdentity {
	bound := NewCEEIdentity(agent, client, envelope.ActorAuthBound)
	folded := NewCEEIdentity(agent, client, envelope.ActorAuthSelfDeclared)
	if bound == folded {
		return []CEEIdentity{bound}
	}
	return []CEEIdentity{bound, folded}
}

// ForAgentAndClient builds the shared agent/client key shape. Named agents are
// namespaced ahead of the client identity; unnamed or anonymous agents collapse
// to the client identity alone.
func ForAgentAndClient(agent, client string) string {
	if agent == "" || agent == AnonymousAgent {
		return client
	}
	return agent + "|" + client
}

// CEESafeAgent returns the agent component that is safe for stateful buckets
// which must resist request-supplied agent-name partitioning.
func CEESafeAgent(agent string, auth envelope.ActorAuth) string {
	switch auth {
	case envelope.ActorAuthBound, envelope.ActorAuthConfigDefault:
		return agent
	default:
		return ""
	}
}

// CEESafeKey builds the partition-resistant state key used by CEE and MCP DoW.
func CEESafeKey(agent, client string, auth envelope.ActorAuth) string {
	return ForAgentAndClient(CEESafeAgent(agent, auth), client)
}

// BaselineKeyForSessionKey derives the behavioral-baseline profile key from a
// classified HTTP session key. Named sessions retain their agent key. Folded
// IP sessions use the reserved ip4-/ip6- namespace so IPv6 is safe for
// baseline persistence and admin URL paths. Non-IP peer identifiers from an
// embedded listener use the reserved ip- namespace instead of colliding with a
// configured identity name.
func BaselineKeyForSessionKey(sessionKey string) string {
	if idx := strings.LastIndex(sessionKey, "|"); idx > 0 {
		// A named session key is "<agent>|<client address>". Confirm the tail
		// is an address before trusting the split: a non-IP peer identifier
		// containing the delimiter would otherwise be read as a named agent
		// and could share a profile with a configured agent of that name.
		if _, err := netip.ParseAddr(strings.Trim(sessionKey[idx+1:], "[]")); err == nil {
			return sessionKey[:idx]
		}
	}
	client := strings.Trim(strings.TrimSpace(sessionKey), "[]")
	if ip, err := netip.ParseAddr(client); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			return "ip4-" + hex.EncodeToString(ip.AsSlice())
		}
		return "ip6-" + hex.EncodeToString(ip.AsSlice())
	}
	return "ip-" + hex.EncodeToString([]byte(sessionKey))
}

// IsFoldedBaselineKey reports whether key is in the namespace reserved for a
// client-address-derived behavioral baseline. Configured agent names may not
// use this namespace, so a named identity cannot collide with a folded client.
func IsFoldedBaselineKey(key string) bool {
	return foldedBaselineKeyRe.MatchString(key)
}

// CEECandidateKeys returns every distinct CEE state key that CEESafeKey could
// have produced for this (agent, client) pair across all authentication grades.
//
// It exists for the operator reset/terminate path, which is keyed by a stored
// adaptive session key (agent|client) that does NOT carry the grade and cannot
// recover a per-listener Bound grade that lived only in request context.
// Re-deriving a single key there would silently miss whichever key the live
// path actually wrote: a self-declared or matched caller folds to the client
// alone, while a bound or config-default caller keeps the agent. Clearing every
// candidate through this one helper keeps reset and the live path on the same
// derivation (CEESafeKey), so reset can never target a key shape the live path
// would not have produced. The set is at most two entries: the namespaced
// "agent|client" and the folded "client"; an unnamed agent yields one.
func CEECandidateKeys(agent, client string) []string {
	keys := make([]string, 0, 2)
	seen := make(map[string]struct{}, 2)
	// ActorAuthBound represents the grades that keep the agent name;
	// ActorAuthSelfDeclared represents the grades that fold it to the client.
	for _, auth := range []envelope.ActorAuth{envelope.ActorAuthBound, envelope.ActorAuthSelfDeclared} {
		key := CEESafeKey(agent, client, auth)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}
