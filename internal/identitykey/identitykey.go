// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package identitykey centralizes stable per-actor key construction for
// stateful proxy detectors.
package identitykey

import "github.com/luckyPipewrench/pipelock/internal/envelope"

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
