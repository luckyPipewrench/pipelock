// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync/atomic"
)

// CanonicalPolicyHash returns a stable SHA-256 digest (hex-encoded) of the
// policy-semantic subset of the config. Unlike Hash(), which digests the
// raw on-disk YAML bytes and so drifts on whitespace or comment changes,
// CanonicalPolicyHash is invariant under anything that does not change
// effective enforcement:
//
//   - Whitespace and indentation changes
//   - YAML comments
//   - Reordering top-level sections
//   - Logging, telemetry, Sentry, emit destinations, flight recorder paths,
//     license metadata, and the envelope signing key path
//
// It IS sensitive to anything that changes enforcement:
//
//   - mode, enforce, explain_blocks
//   - DLP patterns, MCP tool policy rules, chain detection rules
//     (order-preserving — rule order is first-match-wins semantics)
//   - scanner thresholds, action verdicts, allowlists/blocklists
//   - kill switch sources, adaptive enforcement, taint, rules bundle
//   - transport policy knobs under fetch_proxy / forward_proxy /
//     websocket_proxy / reverse_proxy (Blocklist, entropy thresholds,
//     SNIVerification, rate limits, RedirectWebSocketHosts). Listen
//     addresses sit under those same structs so they also flip the
//     hash, which is the correct fail-forward trade: false positives
//     on cosmetic transport changes are less bad than missing a real
//     policy change.
//
// The output is the full 64-character hex (32-byte) SHA-256 of a canonicalised
// JSON encoding of the scanner-relevant config view. Callers that need the
// shortened wire form (ph dictionary key) hand this string to the envelope
// emitter, which decodes the hex and truncates to 16 bytes. Both
// computeCanonicalPolicyHash and the cached CanonicalPolicyHash wrapper
// return the full hex digest, not a truncated prefix.
//
// Per-effective-config: callers pass the resolved *Config for the specific
// agent handling the request, not the global one. Per-agent profiles
// produce distinct canonical hashes; the global config's canonical hash is
// what requests without an agent binding see.
//
// Caching: the hash is memoized on the *Config value via an unexported
// atomic.Value. First call computes and stores; subsequent calls return
// the cached hex string. This is safe because Config instances are
// treated as immutable after Load() — documented invariant. Mutating a
// Config after a canonical hash has been computed will silently return
// a stale hash. Tests must use fresh Config values for sensitivity.
func (c *Config) CanonicalPolicyHash() string {
	if cached := c.canonicalHashCache.Load(); cached != nil {
		if s, ok := cached.(string); ok {
			return s
		}
	}

	h := c.computeCanonicalPolicyHash()
	c.canonicalHashCache.Store(h)
	return h
}

// computeCanonicalPolicyHash is CanonicalPolicyHash without the cache.
// Exported only through the cached wrapper; kept separate so tests can
// exercise the determinism guarantees on fresh Config values.
func (c *Config) computeCanonicalPolicyHash() string {
	view := c.policySemanticView()
	data, err := json.Marshal(view)
	if err != nil {
		// json.Marshal of a Config value only fails on programming errors
		// (channels, functions, cycles). Fall back to the raw byte hash
		// so the proxy stays up. Stale / non-canonical ph is a soft
		// regression; a panicked proxy is not.
		return c.Hash()
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// policySemanticView returns a shallow copy of Config with noise fields
// zeroed. The resulting value, when JSON-marshalled, is the canonical
// policy-semantic projection of the config.
//
// A field is noise when its value does not change what pipelock would
// decide about a scanned request — listen addresses, log destinations,
// telemetry endpoints, flight recorder paths, Sentry config, license
// metadata, and the envelope signing key path (that changes how we sign
// but not WHAT we scan, and must never flow into an emitted ph value).
//
// Agents are zeroed in the global view because per-agent profiles are
// hashed through the agent's own resolved *Config; mixing them into the
// global hash would cause a global hash collision whenever an agent
// profile changed.
//
// Behavioral slice order is preserved by shallow copy (DLP rules, MCP
// tool policy rules, chain detection rules, suppress entries). Only
// set-like string slices with no semantic order (api_allowlist, internal
// SSRF block, trusted_domains) are sorted into canonical order.
func (c *Config) policySemanticView() Config {
	view := *c

	// Transport structs (FetchProxy, ForwardProxy, WebSocketProxy,
	// ReverseProxy) stay in the canonical view because they carry
	// enforcement-relevant fields: Monitoring.Blocklist, entropy
	// thresholds, rate limits, ForwardProxy.SNIVerification,
	// MaxTunnelSeconds, RedirectWebSocketHosts — all of which change
	// what pipelock would decide about a scanned request. A blanket
	// struct-zero would drop those policy knobs and leave ph
	// insensitive to real policy changes, breaking the admission-grade
	// contract.
	//
	// Listen addresses live under those structs. Including them in
	// the hash means `fetch_proxy.listen: :8888 → :8889` shifts ph,
	// even though no enforcement changed. That is the correct
	// trade: false positives on cosmetic transport changes are the
	// less-bad failure mode vs missing a real policy change.
	view.MetricsListen = ""

	// Telemetry and operational outputs — emit destinations, log
	// formatting, Sentry DSN, flight recorder path. None of these
	// affect detection decisions; they affect where observations go.
	view.Logging = LoggingConfig{}
	view.Sentry = SentryConfig{}
	view.Emit = EmitConfig{}
	view.FlightRecorder = FlightRecorder{}

	// License metadata — determines whether a tier feature is available,
	// but the effective per-agent config that the request-time path
	// resolves to already reflects gating outcomes (e.g. agent profile
	// not applied when the agents feature is unlicensed). Including
	// the raw license bytes here would produce different ph values for
	// identical effective policies across license refreshes.
	view.LicenseKey = ""
	view.LicenseFile = ""
	view.LicensePublicKey = ""
	view.LicenseExpiresAt = 0

	// Envelope signing key path — infrastructure, not policy. The key
	// material itself is never read here (we only hold a path), but
	// including the path would cause ph to shift whenever ops rotates
	// the file location without changing any detection semantics.
	// sign, key_id, signed_components, created_skew_seconds, and
	// max_body_bytes DO affect the envelope contract and stay in view.
	view.MediationEnvelope.SigningKeyPath = ""

	// Agents map — handled via per-agent resolved configs. See the
	// CanonicalPolicyHash doc comment.
	view.Agents = nil

	// The unexported rawBytes and canonicalHashCache fields are skipped
	// by encoding/json automatically because they are unexported. No
	// explicit handling needed.

	// Set-like string slices: canonicalise to sorted order so two
	// configs that list the same domains in different order hash equal.
	view.APIAllowlist = sortedCopy(view.APIAllowlist)
	view.Internal = sortedCopy(view.Internal)
	view.TrustedDomains = sortedCopy(view.TrustedDomains)

	return view
}

// sortedCopy returns a sorted copy of s. Nil in, nil out so that an
// omitted-slice field and an empty-slice field hash identically.
func sortedCopy(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

// canonicalHashCacheHolder is the unexported field type added to Config
// for atomic memoisation. It is declared here so the Config struct only
// needs a single field addition and so the canonical hash machinery is
// self-contained in this file.
type canonicalHashCacheHolder = atomic.Value
