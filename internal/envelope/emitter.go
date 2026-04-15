// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync/atomic"
	"time"
)

// Emitter builds and injects mediation envelopes. Nil-safe: all methods
// are no-ops on a nil Emitter, matching the receipt.Emitter pattern.
type Emitter struct {
	configHash atomic.Value // stores string
}

// EmitterConfig holds the configuration for creating an Emitter.
type EmitterConfig struct {
	ConfigHash string
}

// NewEmitter creates an envelope emitter.
func NewEmitter(cfg EmitterConfig) *Emitter {
	e := &Emitter{}
	e.configHash.Store(cfg.ConfigHash)
	return e
}

// UpdateConfigHash atomically updates the policy hash used in envelopes.
// Called on hot-reload.
func (e *Emitter) UpdateConfigHash(hash string) {
	if e == nil {
		return
	}
	e.configHash.Store(hash)
}

// BuildOpts holds per-request context for building an envelope.
type BuildOpts struct {
	ActionID       string
	Action         string
	Verdict        string
	SideEffect     string
	Actor          string
	ActorAuth      ActorAuth
	SessionTaint   string
	TaskID         string
	AuthorityKind  string
	AuthorityRef   string
	RequiresReauth bool

	// PolicyHash is the 16-byte canonical policy fingerprint for the
	// effective config handling this request. When non-empty it wins
	// over the emitter's fallback hash, so a per-agent handler can
	// stamp its own canonical ph without contending with the global
	// reload-time atomic. Callers produce this via PolicyHashFromHex
	// on the output of (*config.Config).CanonicalPolicyHash() for the
	// resolved per-request config. When empty, Build falls back to
	// the emitter's last UpdateConfigHash value — intended for
	// transports that do not yet thread per-agent config through.
	PolicyHash []byte
}

// Build creates an Envelope from the scan decision context.
// Returns a zero Envelope if the emitter is nil.
func (e *Emitter) Build(opts BuildOpts) Envelope {
	if e == nil {
		return Envelope{}
	}

	var hash []byte
	if len(opts.PolicyHash) > 0 {
		hash = opts.PolicyHash
	} else {
		hash = policyHashTruncated(configHashString(e.configHash.Load()))
	}

	return Envelope{
		Version:        1,
		Action:         opts.Action,
		Verdict:        opts.Verdict,
		SideEffect:     opts.SideEffect,
		Actor:          opts.Actor,
		ActorAuth:      opts.ActorAuth,
		PolicyHash:     hash,
		ReceiptID:      opts.ActionID,
		Timestamp:      time.Now().UTC().Unix(),
		SessionTaint:   opts.SessionTaint,
		TaskID:         opts.TaskID,
		AuthorityKind:  opts.AuthorityKind,
		AuthorityRef:   opts.AuthorityRef,
		RequiresReauth: opts.RequiresReauth,
	}
}

// InjectHTTPEnvelope builds an envelope and injects it as an HTTP header.
// No-op if the emitter is nil.
func (e *Emitter) InjectHTTPEnvelope(h http.Header, opts BuildOpts) error {
	if e == nil {
		return nil
	}
	env := e.Build(opts)
	return InjectHTTP(h, env)
}

// InjectMCPEnvelope builds an envelope and injects it into an MCP _meta map.
// No-op if the emitter is nil.
func (e *Emitter) InjectMCPEnvelope(meta map[string]any, opts BuildOpts) {
	if e == nil {
		return
	}
	env := e.Build(opts)
	InjectMCP(meta, env)
}

// PolicyHashFromHex is the exported form of policyHashTruncated. Callers
// hand it the 64-character hex string returned by
// (*config.Config).CanonicalPolicyHash() (or the legacy raw Hash()) and
// get back the 16-byte wire form used as the Pipelock-Mediation ph key.
// Use this at transport inject sites to stamp the per-agent effective
// canonical hash via BuildOpts.PolicyHash.
func PolicyHashFromHex(hash string) []byte {
	return policyHashTruncated(hash)
}

// policyHashTruncated returns the first 16 bytes of the config's policy hash.
// cfg.Hash() and cfg.CanonicalPolicyHash() both return hex-encoded SHA-256
// digests, so we decode and truncate rather than hashing again. Non-hex
// input (e.g. the legacy "sha256:..." prefix) falls through to a SHA-256
// of the string itself so the output is still 16 bytes.
func policyHashTruncated(hash string) []byte {
	if hash == "" {
		return make([]byte, 16)
	}
	decoded, err := hex.DecodeString(hash)
	if err != nil {
		// Not valid hex (e.g. prefixed "sha256:..."). Hash and truncate.
		sum := sha256.Sum256([]byte(hash))
		return sum[:16]
	}
	if len(decoded) >= 16 {
		return decoded[:16]
	}
	// Short hash -- pad to 16 bytes.
	out := make([]byte, 16)
	copy(out, decoded)
	return out
}

func configHashString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
