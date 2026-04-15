// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Emitter builds and injects mediation envelopes. Nil-safe: all methods
// are no-ops on a nil Emitter, matching the receipt.Emitter pattern.
//
// The Emitter's signer field is immutable after construction. Hot
// reload installs a fresh *Emitter via (*Proxy).reloadEnvelopeEmitter
// when either the config hash or the signing key material changes, so
// the runtime swap is a single atomic pointer store.
type Emitter struct {
	configHash atomic.Value // stores string
	signer     *Signer
}

// EmitterConfig holds the configuration for creating an Emitter.
type EmitterConfig struct {
	// ConfigHash is the hex-encoded canonical policy hash for the
	// global config at construction time. Transports that thread a
	// per-agent effective config through their inject call sites
	// pass PolicyHash in BuildOpts to override this default.
	ConfigHash string

	// Signer is the optional RFC 9421 HTTP Message Signature signer.
	// nil means "envelope signing disabled" — InjectAndSign still
	// sets the Pipelock-Mediation header, it just does not attach a
	// signature. When non-nil, the signer's Ed25519 key material is
	// held for the lifetime of this Emitter; swapping the key
	// requires installing a new Emitter.
	Signer *Signer
}

// NewEmitter creates an envelope emitter.
func NewEmitter(cfg EmitterConfig) *Emitter {
	e := &Emitter{signer: cfg.Signer}
	e.configHash.Store(cfg.ConfigHash)
	return e
}

// HasSigner reports whether this Emitter is producing RFC 9421
// signatures. Used by transport wiring (and tests) to decide whether
// a request context that is missing a body needs to buffer one for
// content-digest computation before calling InjectAndSign.
func (e *Emitter) HasSigner() bool {
	return e != nil && e.signer != nil
}

// Signer returns the Emitter's installed Signer, or nil if signing is
// disabled. Exported so the redirect-refresh path can sign the
// rebuilt request without re-plumbing the signer through additional
// call sites.
func (e *Emitter) Signer() *Signer {
	if e == nil {
		return nil
	}
	return e.signer
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
// No-op if the emitter is nil. This is the header-only call path used
// for pre-dispatch injection sites that do not yet have the full
// outbound *http.Request in hand (and so cannot sign). Call sites that
// have the final outbound request should prefer InjectAndSign instead,
// which also attaches the RFC 9421 signature when signing is enabled.
func (e *Emitter) InjectHTTPEnvelope(h http.Header, opts BuildOpts) error {
	if e == nil {
		return nil
	}
	env := e.Build(opts)
	return InjectHTTP(h, env)
}

// InjectAndSign injects the mediation envelope as the Pipelock-Mediation
// header on req AND, if the Emitter has an installed signer, attaches an
// RFC 9421 HTTP Message Signature over the per-request effective
// component list via pipelock1. body is the already-buffered request
// body, or nil for body-less requests. When signing is enabled and body
// is non-nil, the signer populates Content-Digest itself before signing.
//
// Errors from the envelope serialize step or the signer's SignRequest
// are returned to the caller. On error the request's existing headers
// may be partially mutated (Pipelock-Mediation set but signature not
// attached). Callers must fail closed on any non-nil return: the
// request is not safe to forward with a partially-attached pipelock
// signature slot.
//
// No-op and returns nil when called on a nil Emitter.
func (e *Emitter) InjectAndSign(req *http.Request, body []byte, opts BuildOpts) error {
	if e == nil {
		return nil
	}
	if req == nil {
		return fmt.Errorf("envelope emitter: nil *http.Request")
	}
	env := e.Build(opts)
	if err := InjectHTTP(req.Header, env); err != nil {
		return fmt.Errorf("envelope emitter: inject header: %w", err)
	}
	if e.signer == nil {
		return nil
	}
	if err := e.signer.SignRequest(req, body); err != nil {
		return fmt.Errorf("envelope emitter: sign request: %w", err)
	}
	return nil
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
