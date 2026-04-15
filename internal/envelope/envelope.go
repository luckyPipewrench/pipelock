// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package envelope defines the Pipelock mediation envelope: the compact
// per-request metadata record that travels with every proxied request as an
// RFC 8941 Structured Fields Dictionary in the Pipelock-Mediation HTTP header,
// and as a map under the com.pipelock/mediation key in MCP _meta.
package envelope

import (
	"encoding/base64"
	"fmt"

	"github.com/dunglas/httpsfv"
)

// HeaderName is the HTTP header carrying the mediation envelope.
const HeaderName = "Pipelock-Mediation"

// MCPMetaKey is the _meta key for MCP envelope injection.
const MCPMetaKey = "com.pipelock/mediation"

// ActorAuth classifies the trustworthiness of the actor field.
type ActorAuth string

const (
	// ActorAuthBound means the actor identity was set by infrastructure
	// (per-agent listener binding). Spoof-proof.
	ActorAuthBound ActorAuth = "bound"

	// ActorAuthMatched means the actor name matches a configured agent profile
	// but was self-declared via header or query param.
	ActorAuthMatched ActorAuth = "matched"

	// ActorAuthConfigDefault means the actor identity was resolved from the
	// config default_agent_identity field. Operator-configured, not agent-declared.
	ActorAuthConfigDefault ActorAuth = "config-default"

	// ActorAuthSelfDeclared means the actor name is unknown or from the
	// fallback path. Attacker-controllable. Informational only.
	ActorAuthSelfDeclared ActorAuth = "self-declared"
)

// Envelope is the mediation metadata attached to proxied requests.
type Envelope struct {
	Version        int
	Action         string
	Verdict        string
	SideEffect     string
	Actor          string
	ActorAuth      ActorAuth
	PolicyHash     []byte // First 16 bytes of SHA-256 of the policy config.
	ReceiptID      string // UUIDv7 receipt ID for correlation.
	Timestamp      int64  // Unix timestamp (seconds).
	SessionTaint   string
	TaskID         string
	AuthorityKind  string
	AuthorityRef   string
	RequiresReauth bool

	// Hop is the redirect-refresh counter. Zero (the default, omitted
	// from the serialized dictionary) means "original request, no
	// redirect refresh yet." Each redirect refresh increments Hop by 1
	// so a downstream verifier can distinguish the original envelope
	// from one rebuilt by pipelock's CheckRedirect path.
	Hop int
}

// Serialize encodes the envelope as an RFC 8941 Structured Fields Dictionary
// string suitable for the Pipelock-Mediation HTTP header value.
// Wire keys for the RFC 8941 Dictionary encoding.
const (
	keyVersion    = "v"
	keyAction     = "act"
	keyVerdict    = "vd"
	keySideEffect = "se"
	keyActor      = "actor"
	keyActorAuth  = "aa"
	keyPolicyHash = "ph"
	keyReceiptID  = "rid"
	keyTimestamp  = "ts"
	keyTaint      = "taint"
	keyTaskID     = "task"
	keyAuthority  = "auth"
	keyAuthorityR = "authr"
	keyReauth     = "reauth"
	keyHop        = "hop"
)

func (e Envelope) Serialize() (string, error) {
	dict := httpsfv.NewDictionary()

	dict.Add(keyVersion, httpsfv.NewItem(int64(e.Version)))
	dict.Add(keyAction, httpsfv.NewItem(e.Action))
	dict.Add(keyVerdict, httpsfv.NewItem(e.Verdict))
	dict.Add(keySideEffect, httpsfv.NewItem(e.SideEffect))
	dict.Add(keyActor, httpsfv.NewItem(e.Actor))
	dict.Add(keyActorAuth, httpsfv.NewItem(string(e.ActorAuth)))
	dict.Add(keyPolicyHash, httpsfv.NewItem(e.PolicyHash))
	dict.Add(keyReceiptID, httpsfv.NewItem(e.ReceiptID))
	dict.Add(keyTimestamp, httpsfv.NewItem(e.Timestamp))
	if e.SessionTaint != "" {
		dict.Add(keyTaint, httpsfv.NewItem(e.SessionTaint))
	}
	if e.TaskID != "" {
		dict.Add(keyTaskID, httpsfv.NewItem(e.TaskID))
	}
	if e.AuthorityKind != "" {
		dict.Add(keyAuthority, httpsfv.NewItem(e.AuthorityKind))
	}
	if e.AuthorityRef != "" {
		dict.Add(keyAuthorityR, httpsfv.NewItem(e.AuthorityRef))
	}
	if e.RequiresReauth {
		dict.Add(keyReauth, httpsfv.NewItem(true))
	}
	// Hop is omitted from the wire when zero so the common case (no
	// redirect refresh) does not spend bytes declaring the default.
	if e.Hop > 0 {
		dict.Add(keyHop, httpsfv.NewItem(int64(e.Hop)))
	}

	return httpsfv.Marshal(dict)
}

// Parse decodes an RFC 8941 Dictionary string back into an Envelope.
func Parse(s string) (Envelope, error) {
	dict, err := httpsfv.UnmarshalDictionary([]string{s})
	if err != nil {
		return Envelope{}, fmt.Errorf("parsing dictionary: %w", err)
	}

	var env Envelope

	if m, ok := dict.Get(keyVersion); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(int64); ok {
				env.Version = int(v)
			}
		}
	}
	if m, ok := dict.Get(keyAction); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.Action = v
			}
		}
	}
	if m, ok := dict.Get(keyVerdict); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.Verdict = v
			}
		}
	}
	if m, ok := dict.Get(keySideEffect); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.SideEffect = v
			}
		}
	}
	if m, ok := dict.Get(keyActor); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.Actor = v
			}
		}
	}
	if m, ok := dict.Get(keyActorAuth); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.ActorAuth = ActorAuth(v)
			}
		}
	}
	if m, ok := dict.Get(keyPolicyHash); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.([]byte); ok {
				env.PolicyHash = v
			}
		}
	}
	if m, ok := dict.Get(keyReceiptID); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.ReceiptID = v
			}
		}
	}
	if m, ok := dict.Get(keyTimestamp); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(int64); ok {
				env.Timestamp = v
			}
		}
	}
	if m, ok := dict.Get(keyTaint); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.SessionTaint = v
			}
		}
	}
	if m, ok := dict.Get(keyTaskID); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.TaskID = v
			}
		}
	}
	if m, ok := dict.Get(keyAuthority); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.AuthorityKind = v
			}
		}
	}
	if m, ok := dict.Get(keyAuthorityR); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.AuthorityRef = v
			}
		}
	}
	if m, ok := dict.Get(keyReauth); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(bool); ok {
				env.RequiresReauth = v
			}
		}
	}
	if m, ok := dict.Get(keyHop); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(int64); ok {
				if v < 0 {
					return Envelope{}, fmt.Errorf("invalid %q: must be >= 0, got %d", keyHop, v)
				}
				env.Hop = int(v)
			}
		}
	}

	// Reject envelopes missing required fields. A partial envelope
	// could pass through trust decisions with zero-value defaults,
	// silently accepted as if they were valid enum members.
	if env.Version == 0 {
		return Envelope{}, fmt.Errorf("missing required field %q", keyVersion)
	}
	if env.Action == "" {
		return Envelope{}, fmt.Errorf("missing required field %q", keyAction)
	}
	if env.Verdict == "" {
		return Envelope{}, fmt.Errorf("missing required field %q", keyVerdict)
	}
	if env.ReceiptID == "" {
		return Envelope{}, fmt.Errorf("missing required field %q", keyReceiptID)
	}
	if env.Timestamp == 0 {
		return Envelope{}, fmt.Errorf("missing required field %q", keyTimestamp)
	}

	// Validate ActorAuth against allowed values.
	switch env.ActorAuth {
	case ActorAuthBound, ActorAuthMatched, ActorAuthConfigDefault, ActorAuthSelfDeclared, "":
		// valid
	default:
		return Envelope{}, fmt.Errorf("unknown actor_auth value %q", env.ActorAuth)
	}

	return env, nil
}

// ToMCPMeta returns the envelope as a map for MCP _meta injection.
func (e Envelope) ToMCPMeta() map[string]any {
	meta := map[string]any{
		keyVersion:    e.Version,
		keyAction:     e.Action,
		keyVerdict:    e.Verdict,
		keySideEffect: e.SideEffect,
		keyActor:      e.Actor,
		keyActorAuth:  string(e.ActorAuth),
		keyPolicyHash: "sha256-128:" + base64.StdEncoding.EncodeToString(e.PolicyHash),
		keyReceiptID:  e.ReceiptID,
		keyTimestamp:  e.Timestamp,
	}
	if e.SessionTaint != "" {
		meta[keyTaint] = e.SessionTaint
	}
	if e.TaskID != "" {
		meta[keyTaskID] = e.TaskID
	}
	if e.AuthorityKind != "" {
		meta[keyAuthority] = e.AuthorityKind
	}
	if e.AuthorityRef != "" {
		meta[keyAuthorityR] = e.AuthorityRef
	}
	if e.RequiresReauth {
		meta[keyReauth] = true
	}
	if e.Hop > 0 {
		meta[keyHop] = e.Hop
	}
	return meta
}
