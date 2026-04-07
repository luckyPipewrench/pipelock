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

	// ActorAuthSelfDeclared means the actor name is unknown or from the
	// fallback path. Attacker-controllable. Informational only.
	ActorAuthSelfDeclared ActorAuth = "self-declared"
)

// Envelope is the mediation metadata attached to proxied requests.
type Envelope struct {
	Version    int
	Action     string
	Verdict    string
	SideEffect string
	Actor      string
	ActorAuth  ActorAuth
	PolicyHash []byte // First 16 bytes of SHA-256 of the policy config.
	ReceiptID  string // UUIDv7 receipt ID for correlation.
	Timestamp  int64  // Unix timestamp (seconds).
}

// Serialize encodes the envelope as an RFC 8941 Structured Fields Dictionary
// string suitable for the Pipelock-Mediation HTTP header value.
func (e Envelope) Serialize() (string, error) {
	dict := httpsfv.NewDictionary()

	dict.Add("v", httpsfv.NewItem(int64(e.Version)))
	dict.Add("act", httpsfv.NewItem(e.Action))
	dict.Add("vd", httpsfv.NewItem(e.Verdict))
	dict.Add("se", httpsfv.NewItem(e.SideEffect))
	dict.Add("actor", httpsfv.NewItem(e.Actor))
	dict.Add("aa", httpsfv.NewItem(string(e.ActorAuth)))
	dict.Add("ph", httpsfv.NewItem(e.PolicyHash))
	dict.Add("rid", httpsfv.NewItem(e.ReceiptID))
	dict.Add("ts", httpsfv.NewItem(e.Timestamp))

	return httpsfv.Marshal(dict)
}

// Parse decodes an RFC 8941 Dictionary string back into an Envelope.
func Parse(s string) (Envelope, error) {
	dict, err := httpsfv.UnmarshalDictionary([]string{s})
	if err != nil {
		return Envelope{}, fmt.Errorf("parsing dictionary: %w", err)
	}

	var env Envelope

	if m, ok := dict.Get("v"); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(int64); ok {
				env.Version = int(v)
			}
		}
	}
	if m, ok := dict.Get("act"); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.Action = v
			}
		}
	}
	if m, ok := dict.Get("vd"); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.Verdict = v
			}
		}
	}
	if m, ok := dict.Get("se"); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.SideEffect = v
			}
		}
	}
	if m, ok := dict.Get("actor"); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.Actor = v
			}
		}
	}
	if m, ok := dict.Get("aa"); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.ActorAuth = ActorAuth(v)
			}
		}
	}
	if m, ok := dict.Get("ph"); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.([]byte); ok {
				env.PolicyHash = v
			}
		}
	}
	if m, ok := dict.Get("rid"); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(string); ok {
				env.ReceiptID = v
			}
		}
	}
	if m, ok := dict.Get("ts"); ok {
		if item, ok := m.(httpsfv.Item); ok {
			if v, ok := item.Value.(int64); ok {
				env.Timestamp = v
			}
		}
	}

	return env, nil
}

// ToMCPMeta returns the envelope as a map for MCP _meta injection.
func (e Envelope) ToMCPMeta() map[string]any {
	return map[string]any{
		"v":     e.Version,
		"act":   e.Action,
		"vd":    e.Verdict,
		"se":    e.SideEffect,
		"actor": e.Actor,
		"aa":    string(e.ActorAuth),
		"ph":    "sha256-128:" + base64.StdEncoding.EncodeToString(e.PolicyHash),
		"rid":   e.ReceiptID,
		"ts":    e.Timestamp,
	}
}
