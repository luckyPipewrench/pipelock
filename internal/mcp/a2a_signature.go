// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jcs"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// CardSigOutcome is the result of evaluating an Agent Card's signatures.
type CardSigOutcome int

const (
	// SigOutcomeUnsigned means the card carried no signatures. The caller
	// applies require_signed_agent_cards policy.
	SigOutcomeUnsigned CardSigOutcome = iota
	// SigOutcomeVerified means at least one signature verified against a trusted
	// key scoped to the card's origin.
	SigOutcomeVerified
	// SigOutcomeFailed means the card claimed a signature but none verified
	// against a trusted, origin-scoped key, or the card structure was ambiguous.
	// This always fails closed.
	SigOutcomeFailed
)

// CardSignatureResult reports the verification outcome plus context for receipts.
type CardSignatureResult struct {
	Outcome CardSigOutcome
	KeyID   string // verifying key_id, set when Outcome == SigOutcomeVerified
	Reason  string // failure detail, set when Outcome == SigOutcomeFailed
}

const (
	// a2aSignaturesField is the Agent Card member excluded from the signed
	// preimage (RFC 8785 canonicalization of "card minus signatures").
	a2aSignaturesField = "signatures"

	// jwsAlgEdDSA is the only JWS "alg" pipelock will verify. Anything else —
	// "none", RS256, ES256, header-selected algorithms — is rejected. Trusted
	// keys are Ed25519, and the verifier never lets the card's header choose the
	// algorithm or key (algorithm-confusion defense).
	jwsAlgEdDSA = "EdDSA"

	// maxCardSignatures bounds how many signature entries are evaluated, so a
	// malicious card cannot force unbounded Ed25519 verifications. Real cards
	// carry one or two signatures.
	maxCardSignatures = 16

	// maxJSONNesting bounds recursion depth while skipping nested JSON during
	// signature-claim detection, so a deeply nested attacker payload returns an
	// error instead of overflowing the stack (cards are runtime input; a panic
	// would violate the never-panic-on-input rule). 512 is far deeper than any
	// real Agent Card.
	maxJSONNesting = 512
)

// trustedCardKey is a parsed, origin-scoped trusted signing key.
type trustedCardKey struct {
	keyID   string
	pub     ed25519.PublicKey
	origins map[string]struct{}
}

// jwsSignature is one entry of the Agent Card "signatures" array (RFC 7515 JWS
// flattened JSON, detached payload).
type jwsSignature struct {
	Protected string
	Signature string
}

type protectedHeader struct {
	Alg  string
	Kid  string
	B64  bool
	Crit []string
}

// CardSignatureVerificationActive reports whether signature verification should
// run: A2A scanning enabled and at least one trusted key configured.
func CardSignatureVerificationActive(cfg *config.A2AScanning) bool {
	return cfg != nil && cfg.Enabled && len(cfg.TrustedAgentCardKeys) > 0
}

// VerifyAgentCardSignatures evaluates the JWS signatures on a raw Agent Card
// against the configured trusted, origin-scoped keys. It is fail-closed: once a
// card claims a signature, every path other than a genuine trusted-and-valid
// signature returns SigOutcomeFailed.
func VerifyAgentCardSignatures(rawCard []byte, cardOrigin string, cfg *config.A2AScanning) CardSignatureResult {
	// Lenient top-level detection of a signature claim first. It tolerates
	// trailing bytes, so a card that claims a signature AND carries trailing
	// tokens is still recognized as signed here; the strict JCS parse below is
	// what rejects the ambiguity and fails closed.
	if !topLevelHasSignaturesField(rawCard) {
		return CardSignatureResult{Outcome: SigOutcomeUnsigned}
	}

	tree, err := jcs.Parse(rawCard)
	if err != nil {
		return CardSignatureResult{Outcome: SigOutcomeFailed, Reason: "a2a: ambiguous card structure: " + err.Error()}
	}
	top, ok := tree.(map[string]any)
	if !ok {
		return CardSignatureResult{Outcome: SigOutcomeFailed, Reason: "a2a: ambiguous card structure: card is not a JSON object"}
	}
	sigEntries, err := parseJWSSignatureEntries(top[a2aSignaturesField])
	if err != nil {
		return CardSignatureResult{Outcome: SigOutcomeFailed, Reason: "a2a: malformed signatures container"}
	}
	if len(sigEntries) == 0 {
		return CardSignatureResult{Outcome: SigOutcomeUnsigned}
	}

	// The card claims a signature. Compute the unambiguous JCS preimage (card
	// minus signatures).
	delete(top, a2aSignaturesField)
	preimage, err := jcs.Marshal(top)
	if err != nil {
		return CardSignatureResult{Outcome: SigOutcomeFailed, Reason: "a2a: ambiguous card structure: " + err.Error()}
	}

	keys := prepareTrustedCardKeys(cfg)
	origin := CardOriginFromURL(cardOrigin)

	limit := len(sigEntries)
	if limit > maxCardSignatures {
		limit = maxCardSignatures
	}
	for _, entry := range sigEntries[:limit] {
		if keyID, ok := verifyOneSignature(entry, preimage, origin, keys); ok {
			return CardSignatureResult{Outcome: SigOutcomeVerified, KeyID: keyID}
		}
	}
	return CardSignatureResult{
		Outcome: SigOutcomeFailed,
		Reason:  fmt.Sprintf("a2a: no trusted signature for origin %s", originForReason(origin)),
	}
}

// prepareTrustedCardKeys parses configured trusted keys into verification form.
// Invalid entries are skipped (config validation rejects them at load; this is
// defense in depth so a bad entry can never widen trust).
func prepareTrustedCardKeys(cfg *config.A2AScanning) []trustedCardKey {
	out := make([]trustedCardKey, 0, len(cfg.TrustedAgentCardKeys))
	for _, k := range cfg.TrustedAgentCardKeys {
		pub, err := signing.ParsePublicKey(k.PublicKey)
		if err != nil {
			continue
		}
		origins := make(map[string]struct{}, len(k.AllowedOrigins))
		for _, o := range k.AllowedOrigins {
			if norm := CardOriginFromURL(o); norm != "" {
				origins[norm] = struct{}{}
			}
		}
		out = append(out, trustedCardKey{keyID: k.KeyID, pub: pub, origins: origins})
	}
	return out
}

func topLevelHasSignaturesField(rawCard []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(rawCard))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return false
	}
	for dec.More() {
		ktok, err := dec.Token()
		if err != nil {
			return false
		}
		key, ok := ktok.(string)
		if !ok {
			return false
		}
		if key == a2aSignaturesField {
			return true
		}
		if err := skipJSONValue(dec, 0); err != nil {
			return false
		}
	}
	return false
}

// skipJSONValue consumes one JSON value from the decoder without materializing
// it. depth bounds recursion (maxJSONNesting) so deeply nested input returns an
// error rather than overflowing the stack.
func skipJSONValue(dec *json.Decoder, depth int) error {
	if depth > maxJSONNesting {
		return fmt.Errorf("json nesting exceeds %d", maxJSONNesting)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		for dec.More() {
			if _, err := dec.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := skipJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	default:
		return nil
	}
}

func parseJWSSignatureEntries(v any) ([]jwsSignature, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("signatures is %T, want array", v)
	}
	out := make([]jwsSignature, 0, len(arr))
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("signatures[%d] is %T, want object", i, item)
		}
		var entry jwsSignature
		for k, val := range obj {
			switch k {
			case "protected":
				s, ok := val.(string)
				if !ok {
					return nil, fmt.Errorf("signatures[%d].protected is %T, want string", i, val)
				}
				entry.Protected = s
			case "signature":
				s, ok := val.(string)
				if !ok {
					return nil, fmt.Errorf("signatures[%d].signature is %T, want string", i, val)
				}
				entry.Signature = s
			case "header":
				if _, ok := val.(map[string]any); !ok {
					return nil, fmt.Errorf("signatures[%d].header is %T, want object", i, val)
				}
			default:
				return nil, fmt.Errorf("signatures[%d] has unsupported field %q", i, k)
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

// verifyOneSignature attempts to verify a single JWS signature. It returns the
// verifying key_id and true only if the signature is EdDSA, decodes to a
// 64-byte Ed25519 signature, and verifies against a trusted key whose allowed
// origins include the card origin. kid is a lookup hint only.
func verifyOneSignature(entry jwsSignature, preimage []byte, origin string, keys []trustedCardKey) (string, bool) {
	if entry.Protected == "" || entry.Signature == "" {
		return "", false
	}
	protJSON, err := base64.RawURLEncoding.DecodeString(entry.Protected)
	if err != nil {
		return "", false
	}
	hdr, err := parseProtectedHeader(protJSON)
	if err != nil {
		return "", false
	}
	if hdr.Alg != jwsAlgEdDSA {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(entry.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", false
	}

	var signingInput []byte
	if hdr.B64 {
		signingInput = []byte(entry.Protected + "." + base64.RawURLEncoding.EncodeToString(preimage))
	} else {
		signingInput = append([]byte(entry.Protected+"."), preimage...)
	}

	// Empty origin (card origin could not be derived) matches no trusted key, so
	// verification fails closed. kid only reorders candidate keys; it never grants
	// trust, so an unknown kid still verifies if some origin-scoped key matches.
	if origin == "" {
		return "", false
	}
	for _, k := range orderByKidHint(keys, hdr.Kid) {
		if _, ok := k.origins[origin]; !ok {
			continue
		}
		if ed25519.Verify(k.pub, signingInput, sig) {
			return k.keyID, true
		}
	}
	return "", false
}

func parseProtectedHeader(raw []byte) (protectedHeader, error) {
	tree, err := jcs.Parse(raw)
	if err != nil {
		return protectedHeader{}, err
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return protectedHeader{}, fmt.Errorf("protected header is %T, want object", tree)
	}
	hdr := protectedHeader{B64: true}
	critSeen := map[string]struct{}{}
	b64Present := false
	for k, val := range obj {
		switch k {
		case "alg":
			s, ok := val.(string)
			if !ok {
				return protectedHeader{}, fmt.Errorf("protected alg is %T, want string", val)
			}
			hdr.Alg = s
		case "kid":
			s, ok := val.(string)
			if !ok {
				return protectedHeader{}, fmt.Errorf("protected kid is %T, want string", val)
			}
			hdr.Kid = s
		case "b64":
			b, ok := val.(bool)
			if !ok {
				return protectedHeader{}, fmt.Errorf("protected b64 is %T, want bool", val)
			}
			hdr.B64 = b
			b64Present = true
		case "crit":
			arr, ok := val.([]any)
			if !ok {
				return protectedHeader{}, fmt.Errorf("protected crit is %T, want array", val)
			}
			for _, item := range arr {
				name, ok := item.(string)
				if !ok {
					return protectedHeader{}, fmt.Errorf("protected crit entry is %T, want string", item)
				}
				if _, dup := critSeen[name]; dup {
					return protectedHeader{}, fmt.Errorf("duplicate crit entry %q", name)
				}
				critSeen[name] = struct{}{}
				// RFC 7515 critical headers: every listed extension must be
				// understood. This verifier only understands RFC 7797 b64.
				if name != "b64" {
					return protectedHeader{}, fmt.Errorf("unsupported critical header %q", name)
				}
				hdr.Crit = append(hdr.Crit, name)
			}
		}
	}
	if _, critical := critSeen["b64"]; critical && !b64Present {
		return protectedHeader{}, fmt.Errorf("critical b64 header is not present")
	}
	if !hdr.B64 && !jwsCritContains(hdr.Crit, "b64") {
		return protectedHeader{}, fmt.Errorf("b64:false missing critical b64 header")
	}
	return hdr, nil
}

// orderByKidHint returns keys with the kid-matching key first (a hint to reduce
// Ed25519 verifications), preserving the rest in order. It never filters keys —
// kid is not authority.
func orderByKidHint(keys []trustedCardKey, kid string) []trustedCardKey {
	if kid == "" {
		return keys
	}
	ordered := make([]trustedCardKey, 0, len(keys))
	var rest []trustedCardKey
	for _, k := range keys {
		if k.keyID == kid {
			ordered = append(ordered, k)
		} else {
			rest = append(rest, k)
		}
	}
	return append(ordered, rest...)
}

// CardOriginFromURL returns the origin (scheme://host[:port]) of a URL, lowercased,
// or "" if the URL is not an absolute http(s) URL. Used both to scope a card to
// the origin it was fetched from and to normalize configured allowed_origins.
//
// Its output MUST stay byte-identical to config.canonicalCardOrigin's: config
// validation normalizes and stores allowed_origins via that function, and this
// function re-normalizes them (and the card's fetch URL) at match time. Any
// divergence in host-casing, default-port stripping, or IPv6 bracketing would
// silently break origin matching. Keep the two in sync.
func CardOriginFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	port := u.Port()
	if port != "" && !validTCPPort(port) {
		return ""
	}
	// Normalize default ports per RFC 6454 origin semantics so that
	// https://h and https://h:443 (and http://h / http://h:80) compare equal.
	// Clients usually omit the default port in the proxied URL, so without this
	// an operator who pins "https://h:443" would never match a card served at
	// "https://h" — a false-reject, not a security gap, but a real FP class.
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	originHost := strings.ToLower(host)
	if port != "" {
		originHost = net.JoinHostPort(originHost, port)
	} else if strings.Contains(originHost, ":") {
		originHost = "[" + originHost + "]"
	}
	return scheme + "://" + originHost
}

func validTCPPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

func jwsCritContains(crit []string, want string) bool {
	for _, c := range crit {
		if c == want {
			return true
		}
	}
	return false
}

func originForReason(origin string) string {
	if origin == "" {
		return "(unknown)"
	}
	return origin
}
