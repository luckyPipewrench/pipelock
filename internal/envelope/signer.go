// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

// pipelockSigLabel is the dictionary member label used for pipelock's
// RFC 9421 signature slot. It is intentionally distinct from "sig1"
// (the Cloudflare Web Bot Auth default) so pipelock signatures coexist
// with any upstream signature a request already carries.
const pipelockSigLabel = "pipelock1"

// pipelockSigTag is the value of the ;tag= parameter on
// Signature-Input. Verifiers use it to identify the signature's purpose.
const pipelockSigTag = "pipelock-mediation"

// Known RFC 9421 derived component names. Derived components carry
// metadata about the request itself rather than the value of a literal
// HTTP header. The signer supports the minimal set required for the
// mediation envelope contract.
const (
	derivedMethod    = "@method"
	derivedTargetURI = "@target-uri"
	derivedAuthority = "@authority"
)

// Header field names that appear as covered components. Using constants
// (instead of literal strings at call sites) keeps the switch in
// buildComponentValue lint-clean against goconst and also makes the
// canonical component list easy to audit.
const (
	headerContentDigest     = "content-digest"
	headerPipelockMediation = "pipelock-mediation"
)

// ErrSignerDisabled is returned from (*Signer).SignRequest when called
// on a nil receiver. Callers treat nil as "signing disabled" and skip
// attaching a signature; the error exists so callers that want to
// distinguish disabled-vs-failure can check for it explicitly.
var ErrSignerDisabled = errors.New("envelope signer disabled")

// Signer produces RFC 9421 HTTP Message Signatures over the mediation
// envelope's declared component set. One Signer instance is created by
// the proxy reload path per successful config load; the stored private
// key material is the only secret the Signer holds, and it is passed
// in by value (ed25519.PrivateKey is a []byte) so the Signer is self
// contained and cheap to swap atomically on hot reload.
//
// Signer is safe for concurrent use. The key, keyID, and component
// list are immutable after construction; the optional nowFn hook is
// only replaced in tests via the SignerConfig field.
type Signer struct {
	privKey      ed25519.PrivateKey
	keyID        string
	components   []string // maximal declared set — subset used per request
	maxBodyBytes int
	nowFn        func() time.Time
}

// SignerConfig holds the inputs for constructing a Signer.
type SignerConfig struct {
	// PrivKey is the Ed25519 key used to produce signatures. Required.
	// The key is stored by reference; callers must not mutate it after
	// handing it to the Signer.
	PrivKey ed25519.PrivateKey

	// KeyID is emitted as the ;keyid= parameter on Signature-Input.
	// Required; verifiers use it to select the public key.
	KeyID string

	// SignedComponents is the maximal declared component list. The
	// per-request effective list is computed from this by dropping
	// any component that does not apply to the specific request
	// (content-digest on a body-less request, headers that are not
	// present, and so on). Must contain at least one entry.
	SignedComponents []string

	// MaxBodyBytes caps the size of body the Signer is willing to
	// buffer when it has to compute Content-Digest itself. Zero
	// means "do not cap" — SignRequest will accept any body the
	// caller hands it. The proxy fills this from
	// MediationEnvelope.MaxBodyBytes.
	MaxBodyBytes int

	// NowFn returns the current time. Defaults to time.Now. Tests
	// inject a fixed clock so signature base strings are reproducible
	// and the ;created= parameter is deterministic.
	NowFn func() time.Time
}

// NewSigner validates the config and returns a Signer. The only
// runtime error paths today are missing key, missing key id, and empty
// component list — all of which the config validator will also catch
// before this is reached. The redundant check here means a caller that
// constructs a Signer outside the standard config path still gets a
// deterministic error instead of a nil-deref at sign time.
func NewSigner(cfg SignerConfig) (*Signer, error) {
	if len(cfg.PrivKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("envelope signer requires an Ed25519 private key, got %d bytes", len(cfg.PrivKey))
	}
	if strings.TrimSpace(cfg.KeyID) == "" {
		return nil, errors.New("envelope signer requires a non-empty key_id")
	}
	if len(cfg.SignedComponents) == 0 {
		return nil, errors.New("envelope signer requires at least one signed component")
	}
	now := cfg.NowFn
	if now == nil {
		now = time.Now
	}
	// Defensive copy so the caller cannot mutate our component list
	// after construction.
	comps := make([]string, len(cfg.SignedComponents))
	copy(comps, cfg.SignedComponents)

	return &Signer{
		privKey:      cfg.PrivKey,
		keyID:        cfg.KeyID,
		components:   comps,
		maxBodyBytes: cfg.MaxBodyBytes,
		nowFn:        now,
	}, nil
}

// KeyID returns the Signer's declared key_id. Exported for tests and
// operator tooling that needs to confirm which key is active without
// reaching into private state.
func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// SignRequest attaches a pipelock1 RFC 9421 signature to req over a
// request-specific subset of the declared component list.
//
// body is the already-buffered request body or nil for body-less
// requests. When non-nil, SignRequest writes a Content-Digest header
// (replacing any existing one) with the SHA-256 digest of body, and
// includes "content-digest" in the declared component list for this
// request. When body is nil — or when body exceeds maxBodyBytes and
// the signer declines to digest it — "content-digest" is dropped from
// the declared list rather than being signed with an unknown value.
//
// Any header component in the Signer's configured list that is not
// present on the request is skipped for that request (e.g. a
// configured "authorization" component on a request without the
// header). This is allowed by RFC 9421: Signature-Input declares the
// actual components signed, and verifiers use that declaration to
// reconstruct the signature base.
//
// SignRequest coexists with existing signatures: if the request
// already has Signature or Signature-Input dictionary members, the
// pipelock1 member is merged into the existing dictionary rather
// than replacing it. Any pre-existing pipelock* member is overwritten.
func (s *Signer) SignRequest(req *http.Request, body []byte) error {
	if s == nil {
		return ErrSignerDisabled
	}
	if req == nil {
		return errors.New("envelope signer: nil *http.Request")
	}

	// Body buffering cap: if maxBodyBytes is set and the caller has
	// handed us a body larger than the cap, drop it so we still sign
	// but without content-digest. The alternative — failing the whole
	// sign — would take down the transport for a single oversized
	// request, which is the wrong trade-off. The signer's declared
	// component list for THIS request will not contain content-digest,
	// and the verifier sees that in Signature-Input.
	if s.maxBodyBytes > 0 && len(body) > s.maxBodyBytes {
		body = nil
	}

	// Compute the effective component list and set any headers the
	// signer is responsible for populating before signing. Today the
	// only signer-populated header is Content-Digest.
	effective := s.effectiveComponents(req, body)
	if len(effective) == 0 {
		// No component on the request matches our declared list. This
		// is a programming error — the inject path should have set the
		// Pipelock-Mediation header before calling SignRequest, and
		// @method and @target-uri always apply. Fail loudly rather
		// than emitting an empty signature base.
		return errors.New("envelope signer: no effective components for request")
	}

	// Build the signature-params inner list (component list +
	// parameters). This object is emitted on Signature-Input AND
	// serialized into the last line of the signature base.
	created := s.nowFn().UTC().Unix()
	sigParams := buildSigParams(effective, created, s.keyID)

	// Build the signature base per RFC 9421 §2.5.
	base, err := buildSignatureBase(req, body, effective, sigParams)
	if err != nil {
		return fmt.Errorf("envelope signer: building signature base: %w", err)
	}

	rawSig := ed25519.Sign(s.privKey, []byte(base))

	// Attach Signature-Input and Signature headers, preserving any
	// existing sig1 / web-bot-auth members. If the request already
	// carried a pipelock* member (from a previous pipelock hop, an
	// attacker-controlled inbound, or a redirect refresh), replace
	// it in place.
	if err := mergeSignatureInput(req.Header, sigParams); err != nil {
		return fmt.Errorf("envelope signer: merging Signature-Input: %w", err)
	}
	if err := mergeSignature(req.Header, rawSig); err != nil {
		return fmt.Errorf("envelope signer: merging Signature: %w", err)
	}

	return nil
}

// effectiveComponents returns the per-request subset of the configured
// component list. Derived components (@method, @target-uri,
// @authority) always apply. Header field components only apply when
// the header is actually present on the request. content-digest is a
// special case: the signer populates it from body when body is non
// nil, otherwise it is dropped.
func (s *Signer) effectiveComponents(req *http.Request, body []byte) []string {
	out := make([]string, 0, len(s.components))
	for _, raw := range s.components {
		comp := strings.ToLower(strings.TrimSpace(raw))
		if comp == "" {
			continue
		}
		switch comp {
		case derivedMethod, derivedTargetURI, derivedAuthority:
			out = append(out, comp)
		case headerContentDigest:
			if len(body) == 0 {
				// No body to digest. Per RFC 9421 the declared list
				// must match what we actually sign, so drop it.
				continue
			}
			// Populate the header from the body. Replace any
			// inbound value so a stale digest cannot survive.
			req.Header.Set("Content-Digest", contentDigestHeaderValue(body))
			out = append(out, comp)
		default:
			// Any other entry is an HTTP header field name. Include
			// it in the declared list only when the request carries
			// the header — otherwise we would sign a "" value which
			// a verifier might reconstruct differently.
			if req.Header.Get(comp) != "" {
				out = append(out, comp)
			}
		}
	}
	return out
}

// contentDigestHeaderValue returns the RFC 9530 Content-Digest header
// value for a SHA-256 digest of body. The RFC wraps the base64 digest
// in the structured-field byte-sequence form (`:...:`) and tags it
// with the algorithm name.
func contentDigestHeaderValue(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// buildSigParams returns an httpsfv InnerList whose Items are the
// effective component names (as string Items) and whose Params carry
// the RFC 9421 metadata (;created, ;keyid, ;tag). The function cannot
// fail today — Params.Add is infallible for the bare-item types we
// hand it — but the shape is still a constructor so new parameters
// (e.g. ;expires for inbound-verify compatibility) can be added
// without altering the calling convention.
func buildSigParams(components []string, created int64, keyID string) httpsfv.InnerList {
	items := make([]httpsfv.Item, 0, len(components))
	for _, c := range components {
		items = append(items, httpsfv.NewItem(c))
	}
	params := httpsfv.NewParams()
	params.Add("created", created)
	params.Add("keyid", keyID)
	params.Add("tag", pipelockSigTag)
	return httpsfv.InnerList{Items: items, Params: params}
}

// buildSignatureBase constructs the RFC 9421 §2.5 signature base
// string. Each covered component contributes one line of the form
//
//	"<component-name>": <component-value>
//
// followed by a final line for @signature-params whose value is the
// serialized InnerList. The returned string has NO trailing newline —
// RFC 9421 specifies LF between lines, not after the last one.
func buildSignatureBase(req *http.Request, body []byte, components []string, sigParams httpsfv.InnerList) (string, error) {
	var b strings.Builder
	for _, comp := range components {
		value, err := buildComponentValue(req, body, comp)
		if err != nil {
			return "", err
		}
		// Lowercased quoted name, then ": ", then value, then LF.
		b.WriteByte('"')
		b.WriteString(comp)
		b.WriteString(`": `)
		b.WriteString(value)
		b.WriteByte('\n')
	}
	// @signature-params line — no trailing LF.
	b.WriteString(`"@signature-params": `)
	serialized, err := httpsfv.Marshal(sigParams)
	if err != nil {
		return "", fmt.Errorf("serializing signature params: %w", err)
	}
	b.WriteString(serialized)
	return b.String(), nil
}

// buildComponentValue returns the string form of a single covered
// component's value for inclusion in the signature base.
func buildComponentValue(req *http.Request, body []byte, comp string) (string, error) {
	switch comp {
	case derivedMethod:
		return strings.ToUpper(req.Method), nil
	case derivedTargetURI:
		if req.URL == nil {
			return "", errors.New("request has nil URL")
		}
		return req.URL.String(), nil
	case derivedAuthority:
		if req.URL != nil && req.URL.Host != "" {
			return strings.ToLower(req.URL.Host), nil
		}
		return strings.ToLower(req.Host), nil
	case headerContentDigest:
		// contentDigestHeaderValue was just written to the header in
		// effectiveComponents, so read it back from there. That way a
		// caller that pre-set Content-Digest with a different body
		// (e.g. a malicious inbound carry-over) cannot win against
		// the signer — effectiveComponents overwrote it.
		v := req.Header.Get("Content-Digest")
		if v == "" {
			// Defensive: if body existed and we were supposed to
			// digest it, the header must be set. Recompute.
			if len(body) == 0 {
				return "", errors.New("content-digest requested but body is empty")
			}
			v = contentDigestHeaderValue(body)
		}
		return v, nil
	default:
		// Header field component. Lower-cased lookup; the real
		// value goes into the signature base as-is.
		v := req.Header.Get(comp)
		if v == "" {
			return "", fmt.Errorf("header %q requested but not present", comp)
		}
		return v, nil
	}
}

// mergeSignatureInput adds (or replaces) the pipelock1 member on the
// Signature-Input header's dictionary, preserving any existing members
// from upstream signers such as Cloudflare sig1 / web-bot-auth.
func mergeSignatureInput(h http.Header, sigParams httpsfv.InnerList) error {
	dict, err := loadOrNewDict(h, "Signature-Input")
	if err != nil {
		return err
	}
	dict.Add(pipelockSigLabel, sigParams)
	return marshalDictToHeader(h, "Signature-Input", dict)
}

// mergeSignature adds (or replaces) the pipelock1 member on the
// Signature header's dictionary. The signature bytes are wrapped in an
// RFC 8941 byte-sequence Item so that the coexistence-with-sig1 path
// round-trips through any downstream structured-field parser.
func mergeSignature(h http.Header, rawSig []byte) error {
	dict, err := loadOrNewDict(h, "Signature")
	if err != nil {
		return err
	}
	dict.Add(pipelockSigLabel, httpsfv.NewItem(rawSig))
	return marshalDictToHeader(h, "Signature", dict)
}

// loadOrNewDict returns the existing structured-field dictionary for
// the named header, or an empty dictionary if the header is absent.
// Any existing pipelock* member is deleted so the caller's subsequent
// Add installs a fresh value cleanly (redirect refresh and retry paths
// both rely on this).
func loadOrNewDict(h http.Header, headerName string) (*httpsfv.Dictionary, error) {
	values := h.Values(headerName)
	if len(values) == 0 {
		return httpsfv.NewDictionary(), nil
	}
	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		// The existing dictionary is malformed. Refuse to merge with
		// it — we would either corrupt the upstream signature or
		// propagate attacker-supplied garbage into our output.
		return nil, fmt.Errorf("header %q is not a valid structured-field dictionary: %w", headerName, err)
	}
	// Drop any previous pipelock* slot so our new Add does not append
	// a second pipelock1 alongside a stale one. The strip covers
	// "pipelock1", "pipelock2", etc. in case a future key rotation
	// bumps the label.
	for _, name := range dict.Names() {
		if strings.HasPrefix(name, pipelockMemberPrefix) {
			dict.Del(name)
		}
	}
	return dict, nil
}

// marshalDictToHeader serializes dict into headerName, replacing all
// existing values of that header. httpsfv.Marshal returns a single
// flat string — we never emit the dict as multi-line.
func marshalDictToHeader(h http.Header, headerName string, dict *httpsfv.Dictionary) error {
	out, err := httpsfv.Marshal(dict)
	if err != nil {
		return fmt.Errorf("serializing %q dictionary: %w", headerName, err)
	}
	h.Del(headerName)
	h.Set(headerName, out)
	return nil
}
