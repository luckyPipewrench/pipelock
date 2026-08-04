// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Recipe is the fixture-only, typed transform language used by the evidence
// provenance specification. TransformProfileDigest pins all table and limit
// choices; callers must not infer behavior from its human-readable name.
type Recipe struct {
	TransformProfileDigest string      `json:"transform_profile_digest"`
	Operations             []Operation `json:"operations"`
}

// Operation is one ordered transform. Exactly one operation-specific field is
// meaningful for each Kind.
type Operation struct {
	Kind          OperationKind `json:"kind"`
	Component     Component     `json:"component,omitempty"`
	Selector      string        `json:"selector,omitempty"`
	Occurrence    uint32        `json:"occurrence,omitempty"`
	Passes        uint8         `json:"passes,omitempty"`
	Profile       string        `json:"profile,omitempty"`
	DecodePadding bool          `json:"decode_padding,omitempty"`
}

type OperationKind string

const (
	OperationIdentity       OperationKind = "identity"
	OperationURLComponent   OperationKind = "url_component"
	OperationPercentDecode  OperationKind = "percent_decode"
	OperationDLPNormalize   OperationKind = "dlp_normalize"
	OperationLowercase      OperationKind = "lowercase"
	OperationInvisibleStrip OperationKind = "invisible_strip"
	OperationHexDecode      OperationKind = "hex_decode"
	OperationBase32Decode   OperationKind = "base32_decode"
	OperationBase64Decode   OperationKind = "base64_decode"
	OperationLeetspeak      OperationKind = "leetspeak"
	OperationVowelFold      OperationKind = "vowel_fold"
)

// SupportedOperationKinds is the complete, versioned recipe vocabulary. Corpus
// tests require one vector for every returned operation.
func SupportedOperationKinds() []OperationKind {
	return []OperationKind{OperationIdentity, OperationURLComponent, OperationPercentDecode, OperationDLPNormalize, OperationLowercase, OperationInvisibleStrip, OperationHexDecode, OperationBase32Decode, OperationBase64Decode, OperationLeetspeak, OperationVowelFold}
}

type Component string

const (
	ComponentURL      Component = "url"
	ComponentHostname Component = "hostname"
	ComponentPath     Component = "path"
	ComponentQueryKey Component = "query_key"
	ComponentQueryVal Component = "query_value"
)

const evidenceProvenanceProfileMaxDecodePasses = 4

const (
	// EvidenceProvenanceProfileV1Digest identifies the fixture-only evidence
	// provenance transform profile, not the source-span transform profile.
	EvidenceProvenanceProfileV1Digest       = "sha256:8bc27d5d89e4e5ba3e0d1e68a25a3f0170f9a5ea2f19edf81a9a90bf82e23b3e"
	evidenceProvenanceProfileMaxInputBytes  = 2 << 20
	evidenceProvenanceProfileMaxOutputBytes = 1 << 20
)

type transformProfile struct {
	maxInputBytes  int
	maxOutputBytes int
}

func resolveTransformProfile(digest string) (transformProfile, error) {
	if len(digest) != len("sha256:")+64 || !strings.HasPrefix(digest, "sha256:") {
		return transformProfile{}, fmt.Errorf("transform profile digest: invalid SHA-256 digest")
	}
	for _, char := range digest[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return transformProfile{}, fmt.Errorf("transform profile digest: invalid SHA-256 digest")
		}
	}
	if digest != EvidenceProvenanceProfileV1Digest {
		return transformProfile{}, fmt.Errorf("transform profile digest: unknown profile %q", digest)
	}
	return transformProfile{maxInputBytes: evidenceProvenanceProfileMaxInputBytes, maxOutputBytes: evidenceProvenanceProfileMaxOutputBytes}, nil
}

// Validate checks that the recipe names a known profile and has an unambiguous
// operation shape. It does not require source bytes.
func (r Recipe) Validate() error {
	if r.TransformProfileDigest == "" {
		return fmt.Errorf("recipe: missing transform profile digest")
	}
	if _, err := resolveTransformProfile(r.TransformProfileDigest); err != nil {
		return fmt.Errorf("recipe: %w", err)
	}
	for index, op := range r.Operations {
		if err := op.validate(); err != nil {
			return fmt.Errorf("recipe operation %d (%s): %w", index, op.Kind, err)
		}
	}
	return nil
}

// Apply deterministically executes recipe on input. It deliberately rejects
// invalid UTF-8 rather than replacing bytes, because replacement corrupts byte
// offsets. The transform-profile document supplies the bound and invalid-input
// policy for interoperable implementations.
func (r Recipe) Apply(input string) (string, error) {
	if !utf8.ValidString(input) {
		return "", fmt.Errorf("recipe input: invalid UTF-8")
	}
	if err := r.Validate(); err != nil {
		return "", err
	}
	profile, err := resolveTransformProfile(r.TransformProfileDigest)
	if err != nil {
		return "", fmt.Errorf("recipe: %w", err)
	}
	if len(input) > profile.maxInputBytes {
		return "", fmt.Errorf("recipe input: exceeds profile byte limit")
	}
	value := input
	for index, op := range r.Operations {
		value, err = op.apply(value)
		if err != nil {
			return "", fmt.Errorf("recipe operation %d (%s): %w", index, op.Kind, err)
		}
		if !utf8.ValidString(value) {
			return "", fmt.Errorf("recipe operation %d (%s): output: invalid UTF-8", index, op.Kind)
		}
		if len(value) > profile.maxOutputBytes {
			return "", fmt.Errorf("recipe operation %d (%s): output exceeds profile byte limit", index, op.Kind)
		}
	}
	if len(value) > profile.maxOutputBytes {
		return "", fmt.Errorf("recipe output exceeds profile byte limit")
	}
	return value, nil
}

// ValidateOutput checks that value is valid UTF-8 and fits the recipe's
// resolved transform profile. It is for commitment constructors that receive
// an already reconstructed view rather than source bytes to transform.
func (r Recipe) ValidateOutput(value string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("recipe output: invalid UTF-8")
	}
	profile, err := resolveTransformProfile(r.TransformProfileDigest)
	if err != nil {
		return fmt.Errorf("recipe: %w", err)
	}
	if len(value) > profile.maxOutputBytes {
		return fmt.Errorf("recipe output exceeds profile byte limit")
	}
	return nil
}

func (op Operation) apply(value string) (string, error) {
	switch op.Kind {
	case OperationIdentity:
		return value, nil
	case OperationURLComponent:
		return op.selectURLComponent(value)
	case OperationPercentDecode:
		for range op.Passes {
			decoded, err := url.PathUnescape(value)
			if err != nil {
				return "", fmt.Errorf("percent decode: %w", err)
			}
			value = decoded
		}
		return value, nil
	case OperationDLPNormalize:
		return ForDLP(value), nil
	case OperationLowercase:
		return strings.ToLower(value), nil
	case OperationInvisibleStrip:
		return StripZeroWidth(value), nil
	case OperationHexDecode:
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("hex decode: %w", err)
		}
		if hex.EncodeToString(decoded) != value {
			return "", fmt.Errorf("hex decode: non-canonical encoding")
		}
		if !utf8.Valid(decoded) {
			return "", fmt.Errorf("hex decode output: invalid UTF-8")
		}
		return string(decoded), nil
	case OperationBase32Decode:
		encoding := base32.StdEncoding
		if !op.DecodePadding {
			encoding = encoding.WithPadding(base32.NoPadding)
		}
		decoded, err := encoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("base32 decode: %w", err)
		}
		if encoding.EncodeToString(decoded) != value {
			return "", fmt.Errorf("base32 decode: non-canonical encoding")
		}
		if !utf8.Valid(decoded) {
			return "", fmt.Errorf("base32 decode output: invalid UTF-8")
		}
		return string(decoded), nil
	case OperationBase64Decode:
		encoding := base64.StdEncoding
		if !op.DecodePadding {
			encoding = base64.RawStdEncoding
		}
		decoded, err := encoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("base64 decode: %w", err)
		}
		if encoding.EncodeToString(decoded) != value {
			return "", fmt.Errorf("base64 decode: non-canonical encoding")
		}
		if !utf8.Valid(decoded) {
			return "", fmt.Errorf("base64 decode output: invalid UTF-8")
		}
		return string(decoded), nil
	case OperationLeetspeak:
		return Leetspeak(value), nil
	case OperationVowelFold:
		return FoldVowels(value), nil
	default:
		return "", fmt.Errorf("unknown operation %q", op.Kind)
	}
}

func (op Operation) validate() error {
	reject := func(field string) error {
		return fmt.Errorf("unsupported %s for %s", field, op.Kind)
	}
	// The Typed recipe language clause prohibits Unicode control characters in
	// selector and profile values, so implementations reject them before
	// evaluating the operation-specific parameter shape.
	for _, field := range []struct {
		name  string
		value string
	}{{"selector", op.Selector}, {"profile", op.Profile}} {
		for _, r := range field.value {
			if unicode.IsControl(r) {
				return fmt.Errorf("%s for %s contains control character %U", field.name, op.Kind, r)
			}
		}
	}
	noParameters := func() error {
		switch {
		case op.Component != "":
			return reject("component")
		case op.Selector != "":
			return reject("selector")
		case op.Occurrence != 0:
			return reject("occurrence")
		case op.Passes != 0:
			return reject("passes")
		case op.Profile != "":
			return reject("profile")
		case op.DecodePadding:
			return reject("decode_padding")
		default:
			return nil
		}
	}
	switch op.Kind {
	case OperationIdentity, OperationLowercase, OperationInvisibleStrip, OperationLeetspeak, OperationVowelFold:
		return noParameters()
	case OperationURLComponent:
		if op.Passes != 0 {
			return reject("passes")
		}
		if op.Profile != "" {
			return reject("profile")
		}
		if op.DecodePadding {
			return reject("decode_padding")
		}
		switch op.Component {
		case ComponentURL, ComponentHostname, ComponentPath:
			if op.Selector != "" {
				return reject("selector")
			}
			if op.Occurrence != 0 {
				return reject("occurrence")
			}
		case ComponentQueryKey, ComponentQueryVal:
			if op.Selector == "" {
				return fmt.Errorf("query component: missing selector")
			}
		default:
			return fmt.Errorf("unknown URL component %q", op.Component)
		}
		return nil
	case OperationPercentDecode:
		if op.Passes == 0 || op.Passes > evidenceProvenanceProfileMaxDecodePasses {
			return fmt.Errorf("percent decode passes must be 1..%d", evidenceProvenanceProfileMaxDecodePasses)
		}
		if op.Component != "" {
			return reject("component")
		}
		if op.Selector != "" {
			return reject("selector")
		}
		if op.Occurrence != 0 {
			return reject("occurrence")
		}
		if op.Profile != "" {
			return reject("profile")
		}
		if op.DecodePadding {
			return reject("decode_padding")
		}
		return nil
	case OperationDLPNormalize:
		if op.Profile != "pipelock-dlp-v1" {
			return fmt.Errorf("unknown DLP profile %q", op.Profile)
		}
		if op.Component != "" {
			return reject("component")
		}
		if op.Selector != "" {
			return reject("selector")
		}
		if op.Occurrence != 0 {
			return reject("occurrence")
		}
		if op.Passes != 0 {
			return reject("passes")
		}
		if op.DecodePadding {
			return reject("decode_padding")
		}
		return nil
	case OperationHexDecode:
		return noParameters()
	case OperationBase32Decode, OperationBase64Decode:
		if op.Component != "" {
			return reject("component")
		}
		if op.Selector != "" {
			return reject("selector")
		}
		if op.Occurrence != 0 {
			return reject("occurrence")
		}
		if op.Passes != 0 {
			return reject("passes")
		}
		if op.Profile != "" {
			return reject("profile")
		}
		return nil
	default:
		return fmt.Errorf("unknown operation %q", op.Kind)
	}
}

func (op Operation) selectURLComponent(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("URL parse: invalid absolute URL")
	}
	switch op.Component {
	case ComponentURL:
		return value, nil
	case ComponentHostname:
		return parsed.Hostname(), nil
	case ComponentPath:
		return parsed.EscapedPath(), nil
	case ComponentQueryKey, ComponentQueryVal:
		if op.Selector == "" {
			return "", fmt.Errorf("query component: missing selector")
		}
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return "", fmt.Errorf("query parse: %w", err)
		}
		values, ok := query[op.Selector]
		if !ok || int(op.Occurrence) >= len(values) {
			return "", fmt.Errorf("query component: occurrence %d unavailable", op.Occurrence)
		}
		if op.Component == ComponentQueryKey {
			return op.Selector, nil
		}
		return values[op.Occurrence], nil
	default:
		return "", fmt.Errorf("unknown URL component %q", op.Component)
	}
}
