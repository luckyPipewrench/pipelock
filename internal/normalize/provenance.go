// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrEvidenceProvenanceProcessingBudget reports that a recipe exhausted the
// profile-wide cumulative processing allowance.
var ErrEvidenceProvenanceProcessingBudget = errors.New("recipe: exceeds cumulative processing budget")

// ErrEvidenceProvenanceFixtureProcessingBudget reports that a verifier's
// fixture-wide allowance was exhausted after the per-recipe allowance passed.
var ErrEvidenceProvenanceFixtureProcessingBudget = errors.New("fixture: exceeds cumulative recipe processing budget")

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
	Alphabet      string        `json:"alphabet,omitempty"`
	Indices       QueryIndices  `json:"indices,omitempty"`
	MinimumLength uint32        `json:"minimum_length,omitempty"`
}

// QueryIndices is encoded as a JSON array of uint8 values. encoding/json treats
// a bare []uint8 as binary data and emits a base64 string, which would violate
// the profile's normative array<uint8> wire shape and make Go-issued recipes
// invalid in the other reference verifiers.
type QueryIndices []uint8

func (indices QueryIndices) MarshalJSON() ([]byte, error) {
	values := make([]uint16, len(indices))
	for index, value := range indices {
		values[index] = uint16(value)
	}
	return json.Marshal(values)
}

func (indices *QueryIndices) UnmarshalJSON(data []byte) error {
	var values []uint16
	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("query indices must be an array of uint8 values: %w", err)
	}
	result := make(QueryIndices, len(values))
	for index, value := range values {
		if value > 255 {
			return fmt.Errorf("query index %d exceeds uint8", value)
		}
		result[index] = uint8(value)
	}
	*indices = result
	return nil
}

type OperationKind string

const (
	OperationIdentity              OperationKind = "identity"
	OperationURLComponent          OperationKind = "url_component"
	OperationPercentDecode         OperationKind = "percent_decode"
	OperationDLPNormalize          OperationKind = "dlp_normalize"
	OperationLowercase             OperationKind = "lowercase"
	OperationInvisibleStrip        OperationKind = "invisible_strip"
	OperationHexDecode             OperationKind = "hex_decode"
	OperationBase32Decode          OperationKind = "base32_decode"
	OperationBase64Decode          OperationKind = "base64_decode"
	OperationLeetspeak             OperationKind = "leetspeak"
	OperationVowelFold             OperationKind = "vowel_fold"
	OperationQueryUnescape         OperationKind = "query_unescape"
	OperationInvisibleSpace        OperationKind = "invisible_space"
	OperationMatchingNormalize     OperationKind = "matching_normalize"
	OperationHexDecodeLiberal      OperationKind = "hex_decode_liberal"
	OperationBase32DecodeLiberal   OperationKind = "base32_decode_liberal"
	OperationBase64DecodeLiberal   OperationKind = "base64_decode_liberal"
	OperationEncodedTokenNormalize OperationKind = "encoded_token_normalize"
	OperationTextSegment           OperationKind = "text_segment"
	OperationHTMLEntityDecode      OperationKind = "html_entity_decode"
	OperationWhitespaceCompact     OperationKind = "whitespace_compact"
	OperationURLNoiseStrip         OperationKind = "url_noise_strip"
	OperationOrderedQueryConcat    OperationKind = "ordered_query_concat"
	OperationQuerySubsequence      OperationKind = "query_subsequence"
	OperationHostnameDotRemove     OperationKind = "hostname_dot_remove"
	OperationEncodedRun            OperationKind = "encoded_run"
	OperationCanaryCanonicalize    OperationKind = "canary_canonicalize"
)

// SupportedOperationKinds is the complete, versioned recipe vocabulary. Corpus
// tests require one vector for every returned operation.
func SupportedOperationKinds() []OperationKind {
	return []OperationKind{
		OperationIdentity, OperationURLComponent, OperationPercentDecode, OperationDLPNormalize,
		OperationLowercase, OperationInvisibleStrip, OperationHexDecode, OperationBase32Decode,
		OperationBase64Decode, OperationLeetspeak, OperationVowelFold,
		OperationQueryUnescape, OperationInvisibleSpace, OperationMatchingNormalize,
		OperationHexDecodeLiberal, OperationBase32DecodeLiberal, OperationBase64DecodeLiberal,
		OperationEncodedTokenNormalize, OperationTextSegment, OperationHTMLEntityDecode,
		OperationWhitespaceCompact, OperationURLNoiseStrip, OperationOrderedQueryConcat,
		OperationQuerySubsequence, OperationHostnameDotRemove, OperationEncodedRun,
		OperationCanaryCanonicalize,
	}
}

type Component string

const (
	ComponentURL      Component = "url"
	ComponentHostname Component = "hostname"
	ComponentPath     Component = "path"
	ComponentQueryKey Component = "query_key"
	ComponentQueryVal Component = "query_value"
	ComponentRawQuery Component = "raw_query"
)

const evidenceProvenanceProfileMaxDecodePasses = 4

const (
	// ScannerQueryUnescapeMaxRounds is shared with the production scanner so
	// receipt replay cannot drift from IterativeDecode's safety ceiling.
	ScannerQueryUnescapeMaxRounds = 500

	// evidenceProvenanceMaxOperations bounds recipe length. Per-operation input
	// and output caps do not bound verifier work when the attacker controls how
	// MANY operations run: a long sequence of individually legal transforms each
	// stays under the intermediate limit while the total cost grows without
	// bound. Provenance verification runs against externally supplied receipts
	// during incident review, so an unbounded recipe is an availability attack
	// on the audit path.
	evidenceProvenanceMaxOperations = 32
	// evidenceProvenanceMaxTotalBytes bounds CUMULATIVE bytes processed across
	// every operation and every internal pass. Round caps alone are insufficient
	// because a single operation may legally repeat near the maximum size, so
	// the budget is charged in aggregate and exhaustion is a rejection.
	evidenceProvenanceMaxTotalBytes = 16 << 20

	evidenceProvenanceScannerMaxDecodeRounds = ScannerQueryUnescapeMaxRounds
	evidenceProvenanceHTMLMaxDecodePasses    = 16
	evidenceProvenanceQueryMaxValues         = 20
	evidenceProvenanceQueryMinIndices        = 2
	evidenceProvenanceQueryMaxIndices        = 4
)

const (
	// EvidenceProvenanceProfileV1Digest identifies the fixture-only evidence
	// provenance transform profile, not the source-span transform profile.
	EvidenceProvenanceProfileV1Digest       = "sha256:3de14968449593cae58da869cfc97855cb098e491494390a12ba742cb0b70f94"
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
	if len(r.Operations) > evidenceProvenanceMaxOperations {
		return fmt.Errorf("recipe: exceeds %d operations", evidenceProvenanceMaxOperations)
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
	budget := processingBudget(evidenceProvenanceMaxTotalBytes)
	return r.apply(input, &budget)
}

// ApplyWithinBudget executes a recipe while charging every operation and
// internal pass against the per-recipe profile limit first and the caller's
// limit second. It returns the caller-budget bytes charged so a fixture
// verifier can enforce one allowance across many recipes.
func (r Recipe) ApplyWithinBudget(input string, limit int) (string, int, error) {
	if limit < 0 {
		limit = 0
	}
	recipeBudget := processingBudget(evidenceProvenanceMaxTotalBytes)
	fixtureBudget := processingBudget(limit)
	budget := combinedProcessingBudget{recipe: &recipeBudget, fixture: &fixtureBudget}
	value, err := r.apply(input, &budget)
	return value, limit - int(fixtureBudget), err
}

type chargeBudget interface {
	charge(string) error
}

func (r Recipe) apply(input string, budget chargeBudget) (string, error) {
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
		// Charge the operation's input against the cumulative budget BEFORE
		// running it, so an expensive operation cannot spend work it has not
		// been granted.
		if err := budget.charge(value); err != nil {
			return "", err
		}
		value, err = op.apply(value, budget)
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

type processingBudget int

func (budget *processingBudget) charge(value string) error {
	if len(value) > int(*budget) {
		return ErrEvidenceProvenanceProcessingBudget
	}
	*budget -= processingBudget(len(value))
	return nil
}

type combinedProcessingBudget struct {
	recipe  *processingBudget
	fixture *processingBudget
}

func (budget *combinedProcessingBudget) charge(value string) error {
	if err := budget.recipe.charge(value); err != nil {
		return err
	}
	if len(value) > int(*budget.fixture) {
		return ErrEvidenceProvenanceFixtureProcessingBudget
	}
	*budget.fixture -= processingBudget(len(value))
	return nil
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

func (op Operation) apply(value string, budget chargeBudget) (string, error) {
	switch op.Kind {
	case OperationIdentity:
		return value, nil
	case OperationURLComponent:
		return op.selectURLComponent(value)
	case OperationPercentDecode:
		for range op.Passes {
			if err := budget.charge(value); err != nil {
				return "", err
			}
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
	case OperationQueryUnescape:
		return scannerQueryUnescape(value, budget)
	case OperationInvisibleSpace:
		return ReplaceInvisibleWithSpace(value), nil
	case OperationMatchingNormalize:
		return ForMatching(value), nil
	case OperationHexDecodeLiberal:
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("liberal hex decode: %w", err)
		}
		return string(decoded), nil
	case OperationBase32DecodeLiberal:
		encoding := base32.StdEncoding
		if !op.DecodePadding {
			encoding = encoding.WithPadding(base32.NoPadding)
		}
		decoded, err := encoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("liberal base32 decode: %w", err)
		}
		return string(decoded), nil
	case OperationBase64DecodeLiberal:
		encoding, err := scannerBase64Encoding(op.Alphabet, op.DecodePadding)
		if err != nil {
			return "", err
		}
		decoded, err := encoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("liberal base64 decode: %w", err)
		}
		return string(decoded), nil
	case OperationEncodedTokenNormalize:
		return scannerEncodedTokenNormalize(value, op.Alphabet), nil
	case OperationTextSegment:
		return selectScannerTextSegment(value, op.Occurrence)
	case OperationHTMLEntityDecode:
		return scannerHTMLEntityDecode(value, budget)
	case OperationWhitespaceCompact:
		return scannerWhitespaceCompact(value), nil
	case OperationURLNoiseStrip:
		return scannerURLNoiseStrip(value), nil
	case OperationOrderedQueryConcat:
		return scannerOrderedQueryConcat(value, budget)
	case OperationQuerySubsequence:
		return scannerQuerySubsequence(value, op.Indices, budget)
	case OperationHostnameDotRemove:
		return strings.ReplaceAll(value, ".", ""), nil
	case OperationEncodedRun:
		return selectScannerEncodedRun(value, op.Occurrence, op.MinimumLength)
	case OperationCanaryCanonicalize:
		return scannerCanaryCanonicalize(value), nil
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
		return op.noParametersForValidation(reject)
	}
	switch op.Kind {
	case OperationIdentity, OperationLowercase, OperationInvisibleStrip, OperationLeetspeak, OperationVowelFold,
		OperationQueryUnescape, OperationInvisibleSpace, OperationWhitespaceCompact,
		OperationURLNoiseStrip, OperationOrderedQueryConcat, OperationHostnameDotRemove,
		OperationCanaryCanonicalize, OperationHTMLEntityDecode, OperationHexDecodeLiberal:
		return noParameters()
	case OperationURLComponent:
		switch op.Component {
		case ComponentURL, ComponentHostname, ComponentPath, ComponentRawQuery:
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
		parameterless := op
		parameterless.Component = ""
		parameterless.Selector = ""
		parameterless.Occurrence = 0
		return parameterless.noParametersForValidation(reject)
	case OperationPercentDecode:
		if op.Passes == 0 || op.Passes > evidenceProvenanceProfileMaxDecodePasses {
			return fmt.Errorf("percent decode passes must be 1..%d", evidenceProvenanceProfileMaxDecodePasses)
		}
		parameterless := op
		parameterless.Passes = 0
		return parameterless.noParametersForValidation(reject)
	case OperationDLPNormalize:
		if op.Profile != "pipelock-dlp-v1" {
			return fmt.Errorf("unknown DLP profile %q", op.Profile)
		}
		parameterless := op
		parameterless.Profile = ""
		return parameterless.noParametersForValidation(reject)
	case OperationHexDecode:
		return noParameters()
	case OperationBase32Decode, OperationBase64Decode:
		parameterless := op
		parameterless.DecodePadding = false
		return parameterless.noParametersForValidation(reject)
	case OperationMatchingNormalize:
		if op.Profile != "pipelock-matching-v1" {
			return fmt.Errorf("unknown matching profile %q", op.Profile)
		}
		parameterless := op
		parameterless.Profile = ""
		return parameterless.noParametersForValidation(reject)
	case OperationBase32DecodeLiberal:
		parameterless := op
		parameterless.DecodePadding = false
		return parameterless.noParametersForValidation(reject)
	case OperationBase64DecodeLiberal:
		if op.Alphabet != "standard" && op.Alphabet != "url" {
			return fmt.Errorf("unknown base64 alphabet %q", op.Alphabet)
		}
		parameterless := op
		parameterless.Alphabet = ""
		parameterless.DecodePadding = false
		return parameterless.noParametersForValidation(reject)
	case OperationEncodedTokenNormalize:
		switch op.Alphabet {
		case "hex", "base32", "base64_standard", "base64_url":
		default:
			return fmt.Errorf("unknown encoded-token alphabet %q", op.Alphabet)
		}
		parameterless := op
		parameterless.Alphabet = ""
		return parameterless.noParametersForValidation(reject)
	case OperationTextSegment:
		parameterless := op
		parameterless.Occurrence = 0
		return parameterless.noParametersForValidation(reject)
	case OperationQuerySubsequence:
		if len(op.Indices) < evidenceProvenanceQueryMinIndices || len(op.Indices) > evidenceProvenanceQueryMaxIndices {
			return fmt.Errorf("query subsequence indices must contain 2..4 entries")
		}
		for index, value := range op.Indices {
			if value >= evidenceProvenanceQueryMaxValues {
				return fmt.Errorf("query subsequence index %d exceeds scanner limit", value)
			}
			if index > 0 && value <= op.Indices[index-1] {
				return fmt.Errorf("query subsequence indices must be strictly increasing")
			}
		}
		parameterless := op
		parameterless.Indices = nil
		return parameterless.noParametersForValidation(reject)
	case OperationEncodedRun:
		if op.MinimumLength == 0 {
			return fmt.Errorf("encoded run minimum_length must be positive")
		}
		parameterless := op
		parameterless.Occurrence = 0
		parameterless.MinimumLength = 0
		return parameterless.noParametersForValidation(reject)
	default:
		return fmt.Errorf("unknown operation %q", op.Kind)
	}
}

func (op Operation) noParametersForValidation(reject func(string) error) error {
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
	case op.Alphabet != "":
		return reject("alphabet")
	case len(op.Indices) != 0:
		return reject("indices")
	case op.MinimumLength != 0:
		return reject("minimum_length")
	default:
		return nil
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
	case ComponentRawQuery:
		return parsed.RawQuery, nil
	case ComponentQueryKey, ComponentQueryVal:
		if op.Selector == "" {
			return "", fmt.Errorf("query component: missing selector")
		}
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return "", fmt.Errorf("query parse: %w", err)
		}
		values, ok := query[op.Selector]
		if !ok || uint64(op.Occurrence) >= uint64(len(values)) {
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

func scannerQueryUnescape(value string, budget chargeBudget) (string, error) {
	for range evidenceProvenanceScannerMaxDecodeRounds {
		if err := budget.charge(value); err != nil {
			return "", err
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	return value, nil
}

func scannerBase64Encoding(alphabet string, padded bool) (*base64.Encoding, error) {
	var encoding *base64.Encoding
	switch alphabet {
	case "standard":
		encoding = base64.StdEncoding
	case "url":
		encoding = base64.URLEncoding
	default:
		return nil, fmt.Errorf("unknown base64 alphabet %q", alphabet)
	}
	if !padded {
		encoding = encoding.WithPadding(base64.NoPadding)
	}
	return encoding, nil
}

func scannerEncodedTokenNormalize(value, alphabet string) string {
	if len(value) < 4 {
		return ""
	}
	if alphabet == "hex" {
		value = strings.NewReplacer(`\x`, "", `\X`, "", "0x", "", "0X", "").Replace(value)
		value = strings.Map(func(r rune) rune {
			switch r {
			case ':', ' ', '-', ',':
				return -1
			default:
				return r
			}
		}, value)
		if len(value) == 0 || len(value)%2 != 0 {
			return ""
		}
		for _, char := range value {
			if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
				return ""
			}
		}
		return value
	}

	isData := func(char byte) bool {
		switch {
		case char >= 'A' && char <= 'Z':
			return true
		case char >= 'a' && char <= 'z':
			return alphabet != "base32"
		case char >= '0' && char <= '9':
			return alphabet != "base32" || char >= '2' && char <= '7'
		case char == '=':
			return true
		case char == '+' || char == '/':
			return alphabet == "base64_standard"
		case char == '-' || char == '_':
			return alphabet == "base64_url"
		default:
			return false
		}
	}
	isSeparator := func(char byte) bool {
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' || char == '\f' || char == '\v' || char == '.' {
			return true
		}
		switch alphabet {
		case "base64_standard":
			return char == '-' || char == '_'
		case "base64_url":
			return char == '/' || char == '+'
		case "base32":
			return char == '-' || char == '_' || char == '/'
		default:
			return false
		}
	}
	var result strings.Builder
	result.Grow(len(value))
	changed := false
	for index := range len(value) {
		char := value[index]
		switch {
		case isData(char):
			result.WriteByte(char)
		case isSeparator(char):
			changed = true
		default:
			return ""
		}
	}
	if !changed || result.Len() < 4 {
		return ""
	}
	return result.String()
}

func selectScannerTextSegment(value string, occurrence uint32) (string, error) {
	segments := strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case '/', '?', '&', '=', ' ', '\n', '\r', '\t', '"', '\'', '`', '{', '}', '[', ']', '(', ')', '<', '>', ':', ',', ';':
			return true
		default:
			return false
		}
	})
	if uint64(occurrence) >= uint64(len(segments)) {
		return "", fmt.Errorf("text segment: occurrence %d unavailable", occurrence)
	}
	return segments[occurrence], nil
}

func scannerHTMLEntityDecode(value string, budget chargeBudget) (string, error) {
	if !strings.Contains(value, "&") {
		return value, nil
	}
	for range evidenceProvenanceHTMLMaxDecodePasses {
		if err := budget.charge(value); err != nil {
			return "", err
		}
		decoded := html.UnescapeString(value)
		if decoded == value {
			break
		}
		value = decoded
	}
	return value, nil
}

func scannerWhitespaceCompact(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
}

func scannerURLNoiseStrip(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', '/', ' ', '\t', '\n', '\r', '+', ',', ';', '|':
			return -1
		default:
			return r
		}
	}, value)
}

func scannerOrderedQueryConcat(rawQuery string, budget chargeBudget) (string, error) {
	var result strings.Builder
	for _, pair := range strings.Split(rawQuery, "&") {
		_, value, _ := strings.Cut(pair, "=")
		if value != "" {
			decoded, err := scannerQueryUnescape(value, budget)
			if err != nil {
				return "", err
			}
			result.WriteString(decoded)
		}
	}
	return result.String(), nil
}

func scannerQuerySubsequence(rawQuery string, indices []uint8, budget chargeBudget) (string, error) {
	values := make([]string, 0, evidenceProvenanceQueryMaxValues)
	for _, pair := range strings.Split(rawQuery, "&") {
		_, value, _ := strings.Cut(pair, "=")
		if value != "" {
			decoded, err := scannerQueryUnescape(value, budget)
			if err != nil {
				return "", err
			}
			values = append(values, decoded)
			if len(values) == evidenceProvenanceQueryMaxValues {
				break
			}
		}
	}
	var result strings.Builder
	for _, index := range indices {
		if int(index) >= len(values) {
			return "", fmt.Errorf("query subsequence: index %d unavailable", index)
		}
		result.WriteString(values[index])
	}
	return result.String(), nil
}

func selectScannerEncodedRun(value string, occurrence, minimumLength uint32) (string, error) {
	runs := make([]string, 0)
	start := -1
	for index := 0; index < len(value); index++ {
		char := value[index]
		inAlphabet := (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') || char == '+' || char == '/' || char == '-' || char == '_'
		if inAlphabet {
			if start < 0 {
				start = index
			}
			continue
		}
		if start >= 0 {
			end := index
			for pad := 0; pad < 2 && end < len(value) && value[end] == '='; pad++ {
				end++
			}
			if int64(end-start) >= int64(minimumLength) {
				runs = append(runs, value[start:end])
			}
		}
		start = -1
	}
	if start >= 0 && int64(len(value)-start) >= int64(minimumLength) {
		runs = append(runs, value[start:])
	}
	if uint64(occurrence) >= uint64(len(runs)) {
		return "", fmt.Errorf("encoded run: occurrence %d unavailable", occurrence)
	}
	return runs[occurrence], nil
}

func scannerCanaryCanonicalize(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', '/', '\\', '?', '&', '=', ' ', '\t', '\n', '\r', ':', ';', ',', '-', '_', '@', '%', '+', '#':
			return -1
		default:
			return r
		}
	}, value)
}
