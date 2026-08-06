// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const provenanceTestDigest = EvidenceProvenanceProfileV1Digest

func TestQueryIndicesJSONWireShape(t *testing.T) {
	operation := Operation{Kind: OperationQuerySubsequence, Indices: QueryIndices{0, 2}}
	encoded, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"kind":"query_subsequence","indices":[0,2]}`; got != want {
		t.Fatalf("Marshal() = %s, want %s", got, want)
	}

	var decoded Operation
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decoded.Indices, operation.Indices) {
		t.Fatalf("Unmarshal() indices = %v, want %v", decoded.Indices, operation.Indices)
	}
	if err := json.Unmarshal([]byte(`{"kind":"query_subsequence","indices":"AAI="}`), &decoded); err == nil {
		t.Fatal("Unmarshal() accepted the legacy base64 string instead of array<uint8>")
	}
	err = json.Unmarshal([]byte(`{"kind":"query_subsequence","indices":[0,300]}`), &decoded)
	if err == nil || !strings.Contains(err.Error(), "exceeds uint8") {
		t.Fatalf("Unmarshal() out-of-range index error = %v, want a uint8 range rejection", err)
	}
}

func TestRecipeApplyOperations(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		op    Operation
		want  string
	}{
		{"identity", "MiXeD", Operation{Kind: OperationIdentity}, "MiXeD"},
		{"URL", "https://api.vendor.example/a%20b?q=first&q=second", Operation{Kind: OperationURLComponent, Component: ComponentURL}, "https://api.vendor.example/a%20b?q=first&q=second"},
		{"hostname", "https://api.vendor.example/a", Operation{Kind: OperationURLComponent, Component: ComponentHostname}, "api.vendor.example"},
		{"path", "https://api.vendor.example/a%20b", Operation{Kind: OperationURLComponent, Component: ComponentPath}, "/a%20b"},
		{"query key", "https://api.vendor.example/a?marker=first", Operation{Kind: OperationURLComponent, Component: ComponentQueryKey, Selector: "marker"}, "marker"},
		{"query value occurrence", "https://api.vendor.example/a?marker=first&marker=second", Operation{Kind: OperationURLComponent, Component: ComponentQueryVal, Selector: "marker", Occurrence: 1}, "second"},
		{"raw query", "https://api.vendor.example/a?first=x%2521&second=y+z", Operation{Kind: OperationURLComponent, Component: ComponentRawQuery}, "first=x%2521&second=y+z"},
		{"percent decode", "%2520", Operation{Kind: OperationPercentDecode, Passes: 2}, " "},
		{"DLP normalize", "s\u200becret", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1"}, ForDLP("s\u200becret")},
		{"lowercase", "MiXeD", Operation{Kind: OperationLowercase}, "mixed"},
		{"invisible strip", "s\u200becret", Operation{Kind: OperationInvisibleStrip}, "secret"},
		{"hex decode", "6869", Operation{Kind: OperationHexDecode}, "hi"},
		{"base32 padded", base32.StdEncoding.EncodeToString([]byte("hi")), Operation{Kind: OperationBase32Decode, DecodePadding: true}, "hi"},
		{"base32 raw", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("hi")), Operation{Kind: OperationBase32Decode}, "hi"},
		{"base64 padded", base64.StdEncoding.EncodeToString([]byte("hi")), Operation{Kind: OperationBase64Decode, DecodePadding: true}, "hi"},
		{"base64 raw", base64.RawStdEncoding.EncodeToString([]byte("hi")), Operation{Kind: OperationBase64Decode}, "hi"},
		{"leetspeak", "s3cr3t", Operation{Kind: OperationLeetspeak}, Leetspeak("s3cr3t")},
		{"vowel fold", "sëcrêt", Operation{Kind: OperationVowelFold}, FoldVowels("sëcrêt")},
		{"query unescape", "a+b%2521", Operation{Kind: OperationQueryUnescape}, "a b!"},
		{"query unescape preserves last good value", "%25zz", Operation{Kind: OperationQueryUnescape}, "%zz"},
		{"invisible space", "a\u200bb", Operation{Kind: OperationInvisibleSpace}, "a b"},
		{"matching normalize", "Ａ\u200bB\u00a0C", Operation{Kind: OperationMatchingNormalize, Profile: "pipelock-matching-v1"}, "AB C"},
		{"liberal hex", "4A", Operation{Kind: OperationHexDecodeLiberal}, "J"},
		{"liberal base32", "MZ======", Operation{Kind: OperationBase32DecodeLiberal, DecodePadding: true}, "f"},
		{"liberal raw base32", "MY", Operation{Kind: OperationBase32DecodeLiberal}, "f"},
		{"liberal base64", "Zh==", Operation{Kind: OperationBase64DecodeLiberal, Alphabet: "standard", DecodePadding: true}, "f"},
		{"liberal raw base64", "Zg", Operation{Kind: OperationBase64DecodeLiberal, Alphabet: "standard"}, "f"},
		{"liberal URL base64", "4KC-", Operation{Kind: OperationBase64DecodeLiberal, Alphabet: "url"}, "࠾"},
		{"encoded hex token normalize", `\x48 \x69`, Operation{Kind: OperationEncodedTokenNormalize, Alphabet: "hex"}, "4869"},
		{"encoded standard base64 token normalize", "S G.k=", Operation{Kind: OperationEncodedTokenNormalize, Alphabet: "base64_standard"}, "SGk="},
		{"encoded URL base64 token normalize", "4K/C-", Operation{Kind: OperationEncodedTokenNormalize, Alphabet: "base64_url"}, "4KC-"},
		{"encoded base32 token normalize", "J B/UQ====", Operation{Kind: OperationEncodedTokenNormalize, Alphabet: "base32"}, "JBUQ===="},
		{"ineligible encoded token", "abc", Operation{Kind: OperationEncodedTokenNormalize, Alphabet: "base32"}, ""},
		{"text segment", "pre https://host/path,tail", Operation{Kind: OperationTextSegment, Occurrence: 3}, "path"},
		{"HTML entity decode", "&amp;amp;", Operation{Kind: OperationHTMLEntityDecode}, "&"},
		{"whitespace compact", "a\u2003 b\n", Operation{Kind: OperationWhitespaceCompact}, "ab"},
		{"URL noise strip", "a./ +,;|\tb", Operation{Kind: OperationURLNoiseStrip}, "ab"},
		{"ordered query concat", "a=x%2521&empty=&b=y+z", Operation{Kind: OperationOrderedQueryConcat}, "x!y z"},
		{"query subsequence", "a=one&b=junk&c=two&d=three", Operation{Kind: OperationQuerySubsequence, Indices: QueryIndices{0, 2, 3}}, "onetwothree"},
		{"hostname dot remove", "api.vendor.example", Operation{Kind: OperationHostnameDotRemove}, "apivendorexample"},
		{"encoded run", "prefix:QUJDRA== suffix", Operation{Kind: OperationEncodedRun, Occurrence: 1, MinimumLength: 6}, "QUJDRA=="},
		{"canary canonicalize", "Ab-c_d/e?f", Operation{Kind: OperationCanaryCanonicalize}, "Abcdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{tc.op}}).Apply(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("Apply() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRecipeApplyRejectsInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		recipe Recipe
		input  string
		want   string
	}{
		{"invalid UTF-8", Recipe{TransformProfileDigest: provenanceTestDigest}, string([]byte{0xff}), "recipe input: invalid UTF-8"},
		{"missing profile", Recipe{}, "value", "missing transform profile digest"},
		{"malformed profile", Recipe{TransformProfileDigest: "sha256:bad"}, "value", "invalid SHA-256 digest"},
		{"unknown profile", Recipe{TransformProfileDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "value", "unknown profile"},
		{"unknown operation", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: "unknown"}}}, "value", "unknown operation"},
		{"invalid URL", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationURLComponent, Component: ComponentURL}}}, "://", "invalid absolute URL"},
		{"unknown URL component", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationURLComponent, Component: "unknown"}}}, "https://api.vendor.example", "unknown URL component"},
		{"missing query selector", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationURLComponent, Component: ComponentQueryVal}}}, "https://api.vendor.example", "missing selector"},
		{"missing query occurrence", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationURLComponent, Component: ComponentQueryVal, Selector: "missing"}}}, "https://api.vendor.example", "occurrence 0 unavailable"},
		{"zero percent passes", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationPercentDecode}}}, "value", "passes must be 1..4"},
		{"excess percent passes", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationPercentDecode, Passes: 5}}}, "value", "passes must be 1..4"},
		{"malformed percent encoding", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationPercentDecode, Passes: 1}}}, "%zz", "percent decode"},
		{"percent output invalid UTF-8", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationPercentDecode, Passes: 1}}}, "%ff", "output: invalid UTF-8"},
		{"percent output invalid UTF-8 before Unicode transform", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationPercentDecode, Passes: 1}, {Kind: OperationLowercase}}}, "%ff", "output: invalid UTF-8"},
		{"unknown DLP profile", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationDLPNormalize, Profile: "unknown"}}}, "value", "unknown DLP profile"},
		{"malformed hex", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationHexDecode}}}, "z", "hex decode"},
		{"non-UTF-8 hex", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationHexDecode}}}, "ff", "hex decode output: invalid UTF-8"},
		{"non-canonical hex", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationHexDecode}}}, "4A", "hex decode: non-canonical encoding"},
		{"malformed base32", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase32Decode, DecodePadding: true}}}, "!", "base32 decode"},
		{"non-UTF-8 base32", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase32Decode, DecodePadding: true}}}, base32.StdEncoding.EncodeToString([]byte{0xff}), "base32 decode output: invalid UTF-8"},
		{"non-canonical padded base32", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase32Decode, DecodePadding: true}}}, "MZ======", "base32 decode: non-canonical encoding"},
		{"non-canonical raw base32", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase32Decode}}}, "MZ", "base32 decode: non-canonical encoding"},
		{"malformed base64", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase64Decode, DecodePadding: true}}}, "!", "base64 decode"},
		{"non-UTF-8 base64", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase64Decode, DecodePadding: true}}}, base64.StdEncoding.EncodeToString([]byte{0xff}), "base64 decode output: invalid UTF-8"},
		{"non-canonical padded base64", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase64Decode, DecodePadding: true}}}, "Zh==", "base64 decode: non-canonical encoding"},
		{"non-canonical raw base64", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase64Decode}}}, "Zh", "base64 decode: non-canonical encoding"},
		{"malformed liberal hex", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationHexDecodeLiberal}}}, "z", "liberal hex decode"},
		{"liberal hex invalid UTF-8", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationHexDecodeLiberal}}}, "ff", "output: invalid UTF-8"},
		{"malformed liberal base32", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase32DecodeLiberal, DecodePadding: true}}}, "!", "liberal base32 decode"},
		{"malformed liberal base64", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationBase64DecodeLiberal, Alphabet: "standard", DecodePadding: true}}}, "!", "liberal base64 decode"},
		{"missing text segment", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationTextSegment, Occurrence: 2}}}, "one/two", "occurrence 2 unavailable"},
		{"missing query subsequence value", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationQuerySubsequence, Indices: QueryIndices{0, 2}}}}, "a=one&b=two", "index 2 unavailable"},
		{"missing encoded run", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationEncodedRun, MinimumLength: 8}}}, "short", "occurrence 0 unavailable"},
		{"huge query occurrence", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationURLComponent, Component: ComponentQueryVal, Selector: "q", Occurrence: ^uint32(0)}}}, "https://api.vendor.example/?q=value", "occurrence 4294967295 unavailable"},
		{"huge text occurrence", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationTextSegment, Occurrence: ^uint32(0)}}}, "one/two", "occurrence 4294967295 unavailable"},
		{"huge encoded run occurrence", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationEncodedRun, Occurrence: ^uint32(0), MinimumLength: 4}}}, "QUJD", "occurrence 4294967295 unavailable"},
		{"identity rejects component", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationIdentity, Component: ComponentPath}}}, "value", "unsupported component"},
		{"lowercase rejects selector", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationLowercase, Selector: "ignored"}}}, "value", "unsupported selector"},
		{"URL rejects passes", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationURLComponent, Component: ComponentURL, Passes: 1}}}, "https://api.vendor.example", "unsupported passes"},
		{"percent rejects profile", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationPercentDecode, Passes: 1, Profile: "ignored"}}}, "value", "unsupported profile"},
		{"DLP rejects occurrence", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Occurrence: 1}}}, "value", "unsupported occurrence"},
		{"decoder rejects selector", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationHexDecode, Selector: "ignored"}}}, "6869", "unsupported selector"},
		{"malformed query encoding", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationURLComponent, Component: ComponentQueryVal, Selector: "marker"}}}, "https://api.vendor.example/?marker=ok&broken=%zz", "query parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.recipe.Apply(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRecipeApplyProfileByteLimits(t *testing.T) {
	tooLargeInput := strings.Repeat("x", evidenceProvenanceProfileMaxInputBytes+1)
	tooLargeOutput := strings.Repeat("x", evidenceProvenanceProfileMaxOutputBytes+1)
	for _, tc := range []struct {
		name   string
		recipe Recipe
		input  string
		want   string
	}{
		{"input", Recipe{TransformProfileDigest: provenanceTestDigest}, tooLargeInput, "input: exceeds profile byte limit"},
		{"output after operation", Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationIdentity}}}, tooLargeOutput, "output exceeds profile byte limit"},
		{"output with zero operations", Recipe{TransformProfileDigest: provenanceTestDigest}, tooLargeOutput, "output exceeds profile byte limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.recipe.Apply(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestOperationValidateRejectsControlCharacters(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   Operation
		want string
	}{
		{"selector", Operation{Kind: OperationURLComponent, Component: ComponentQueryVal, Selector: "marker\n"}, "selector for url_component contains control character"},
		{"profile", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1\t"}, "profile for dlp_normalize contains control character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.op.validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestTransformProfileV1DigestMatchesCanonicalDocument(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "sdk", "conformance", "testdata", "transform-profile", "evidence-provenance-transform-v1.json"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != EvidenceProvenanceProfileV1Digest {
		t.Fatalf("canonical evidence provenance transform profile digest = %q, want %q", got, EvidenceProvenanceProfileV1Digest)
	}
	var profile struct {
		Format              string `json:"format"`
		Profile             string `json:"profile"`
		Version             int    `json:"version"`
		OperationVocabulary []struct {
			Kind string `json:"kind"`
		} `json:"operation_vocabulary"`
		Limits struct {
			MaxDecodePasses               int `json:"max_decode_passes"`
			ScannerQueryUnescapeMaxRounds int `json:"scanner_query_unescape_max_rounds"`
			HTMLEntityDecodeMaxPasses     int `json:"html_entity_decode_max_passes"`
			QuerySubsequenceMaxValues     int `json:"query_subsequence_max_values"`
			QuerySubsequenceMinSize       int `json:"query_subsequence_min_size"`
			QuerySubsequenceMaxSize       int `json:"query_subsequence_max_size"`
			MaxOperations                 int `json:"max_operations"`
			MaxCumulativeProcessedBytes   int `json:"max_cumulative_processed_bytes"`
			MaxInputBytes                 int `json:"max_input_bytes"`
			MaxOutputBytes                int `json:"max_output_bytes"`
		} `json:"limits"`
		Normalization struct {
			DLPNormalize struct {
				ConfusableToASCII struct {
					SingleCodePoints map[string]string `json:"single_code_points"`
					SequentialRanges []struct {
						From    string `json:"from"`
						To      string `json:"to"`
						Outputs string `json:"outputs"`
					} `json:"sequential_ranges"`
				} `json:"confusable_to_ascii"`
			} `json:"dlp_normalize"`
		} `json:"normalization"`
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("decode evidence provenance transform profile: %v", err)
	}
	if profile.Format != "pipelock-evidence-provenance-transform-profile/v1" || profile.Profile != "pipelock-evidence-provenance-transform-v1" || profile.Version != 1 {
		t.Fatalf("profile identity = format %q profile %q version %d", profile.Format, profile.Profile, profile.Version)
	}
	if profile.Limits.MaxDecodePasses != evidenceProvenanceProfileMaxDecodePasses || profile.Limits.MaxInputBytes != evidenceProvenanceProfileMaxInputBytes || profile.Limits.MaxOutputBytes != evidenceProvenanceProfileMaxOutputBytes {
		t.Fatalf("profile limits = decode passes %d, input %d, output %d; Go = decode passes %d, input %d, output %d", profile.Limits.MaxDecodePasses, profile.Limits.MaxInputBytes, profile.Limits.MaxOutputBytes, evidenceProvenanceProfileMaxDecodePasses, evidenceProvenanceProfileMaxInputBytes, evidenceProvenanceProfileMaxOutputBytes)
	}
	if profile.Limits.MaxOperations != evidenceProvenanceMaxOperations || profile.Limits.MaxCumulativeProcessedBytes != evidenceProvenanceMaxTotalBytes {
		t.Fatalf("profile execution limits = operations %d, cumulative bytes %d; Go = operations %d, cumulative bytes %d", profile.Limits.MaxOperations, profile.Limits.MaxCumulativeProcessedBytes, evidenceProvenanceMaxOperations, evidenceProvenanceMaxTotalBytes)
	}
	if profile.Limits.ScannerQueryUnescapeMaxRounds != evidenceProvenanceScannerMaxDecodeRounds || profile.Limits.HTMLEntityDecodeMaxPasses != evidenceProvenanceHTMLMaxDecodePasses {
		t.Fatalf("scanner decode limits = query %d HTML %d; Go = query %d HTML %d", profile.Limits.ScannerQueryUnescapeMaxRounds, profile.Limits.HTMLEntityDecodeMaxPasses, evidenceProvenanceScannerMaxDecodeRounds, evidenceProvenanceHTMLMaxDecodePasses)
	}
	if profile.Limits.QuerySubsequenceMaxValues != evidenceProvenanceQueryMaxValues || profile.Limits.QuerySubsequenceMinSize != evidenceProvenanceQueryMinIndices || profile.Limits.QuerySubsequenceMaxSize != evidenceProvenanceQueryMaxIndices {
		t.Fatalf("query subsequence limits = values %d size %d..%d; Go = values %d size %d..%d", profile.Limits.QuerySubsequenceMaxValues, profile.Limits.QuerySubsequenceMinSize, profile.Limits.QuerySubsequenceMaxSize, evidenceProvenanceQueryMaxValues, evidenceProvenanceQueryMinIndices, evidenceProvenanceQueryMaxIndices)
	}
	gotKinds := make([]OperationKind, 0, len(profile.OperationVocabulary))
	for _, operation := range profile.OperationVocabulary {
		gotKinds = append(gotKinds, OperationKind(operation.Kind))
	}
	if !slices.Equal(gotKinds, SupportedOperationKinds()) {
		t.Fatalf("profile operation vocabulary = %v, want %v", gotKinds, SupportedOperationKinds())
	}
	if !maps.Equal(profileConfusableToASCII(t, profile.Normalization.DLPNormalize.ConfusableToASCII.SingleCodePoints, profile.Normalization.DLPNormalize.ConfusableToASCII.SequentialRanges), confusableMap) {
		t.Fatal("profile confusable-to-ASCII mapping differs from Go")
	}
}

func profileConfusableToASCII(t *testing.T, singleCodePoints map[string]string, sequentialRanges []struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Outputs string `json:"outputs"`
},
) map[rune]rune {
	t.Helper()
	result := make(map[rune]rune, len(singleCodePoints))
	for input, output := range singleCodePoints {
		inputRune := profileCodePoint(t, input)
		outputRunes := []rune(output)
		if len(outputRunes) != 1 {
			t.Fatalf("profile mapping %q output %q is not one rune", input, output)
		}
		result[inputRune] = outputRunes[0]
	}
	for _, sequentialRange := range sequentialRanges {
		start := profileCodePoint(t, sequentialRange.From)
		end := profileCodePoint(t, sequentialRange.To)
		outputs := []rune(sequentialRange.Outputs)
		if end < start || len(outputs) != int(end-start+1) {
			t.Fatalf("profile sequential range %q-%q has %d outputs", sequentialRange.From, sequentialRange.To, len(outputs))
		}
		for index, output := range outputs {
			result[start+rune(index)] = output
		}
	}
	return result
}

func profileCodePoint(t *testing.T, value string) rune {
	t.Helper()
	if !strings.HasPrefix(value, "U+") {
		t.Fatalf("profile code point %q lacks U+ prefix", value)
	}
	parsed, err := strconv.ParseInt(strings.TrimPrefix(value, "U+"), 16, 32)
	if err != nil || parsed > utf8.MaxRune {
		t.Fatalf("profile code point %q: %v", value, err)
	}
	return rune(parsed)
}

func TestRecipeValidateOutput(t *testing.T) {
	valid := Recipe{TransformProfileDigest: provenanceTestDigest, Operations: []Operation{{Kind: OperationIdentity}}}
	for _, tc := range []struct {
		name   string
		recipe Recipe
		value  string
		want   string
	}{
		{"valid", valid, "view", ""},
		{"invalid recipe", Recipe{}, "view", "missing transform profile digest"},
		{"invalid UTF-8", valid, string([]byte{0xff}), "output: invalid UTF-8"},
		{"over-limit", valid, strings.Repeat("x", evidenceProvenanceProfileMaxOutputBytes+1), "output exceeds profile byte limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.recipe.ValidateOutput(tc.value)
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestOperationValidateParameterShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   Operation
		want string
	}{
		{"identity parameters", Operation{Kind: OperationIdentity, Occurrence: 1}, "unsupported occurrence"},
		{"lowercase parameters", Operation{Kind: OperationLowercase, Passes: 1}, "unsupported passes"},
		{"invisible strip parameters", Operation{Kind: OperationInvisibleStrip, Profile: "x"}, "unsupported profile"},
		{"leetspeak parameters", Operation{Kind: OperationLeetspeak, DecodePadding: true}, "unsupported decode_padding"},
		{"vowel fold parameters", Operation{Kind: OperationVowelFold, Component: ComponentPath}, "unsupported component"},
		{"URL passes", Operation{Kind: OperationURLComponent, Component: ComponentPath, Passes: 1}, "unsupported passes"},
		{"URL profile", Operation{Kind: OperationURLComponent, Component: ComponentPath, Profile: "x"}, "unsupported profile"},
		{"URL padding", Operation{Kind: OperationURLComponent, Component: ComponentPath, DecodePadding: true}, "unsupported decode_padding"},
		{"URL alphabet", Operation{Kind: OperationURLComponent, Component: ComponentPath, Alphabet: "url"}, "unsupported alphabet"},
		{"URL indices", Operation{Kind: OperationURLComponent, Component: ComponentPath, Indices: QueryIndices{0, 1}}, "unsupported indices"},
		{"URL minimum length", Operation{Kind: OperationURLComponent, Component: ComponentPath, MinimumLength: 8}, "unsupported minimum_length"},
		{"URL selector", Operation{Kind: OperationURLComponent, Component: ComponentPath, Selector: "marker"}, "unsupported selector"},
		{"URL occurrence", Operation{Kind: OperationURLComponent, Component: ComponentPath, Occurrence: 1}, "unsupported occurrence"},
		{"percent component", Operation{Kind: OperationPercentDecode, Passes: 1, Component: ComponentPath}, "unsupported component"},
		{"percent selector", Operation{Kind: OperationPercentDecode, Passes: 1, Selector: "marker"}, "unsupported selector"},
		{"percent occurrence", Operation{Kind: OperationPercentDecode, Passes: 1, Occurrence: 1}, "unsupported occurrence"},
		{"percent alphabet", Operation{Kind: OperationPercentDecode, Passes: 1, Alphabet: "url"}, "unsupported alphabet"},
		{"percent indices", Operation{Kind: OperationPercentDecode, Passes: 1, Indices: QueryIndices{0, 1}}, "unsupported indices"},
		{"percent minimum length", Operation{Kind: OperationPercentDecode, Passes: 1, MinimumLength: 8}, "unsupported minimum_length"},
		{"DLP passes", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Passes: 1}, "unsupported passes"},
		{"DLP component", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Component: ComponentPath}, "unsupported component"},
		{"DLP selector", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Selector: "marker"}, "unsupported selector"},
		{"DLP occurrence", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Occurrence: 1}, "unsupported occurrence"},
		{"DLP padding", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", DecodePadding: true}, "unsupported decode_padding"},
		{"DLP alphabet", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Alphabet: "url"}, "unsupported alphabet"},
		{"DLP indices", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Indices: QueryIndices{0, 1}}, "unsupported indices"},
		{"DLP minimum length", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", MinimumLength: 8}, "unsupported minimum_length"},
		{"decoder padding is valid", Operation{Kind: OperationBase64Decode, DecodePadding: true}, ""},
		{"hex rejects padding", Operation{Kind: OperationHexDecode, DecodePadding: true}, "unsupported decode_padding"},
		{"decoder component", Operation{Kind: OperationHexDecode, Component: ComponentPath}, "unsupported component"},
		{"decoder selector", Operation{Kind: OperationHexDecode, Selector: "marker"}, "unsupported selector"},
		{"decoder occurrence", Operation{Kind: OperationHexDecode, Occurrence: 1}, "unsupported occurrence"},
		{"decoder passes", Operation{Kind: OperationHexDecode, Passes: 1}, "unsupported passes"},
		{"decoder profile", Operation{Kind: OperationHexDecode, Profile: "x"}, "unsupported profile"},
		{"decoder alphabet", Operation{Kind: OperationBase64Decode, Alphabet: "url"}, "unsupported alphabet"},
		{"decoder indices", Operation{Kind: OperationBase64Decode, Indices: QueryIndices{0, 1}}, "unsupported indices"},
		{"decoder minimum length", Operation{Kind: OperationBase64Decode, MinimumLength: 8}, "unsupported minimum_length"},
		{"new no-param component", Operation{Kind: OperationQueryUnescape, Component: ComponentPath}, "unsupported component"},
		{"new no-param selector", Operation{Kind: OperationQueryUnescape, Selector: "marker"}, "unsupported selector"},
		{"new no-param occurrence", Operation{Kind: OperationQueryUnescape, Occurrence: 1}, "unsupported occurrence"},
		{"new no-param passes", Operation{Kind: OperationQueryUnescape, Passes: 1}, "unsupported passes"},
		{"new no-param profile", Operation{Kind: OperationQueryUnescape, Profile: "x"}, "unsupported profile"},
		{"new no-param padding", Operation{Kind: OperationQueryUnescape, DecodePadding: true}, "unsupported decode_padding"},
		{"new no-param alphabet", Operation{Kind: OperationQueryUnescape, Alphabet: "url"}, "unsupported alphabet"},
		{"new no-param indices", Operation{Kind: OperationQueryUnescape, Indices: QueryIndices{0, 1}}, "unsupported indices"},
		{"new no-param minimum length", Operation{Kind: OperationQueryUnescape, MinimumLength: 8}, "unsupported minimum_length"},
		{"identity alphabet", Operation{Kind: OperationIdentity, Alphabet: "url"}, "unsupported alphabet"},
		{"identity indices", Operation{Kind: OperationIdentity, Indices: QueryIndices{0, 1}}, "unsupported indices"},
		{"identity minimum length", Operation{Kind: OperationIdentity, MinimumLength: 8}, "unsupported minimum_length"},
		{"matching profile", Operation{Kind: OperationMatchingNormalize, Profile: "unknown"}, "unknown matching profile"},
		{"liberal base64 alphabet", Operation{Kind: OperationBase64DecodeLiberal, Alphabet: "unknown"}, "unknown base64 alphabet"},
		{"encoded token alphabet", Operation{Kind: OperationEncodedTokenNormalize, Alphabet: "unknown"}, "unknown encoded-token alphabet"},
		{"query subsequence too short", Operation{Kind: OperationQuerySubsequence, Indices: QueryIndices{0}}, "2..4"},
		{"query subsequence unordered", Operation{Kind: OperationQuerySubsequence, Indices: QueryIndices{1, 1}}, "strictly increasing"},
		{"query subsequence out of range", Operation{Kind: OperationQuerySubsequence, Indices: QueryIndices{0, 20}}, "exceeds scanner limit"},
		{"encoded run missing minimum", Operation{Kind: OperationEncodedRun}, "minimum_length must be positive"},
		{"matching normalize rejects alphabet", Operation{Kind: OperationMatchingNormalize, Profile: "pipelock-matching-v1", Alphabet: "url"}, "unsupported alphabet"},
		{"liberal base32 rejects occurrence", Operation{Kind: OperationBase32DecodeLiberal, Occurrence: 1}, "unsupported occurrence"},
		{"liberal base64 rejects indices", Operation{Kind: OperationBase64DecodeLiberal, Alphabet: "standard", Indices: QueryIndices{0, 1}}, "unsupported indices"},
		{"encoded token rejects padding", Operation{Kind: OperationEncodedTokenNormalize, Alphabet: "hex", DecodePadding: true}, "unsupported decode_padding"},
		{"text segment rejects selector", Operation{Kind: OperationTextSegment, Selector: "marker"}, "unsupported selector"},
		{"query subsequence rejects minimum", Operation{Kind: OperationQuerySubsequence, Indices: QueryIndices{0, 1}, MinimumLength: 8}, "unsupported minimum_length"},
		{"encoded run rejects alphabet", Operation{Kind: OperationEncodedRun, MinimumLength: 6, Alphabet: "hex"}, "unsupported alphabet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.op.validate()
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSupportedOperationKinds(t *testing.T) {
	got := SupportedOperationKinds()
	want := []OperationKind{
		OperationIdentity,
		OperationURLComponent,
		OperationPercentDecode,
		OperationDLPNormalize,
		OperationLowercase,
		OperationInvisibleStrip,
		OperationHexDecode,
		OperationBase32Decode,
		OperationBase64Decode,
		OperationLeetspeak,
		OperationVowelFold,
		OperationQueryUnescape,
		OperationInvisibleSpace,
		OperationMatchingNormalize,
		OperationHexDecodeLiberal,
		OperationBase32DecodeLiberal,
		OperationBase64DecodeLiberal,
		OperationEncodedTokenNormalize,
		OperationTextSegment,
		OperationHTMLEntityDecode,
		OperationWhitespaceCompact,
		OperationURLNoiseStrip,
		OperationOrderedQueryConcat,
		OperationQuerySubsequence,
		OperationHostnameDotRemove,
		OperationEncodedRun,
		OperationCanaryCanonicalize,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("SupportedOperationKinds() = %v, want %v", got, want)
	}
}

// TestRecipeExecutionBudgetsRejectUnboundedWork pins the two limits that bound
// verifier cost for an externally supplied receipt. Per-operation input and
// output caps do not constrain total work when the attacker chooses how many
// operations run, and provenance verification is performed against untrusted
// receipts during incident review, so an unbounded recipe is an availability
// attack on the audit path rather than a theoretical concern.
func TestRecipeExecutionBudgetsRejectUnboundedWork(t *testing.T) {
	t.Parallel()

	// Keep this normative value independent of the implementation constants so
	// neutralizing a guard makes the test fail instead of moving its own target.
	const profileMaxOperations = 32
	identity := Operation{Kind: OperationIdentity}

	t.Run("operation count is capped", func(t *testing.T) {
		t.Parallel()
		operations := make([]Operation, profileMaxOperations+1)
		for i := range operations {
			operations[i] = identity
		}
		recipe := Recipe{TransformProfileDigest: EvidenceProvenanceProfileV1Digest, Operations: operations}
		if err := recipe.Validate(); err == nil {
			t.Fatal("recipe validation accepted an operation count that commitment reconstruction must reject")
		}
		if _, err := recipe.Apply("value"); err == nil {
			t.Fatal("recipe exceeding the operation cap was accepted")
		}
	})

	t.Run("repeated internal passes consume the same budget", func(t *testing.T) {
		t.Parallel()
		// One deeply nested token stays under the 2 MiB input cap, but each
		// QueryUnescape round reprocesses almost all of it. Charging only once
		// at operation dispatch would incorrectly accept this verifier DoS.
		token := "%" + strings.Repeat("25", evidenceProvenanceScannerMaxDecodeRounds)
		input := strings.Repeat(token, 1500)
		recipe := Recipe{TransformProfileDigest: EvidenceProvenanceProfileV1Digest, Operations: []Operation{{Kind: OperationQueryUnescape}}}
		if _, err := recipe.Apply(input); err == nil || !strings.Contains(err.Error(), "cumulative processing budget") {
			t.Fatalf("repeated decode budget error = %v", err)
		}
	})

	t.Run("cap boundary is inclusive", func(t *testing.T) {
		t.Parallel()
		operations := make([]Operation, profileMaxOperations)
		for i := range operations {
			operations[i] = identity
		}
		recipe := Recipe{TransformProfileDigest: EvidenceProvenanceProfileV1Digest, Operations: operations}
		if _, err := recipe.Apply("value"); err != nil {
			t.Fatalf("recipe at exactly the operation cap was rejected: %v", err)
		}
	})

	t.Run("cumulative budget is charged across operations", func(t *testing.T) {
		t.Parallel()
		// Each pass re-reads a large intermediate value. No single operation
		// exceeds the per-output cap, but together they must exhaust the budget.
		operations := make([]Operation, profileMaxOperations)
		for i := range operations {
			operations[i] = identity
		}
		recipe := Recipe{TransformProfileDigest: EvidenceProvenanceProfileV1Digest, Operations: operations}
		large := strings.Repeat("a", 1<<20)
		if _, err := recipe.Apply(large); err == nil {
			t.Fatal("recipe exhausting the cumulative budget was accepted")
		}
	})
}

func TestRecipeApplyWithinBudgetDistinguishesBudgetFailures(t *testing.T) {
	t.Parallel()
	recipe := Recipe{
		TransformProfileDigest: EvidenceProvenanceProfileV1Digest,
		Operations:             []Operation{{Kind: OperationIdentity}, {Kind: OperationIdentity}},
	}
	value, charged, err := recipe.ApplyWithinBudget("value", 10)
	if err != nil || value != "value" || charged != 10 {
		t.Fatalf("successful shared budget = value %q, charged %d, err %v", value, charged, err)
	}

	_, charged, err = recipe.ApplyWithinBudget("value", -1)
	if !errors.Is(err, ErrEvidenceProvenanceFixtureProcessingBudget) || errors.Is(err, ErrEvidenceProvenanceProcessingBudget) || charged != 0 {
		t.Fatalf("fixture budget error = charged %d, err %v", charged, err)
	}

	large := strings.Repeat("a", 1<<20)
	operations := make([]Operation, 17)
	for index := range operations {
		operations[index] = Operation{Kind: OperationIdentity}
	}
	perRecipe := Recipe{TransformProfileDigest: EvidenceProvenanceProfileV1Digest, Operations: operations}
	_, charged, err = perRecipe.ApplyWithinBudget(large, evidenceProvenanceMaxTotalBytes)
	if !errors.Is(err, ErrEvidenceProvenanceProcessingBudget) || errors.Is(err, ErrEvidenceProvenanceFixtureProcessingBudget) || charged != evidenceProvenanceMaxTotalBytes {
		t.Fatalf("per-recipe budget error = charged %d, err %v", charged, err)
	}
}
