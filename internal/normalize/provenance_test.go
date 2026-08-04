// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
			MaxDecodePasses int `json:"max_decode_passes"`
			MaxInputBytes   int `json:"max_input_bytes"`
			MaxOutputBytes  int `json:"max_output_bytes"`
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
		{"URL selector", Operation{Kind: OperationURLComponent, Component: ComponentPath, Selector: "marker"}, "unsupported selector"},
		{"URL occurrence", Operation{Kind: OperationURLComponent, Component: ComponentPath, Occurrence: 1}, "unsupported occurrence"},
		{"percent component", Operation{Kind: OperationPercentDecode, Passes: 1, Component: ComponentPath}, "unsupported component"},
		{"percent selector", Operation{Kind: OperationPercentDecode, Passes: 1, Selector: "marker"}, "unsupported selector"},
		{"percent occurrence", Operation{Kind: OperationPercentDecode, Passes: 1, Occurrence: 1}, "unsupported occurrence"},
		{"DLP passes", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Passes: 1}, "unsupported passes"},
		{"DLP component", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Component: ComponentPath}, "unsupported component"},
		{"DLP selector", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Selector: "marker"}, "unsupported selector"},
		{"DLP occurrence", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", Occurrence: 1}, "unsupported occurrence"},
		{"DLP padding", Operation{Kind: OperationDLPNormalize, Profile: "pipelock-dlp-v1", DecodePadding: true}, "unsupported decode_padding"},
		{"decoder padding is valid", Operation{Kind: OperationBase64Decode, DecodePadding: true}, ""},
		{"hex rejects padding", Operation{Kind: OperationHexDecode, DecodePadding: true}, "unsupported decode_padding"},
		{"decoder component", Operation{Kind: OperationHexDecode, Component: ComponentPath}, "unsupported component"},
		{"decoder selector", Operation{Kind: OperationHexDecode, Selector: "marker"}, "unsupported selector"},
		{"decoder occurrence", Operation{Kind: OperationHexDecode, Occurrence: 1}, "unsupported occurrence"},
		{"decoder passes", Operation{Kind: OperationHexDecode, Passes: 1}, "unsupported passes"},
		{"decoder profile", Operation{Kind: OperationHexDecode, Profile: "x"}, "unsupported profile"},
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
	}
	if !slices.Equal(got, want) {
		t.Fatalf("SupportedOperationKinds() = %v, want %v", got, want)
	}
}
