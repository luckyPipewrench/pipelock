// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf8"
)

// inertParityCheck compares both fast-pathed pipelines with their full
// reference pipelines on one input.
func inertParityCheck(t *testing.T, input string) {
	t.Helper()
	if got, want := ForDLP(input), forDLPFull(input); got != want {
		t.Fatalf("ForDLP fast path differs for %x: got %x, want %x", input, got, want)
	}
	for _, recompose := range []bool{true, false} {
		if got, want := matchingNormalize(input, recompose), matchingNormalizeFull(input, recompose); got != want {
			t.Fatalf("matching fast path (recompose=%v) differs for %x: got %x, want %x", recompose, input, got, want)
		}
	}
}

// sweepStride is 1 for a full exhaustive sweep. Under the race detector the
// sweeps visit every sixteenth element so each path still runs in CI; a plain
// go test run covers every element.
func sweepStride() int {
	if raceEnabled {
		return int(raceSweepStride)
	}
	return 1
}

const raceSweepStride rune = 16

func scalarSweepStride() rune {
	if raceEnabled {
		return raceSweepStride
	}
	return 1
}

func inertRunes(table *segmentTable) []rune {
	runes := []rune{utf8.RuneError}
	for r := rune(0); r < inertRuneLimit; r++ {
		if table.isInert(r) {
			runes = append(runes, r)
		}
	}
	return runes
}

func TestInertReplacementCharacterIsIsolated(t *testing.T) {
	if !boundaryIsolated(utf8.RuneError) {
		t.Fatal("U+FFFD must be boundary-isolated for the invalid-byte fast path")
	}
	single := string(utf8.RuneError)
	if forDLPFull(single) != single || matchingNormalizeFull(single, true) != single || matchingNormalizeFull(single, false) != single {
		t.Fatal("U+FFFD must pass both full pipelines unchanged")
	}
	tables := segmentTablesOnce()
	for _, r := range []rune{'\u0301', '\u00e9', '\u00a0', '\u0430', '\u00d8', '\u0085', '\t'} {
		if tables.dlp.isInert(r) {
			t.Fatalf("U+%04X must not be DLP-inert", r)
		}
	}
	if !tables.matching[0].isInert('\t') || !tables.matching[1].isInert('\t') {
		t.Fatal("tab is kept by the matching pipeline and must be matching-inert")
	}
	t.Logf("dlp inert scalars: %d, matching inert scalars: %d", len(inertRunes(&tables.dlp)), len(inertRunes(&tables.matching[1])))
}

// TestInertPairsMatchFullPipeline checks every ordered pair of inert scalars,
// with and without a stripped scalar between them, against the full pipelines.
// Composition and reordering only act on adjacent scalars, so a pair is the
// smallest context that could expose an interaction.
func TestInertPairsMatchFullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive pair sweep")
	}
	tables := segmentTablesOnce()
	runes := inertRunes(&tables.dlp)
	runes = append(runes, inertRunes(&tables.matching[0])...)
	runes = append(runes, inertRunes(&tables.matching[1])...)
	seen := make(map[rune]struct{}, len(runes))
	uniq := runes[:0]
	for _, r := range runes {
		if _, ok := seen[r]; !ok {
			seen[r] = struct{}{}
			uniq = append(uniq, r)
		}
	}
	var buf strings.Builder
	pairs := 0
	for ai := 0; ai < len(uniq); ai += sweepStride() {
		a := uniq[ai]
		buf.Reset()
		for _, b := range uniq {
			buf.WriteRune(a)
			buf.WriteRune(b)
			buf.WriteString("\u200b")
			buf.WriteRune(a)
			buf.WriteByte(0x01)
			buf.WriteRune(b)
			buf.WriteByte('|')
			pairs++
		}
		inertParityCheck(t, buf.String())
	}
	t.Logf("compared %d inert pairs", pairs)
}

// TestInertEveryScalarMatchesFullPipeline puts every Unicode scalar next to
// inert neighbours, combining marks and invalid bytes, so a misclassified or
// fallback scalar is exercised in context.
// TestInertNextToEveryScalarBelowLimit surrounds every scalar below the
// table limit, and a set of composing scalars above it, with each inert
// scalar on both sides. The neighbour set is independent of the table under
// test, so a misclassified scalar still meets every neighbour.
func TestInertNextToEveryScalarBelowLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive split-point sweep")
	}
	tables := segmentTablesOnce()
	others := make([]rune, 0, inertRuneLimit+16)
	for r := rune(0); r < inertRuneLimit; r++ {
		others = append(others, r)
	}
	others = append(others, '\u0b47', '\u0b3e', '\u1100', '\u1161', '\u11a8', '\uac00', '\u3099', '\u309a', '\u304b', '\u2126', '\u212a', '\ufb01', '\u0f73', '\U0001D15E', '\u200b', '\u3000')
	inerts := inertRunes(&tables.dlp)
	for _, r := range inertRunes(&tables.matching[1]) {
		if !tables.dlp.isInert(r) {
			inerts = append(inerts, r)
		}
	}
	var buf strings.Builder
	for ii := 0; ii < len(inerts); ii += sweepStride() {
		i := inerts[ii]
		buf.Reset()
		for _, r := range others {
			buf.WriteRune(r)
			buf.WriteRune(i)
			buf.WriteRune(r)
			buf.WriteRune(r)
			buf.WriteRune(i)
			buf.WriteRune(i)
		}
		inertParityCheck(t, buf.String())
	}
	t.Logf("compared %d inert scalars against %d neighbours", len(inerts), len(others))
}

func TestInertEveryScalarMatchesFullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("exhaustive scalar sweep")
	}
	var batch strings.Builder
	n := 0
	for r := rune(0); r <= utf8.MaxRune; r += scalarSweepStride() {
		if !utf8.ValidRune(r) {
			continue
		}
		batch.WriteString("a\xff")
		batch.WriteRune(r)
		batch.WriteString("\u00c2\u0301\ufffdz\x80")
		batch.WriteRune(r)
		n++
		if n%1024 == 0 {
			inertParityCheck(t, batch.String())
			batch.Reset()
		}
	}
	inertParityCheck(t, batch.String())
}

func TestInertRawBytesMatchFullPipeline(t *testing.T) {
	for first := range 256 {
		for second := range 256 {
			pair := string([]byte{byte(first), byte(second)})
			inertParityCheck(t, pair)
			inertParityCheck(t, "x"+pair+"\u0301")
		}
	}
	rng := &testBytes{state: 1002}
	raw := make([]byte, 128)
	for range 15000 / sweepStride() {
		n := 1 + rng.IntN(len(raw))
		rng.fill(raw[:n])
		data := raw[:n]
		inertParityCheck(t, string(data))
		// Decoded views of encoded random data: the receipt signature,
		// key and nonce fields decode to exactly this kind of byte string.
		if decoded, err := hex.DecodeString(hex.EncodeToString(data)); err == nil {
			inertParityCheck(t, string(decoded))
		}
		enc := base64.StdEncoding.EncodeToString(data)
		if decoded, err := base64.StdEncoding.DecodeString(enc[:len(enc)/4*4]); err == nil {
			inertParityCheck(t, string(decoded))
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(hex.EncodeToString(data)); err == nil {
			inertParityCheck(t, string(decoded))
		}
		if decoded, err := base32.StdEncoding.DecodeString(base32.StdEncoding.EncodeToString(data)); err == nil {
			inertParityCheck(t, string(decoded)+"\u0301")
		}
	}
}

func TestInertAdversarialInputsMatchFullPipeline(t *testing.T) {
	inputs := []string{
		"", "plain", "\ufffd", "\xff", "\xef\xbf\xbd\xff", "a\u0301", "\u00e9", "e\u0301",
		"\u1100\u1161", "\u0915\u093c", "\u0627\u0653", "sk-\u0430nt-api03", "sk-\u0585nt",
		"\uff21\u00a0\uff22", "\u212a", "\u2126", "\u00c5", "A\u030a", "\u0300a", "a\u200bb\u200cc",
		"\ufeffkey\u2060", "\u0085\u00a0\u3000", "\t\n\r", "seed\u00adword", "\xc0\xaf", "\xed\xa0\x80",
		"\U0001F170\U0001F1E6", "\u05d0\u05b8", "\u0e01\u0e48", "\u0391\u03b1\u0301",
		strings.Repeat("\xff\u07ff\u0600", 40), strings.Repeat("\u0450\u0301", 20),
	}
	for _, input := range inputs {
		inertParityCheck(t, input)
		inertParityCheck(t, input+"\u0327")
		inertParityCheck(t, "\ufffd"+input)
	}
}

func FuzzInertMatchesFullPipeline(f *testing.F) {
	for _, seed := range []string{"", "a\u0301", "\xff\xfe", "\u00c2\u0301", "\u1100\u1161\u11a8"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		inertParityCheck(t, input)
	})
}

// testBytes is a deterministic splitmix64 byte source for differential tests.
type testBytes struct{ state uint64 }

func (r *testBytes) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// IntN returns a value in [0, n) for n > 0; modulo bias does not matter here.
func (r *testBytes) IntN(n int) int {
	if n <= 0 {
		panic("testBytes.IntN: n must be positive")
	}
	return int(r.next()>>1) % n
}

func (r *testBytes) fill(b []byte) {
	for i := range b {
		b[i] = byte(r.next() & 0xff)
	}
}
