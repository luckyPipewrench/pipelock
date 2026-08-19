package scanner

import (
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// TestHexReplayMatchesScannerNormalizer proves the v2 replay reconstructs the
// exact view normalizeHex produced. A receipt attests a finding in the view the
// scanner actually built, so any disagreement means a valid receipt fails to
// verify, or an invalid one appears to.
//
// It exists because reading the two functions side by side did not catch the
// drift. Both were individually reasonable and the pair disagreed on 5,844 of
// these inputs: the scanner consumed a "0x" unconditionally while the replay
// consumed it only ahead of two hex digits, so "000x" normalized to "00" on one
// side and to "" on the other. Enumeration found it in one run.
//
// The alphabet mixes hex digits, both prefix-introducer bytes, the escape
// backslash, an out-of-alphabet letter and a separator, so it reaches every
// branch in both implementations.
func TestHexReplayMatchesScannerNormalizer(t *testing.T) {
	alphabet := []byte{'0', 'x', 'X', '\\', '4', '8', 'f', 'g', ':', 'z'}

	replay := func(s string) string {
		out, err := (normalize.Recipe{
			TransformProfileDigest: normalize.EvidenceProvenanceProfileV2Digest,
			Operations: []normalize.Operation{{
				Kind:     normalize.OperationEncodedTokenNormalize,
				Alphabet: "hex",
			}},
		}).Apply(s)
		if err != nil {
			return fmt.Sprintf("error:%v", err)
		}
		return out
	}

	var checked, mismatched int
	var buf []byte
	var walk func(depth int)
	walk = func(depth int) {
		if depth == 0 {
			input := string(buf)
			checked++
			scanner, replayed := normalizeHex(input), replay(input)
			if scanner != replayed {
				mismatched++
				if mismatched <= 10 {
					t.Errorf("input %q: scanner = %q, replay = %q", input, scanner, replayed)
				}
			}
			return
		}
		for _, char := range alphabet {
			buf = append(buf, char)
			walk(depth - 1)
			buf = buf[:len(buf)-1]
		}
	}
	for length := 4; length <= 5; length++ {
		buf = buf[:0]
		walk(length)
	}

	if mismatched > 0 {
		t.Fatalf("%d of %d inputs disagreed between the scanner and the v2 replay", mismatched, checked)
	}
	t.Logf("%d inputs agreed", checked)
}
