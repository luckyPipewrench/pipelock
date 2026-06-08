// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"sort"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// ComparableAppraisal projects an Appraisal onto the stable, cross-language
// comparison surface used by the four-language conformance gate, then returns
// its JCS-canonical bytes. Two verifiers in two languages that appraise the same
// envelope under the same trust MUST emit byte-identical ComparableAppraisal
// output; any divergence is the bug class the corpus exists to kill.
//
// The projection deliberately EXCLUDES:
//
//   - Warnings and per-signature Reason text — human prose that legitimately
//     differs across language runtimes and is not security-load-bearing.
//   - AssuranceClaimed — a verbatim echo of the producer's input, not a
//     verification result; including it would compare inputs, not outcomes.
//
// It INCLUDES exactly the security-load-bearing outcomes: whether the assertion
// is signed, the per-signature status (the enum, not its prose reason), the
// verified claim set, the claimed-but-unverified set, the per-axis grouping, and
// the fixed does_not_assert list. Order-insensitive fields are sorted so a
// verifier that appends claims in a different order does not register as a false
// differential; the signatures array preserves envelope order (every verifier
// walks the signatures in the same order, so this is deterministic and a
// reorder is itself a meaningful difference).
func ComparableAppraisal(ap *Appraisal) ([]byte, error) {
	sigs := make([]any, 0, len(ap.Signatures))
	for _, s := range ap.Signatures {
		sigs = append(sigs, map[string]any{
			"alg":         s.Alg,
			"key_id":      s.KeyID,
			"signer_role": s.Role,
			"status":      string(s.Status),
		})
	}

	axes := map[string]any{}
	for axis, claims := range ap.Axes {
		if len(claims) == 0 {
			continue
		}
		axes[axis] = sortedUnique(claims)
	}

	obj := map[string]any{
		"profile":            ap.Profile,
		"assertion_signed":   ap.AssertionSigned,
		"signatures":         sigs,
		"verified_claims":    sortedUnique(ap.VerifiedClaims),
		"claimed_unverified": sortedUnique(ap.ClaimedUnverified),
		"axes":               axes,
		"does_not_assert":    sortedUnique(ap.DoesNotAssert),
		"overclaim_risks":    sortedUnique(ap.OverclaimRisks),
		// assurance is the axis-set descriptor (which axes hold verified claims),
		// never a grade. The redundant axis count is intentionally omitted from the
		// comparable surface so it stays free of raw JSON numbers — every verifier
		// already agrees on string arrays, but a bare integer's canonicalization is
		// an avoidable cross-language hazard. Readers derive the count as the
		// array length.
		"assurance": map[string]any{
			"axes_with_verified_claims": sortedUnique(ap.Assurance.AxesWithVerifiedClaims),
		},
	}

	// Canonicalize sorts object keys and arrays-of-strings stay in the (already
	// sorted) order we built them in. The signatures array stays in envelope
	// order because Canonicalize never reorders array elements.
	return contract.Canonicalize(obj)
}

// ComparableChain projects a VerifyChain outcome onto the stable cross-language
// comparison surface and returns its JCS-canonical bytes. It reports whether the
// stream is contiguously hash-linked under a single issuer and the stream length
// — never the prose reason for a break (which differs across languages). The
// per-break index is intentionally excluded: a broken stream is rejected
// (non-zero exit) and the gate compares rejection agreement, not break offsets.
func ComparableChain(envs []Envelope) ([]byte, error) {
	linked := VerifyChain(envs) == nil
	obj := map[string]any{
		"chain_linked": linked,
		"length":       len(envs),
	}
	return contract.Canonicalize(obj)
}

// sortedUnique returns a sorted copy of in with duplicates removed. It converts
// to []any so the result drops straight into a Canonicalize tree.
func sortedUnique(in []string) []any {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	anyOut := make([]any, len(out))
	for i, s := range out {
		anyOut[i] = s
	}
	return anyOut
}
