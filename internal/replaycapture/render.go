// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// boundedInt converts a chain sequence (uint64) to int, saturating at MaxInt.
// Chain sequences are tiny in practice; the guard satisfies gosec G115 and keeps
// the conversion provably safe.
func boundedInt(v uint64) int {
	if v > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(v)
}

// marshalIndentNoEscape renders v as indented JSON with HTML escaping disabled
// (no < noise in published packets). The encoder's trailing newline is kept so
// every artifact ends with a newline, matching the repo's end-of-file
// convention and keeping the manifest's packet hash bound to the exact on-disk
// bytes (hooks must not need to modify a published file after the hash is taken).
func marshalIndentNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	return buf.Bytes(), nil
}

// verifierText is the human-readable verifier note shipped as verifier.txt. It
// records the offline verification result for the captured chain and the exact
// command a visitor runs to reproduce it.
func verifierText(cs *CapturedScenario) string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "Pipelock audit packet — receipt chain verification\n")
	_, _ = fmt.Fprintf(&b, "scenario: %s\n", cs.Scenario.ID)
	_, _ = fmt.Fprintf(&b, "receipts: %d\n", cs.ReceiptCount)
	_, _ = fmt.Fprintf(&b, "verdict: %s (trusted)\n", verifierVerdictTrusted)
	_, _ = fmt.Fprintf(&b, "root_hash: %s\n", cs.RootHash)
	_, _ = fmt.Fprintf(&b, "signer_key: %s\n", cs.SignerKeyHex)
	_, _ = fmt.Fprintf(&b, "\nVerify it yourself from this directory:\n")
	_, _ = fmt.Fprintf(&b, "  pipelock-verifier audit-packet . --key %s\n", cs.SignerKeyHex)
	return b.String()
}

// summaryMarkdown is a short, public-safe human summary shipped as summary.md.
func summaryMarkdown(cs *CapturedScenario) string {
	s := cs.Scenario
	decisive := decisiveVerdict(cs)
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "# %s\n\n", s.Title)
	_, _ = fmt.Fprintf(&b, "- **Category:** %s\n", s.Category)
	_, _ = fmt.Fprintf(&b, "- **Bench case:** `%s`\n", s.BenchCaseID)
	_, _ = fmt.Fprintf(&b, "- **Transport:** %s\n", s.Transport)
	_, _ = fmt.Fprintf(&b, "- **Destination:** %s\n", s.DestinationClass)
	_, _ = fmt.Fprintf(&b, "- **Decision:** %s\n", decisive)
	_, _ = fmt.Fprintf(&b, "- **Receipts:** %d (chain verifies)\n\n", cs.ReceiptCount)
	_, _ = fmt.Fprintf(&b, "## Without Pipelock\n\n%s\n\n", s.Without)
	_, _ = fmt.Fprintf(&b, "## With Pipelock\n\n%s\n\n", s.With)
	_, _ = fmt.Fprintf(&b, "These receipts record the *mediated decisions* Pipelock signed. ")
	_, _ = fmt.Fprintf(&b, "A verified chain proves those decisions were signed and untampered; ")
	_, _ = fmt.Fprintf(&b, "it does not prove session completeness or that no event was missed.\n")
	return b.String()
}

// decisiveVerdict returns the headline verdict label for a captured scenario.
func decisiveVerdict(cs *CapturedScenario) string {
	if decisiveReceiptAR(cs.Receipts, cs.Scenario.ExpectedVerdict) != nil {
		return cs.Scenario.ExpectedVerdict
	}
	if len(cs.Receipts) > 0 {
		return cs.Receipts[len(cs.Receipts)-1].ActionRecord.Verdict
	}
	return "unknown"
}

// decisiveReceiptAR returns the first receipt action record matching verdict, or
// nil. Production sibling of the test-only helper.
func decisiveReceiptAR(receipts []receipt.Receipt, verdict string) *receipt.ActionRecord {
	for i := range receipts {
		if receipts[i].ActionRecord.Verdict == verdict {
			return &receipts[i].ActionRecord
		}
	}
	return nil
}
