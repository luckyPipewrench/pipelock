// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// Repeated cell values, extracted so goconst does not flag the matrix literal
// and so the allow/fail-closed wording stays identical across rows.
const (
	rcReceiptYes          = "yes"
	rcAllowFailClosedNote = "Allow receipt; fails closed if emission fails."
	rcAllowOptInNote      = "Allow receipts are opt-in via `require_receipts`."
)

// receiptCoverageMatrix is the canonical, single-source-of-truth list of when a
// signed action receipt is and is not emitted, including the deliberate
// no-receipt cases. It is rendered into the "Intentional no-receipt and
// summarized cases" block of docs/guides/transport-modes.md and drift-checked by
// TestReceiptCoverage_MatrixMatchesDocs. Edit this slice (not the doc) and run
//
//	UPDATE_GOLDEN=1 go test ./internal/proxy/ -run TestReceiptCoverage_MatrixMatchesDocs
//
// to regenerate the doc block.
var receiptCoverageMatrix = []struct {
	Scenario string
	Receipt  string
	Notes    string
}{
	{"`tools/call` block", rcReceiptYes, "Block receipt (best-effort: the action is already denied)."},
	{"`tools/call` allow, `require_receipts: true`", rcReceiptYes, rcAllowFailClosedNote},
	{"`tools/call` allow, default", "no", rcAllowOptInNote},
	{"A2A method block", rcReceiptYes, "Block receipt with the A2A method name as `target`."},
	{"A2A method allow, `require_receipts: true`", rcReceiptYes, rcAllowFailClosedNote},
	{"A2A method allow, default", "no", rcAllowOptInNote},
	{"Proxy block (fetch / CONNECT / forward / WS handshake)", rcReceiptYes, "Pre- or post-forward block receipt."},
	{"Proxy allow, `require_receipts: true`", rcReceiptYes, rcAllowFailClosedNote},
	{"Clean WebSocket frame", "no (intentional)", "Per-frame allow receipts are O(n) in stream length; summarized, not emitted, to avoid a receipt-flood denial-of-service vector."},
	{"Clean SSE / streamed response chunk", "no (intentional)", "Streamed response chunks are summarized, not receipted per chunk."},
	{"WebSocket session close", rcReceiptYes, "Session-close receipt records the close reason."},
	{"Required receipt emission fails", "block", "Request fails closed with `receipt_emission_failed` instead of forwarding."},
}

const (
	receiptMatrixBeginMarker = "<!-- BEGIN receipt-coverage-matrix (generated; edit internal/proxy/receipt_coverage_matrix_test.go) -->"
	receiptMatrixEndMarker   = "<!-- END receipt-coverage-matrix -->"
	receiptMatrixDocPath     = "../../docs/guides/transport-modes.md"
)

func renderReceiptCoverageMatrix() string {
	var b strings.Builder
	b.WriteString("| Scenario | Receipt | Notes |\n")
	b.WriteString("|----------|---------|-------|\n")
	for _, r := range receiptCoverageMatrix {
		b.WriteString("| " + r.Scenario + " | " + r.Receipt + " | " + r.Notes + " |\n")
	}
	return b.String()
}

// normalizeMatrixLines trims trailing whitespace and drops blank lines so the
// drift comparison is robust to incidental formatting differences.
func normalizeMatrixLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, " \t\r")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		out = append(out, ln)
	}
	return out
}

// TestReceiptCoverage_MatrixMatchesDocs is the regression brake that keeps the
// public receipt-coverage matrix honest: if the code-side matrix and the doc
// block drift apart, this fails. Run with UPDATE_GOLDEN=1 to regenerate the doc.
func TestReceiptCoverage_MatrixMatchesDocs(t *testing.T) {
	docBytes, err := os.ReadFile(receiptMatrixDocPath)
	if err != nil {
		t.Fatalf("read doc %s: %v", receiptMatrixDocPath, err)
	}
	doc := string(docBytes)

	begin := strings.Index(doc, receiptMatrixBeginMarker)
	end := strings.Index(doc, receiptMatrixEndMarker)
	if begin < 0 || end < 0 || end < begin {
		t.Fatalf("receipt-coverage-matrix markers not found or malformed in %s", receiptMatrixDocPath)
	}
	rendered := renderReceiptCoverageMatrix()

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		newBlock := receiptMatrixBeginMarker + "\n\n" + rendered + "\n" + receiptMatrixEndMarker
		updated := doc[:begin] + newBlock + doc[end+len(receiptMatrixEndMarker):]
		if err := os.WriteFile(receiptMatrixDocPath, []byte(updated), 0o600); err != nil {
			t.Fatalf("write doc %s: %v", receiptMatrixDocPath, err)
		}
		t.Logf("regenerated receipt-coverage-matrix block in %s", receiptMatrixDocPath)
		return
	}

	current := doc[begin+len(receiptMatrixBeginMarker) : end]
	got := normalizeMatrixLines(current)
	want := normalizeMatrixLines(rendered)
	if !slices.Equal(got, want) {
		t.Fatalf("receipt-coverage-matrix in %s is stale.\nRegenerate with: UPDATE_GOLDEN=1 go test ./internal/proxy/ -run TestReceiptCoverage_MatrixMatchesDocs\n--- doc has ---\n%s\n--- code wants ---\n%s",
			receiptMatrixDocPath, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
