// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/evidence"
)

func main() {
	var b bytes.Buffer
	b.WriteString("# Evidence Hard Limits\n\n")
	b.WriteString("## How to Read This\n\n")
	b.WriteString("These limits are not loopholes in receipt verification. They are the boundary of what signed, hash-chained evidence can honestly prove without extra witnesses, configuration attestation, or containment attestation.\n\n")
	for _, limit := range evidence.Limits {
		_, _ = fmt.Fprintf(&b, "## %s - %s\n\n", limit.ID, limit.Title)
		_, _ = fmt.Fprintf(&b, "**Category:** %s\n\n", limit.Category)
		_, _ = fmt.Fprintf(&b, "**Summary:** %s\n\n", limit.Summary)
		b.WriteString("**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.\n\n")
		_, _ = fmt.Fprintf(&b, "**Bound:** %s\n\n", limit.Bound)
		_, _ = fmt.Fprintf(&b, "**How the verifier surfaces it:** Passing verification prints `%s` with this summary when the verified surface is subject to the limit.\n\n", limit.ID)
	}
	b.WriteString("## What Pipelock DOES Prove\n\n")
	b.WriteString("Pipelock receipts prove that the verified bytes were signed by the trusted key, chained in order, and checked by the verifier without mutation. Anchors and containment evidence can narrow specific gaps, but they do not turn these hard limits into stronger claims than the evidence supports.\n")

	path := filepath.Join("..", "..", "docs", "evidence", "hard-limits.md")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		panic(err)
	}
}
