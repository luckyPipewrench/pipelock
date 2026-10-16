// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"bytes"
	"strings"
	"testing"
)

func TestRewriteJSONCardDepthRefusal(t *testing.T) {
	_, _, err := RewriteJSON([]byte(`[[1]]`), NewDefaultMatcher(), NewRedactor(), Limits{MaxDepth: 1})
	be, ok := asBlockError(err)
	if !ok || be.Reason != ReasonSecretInNumericScalar {
		t.Fatalf("early typed inspection did not refuse depth: %v", err)
	}
}

func TestRewriteJSONNumberOnlyRunsUnchanged(t *testing.T) {
	for _, body := range []string{`[4111,1111,1111,1111]`, `[4111.0,1111.0,1111.0,1111.0]`, `[4111e0,1111e-2,1111E2,1111e+1]`} {
		out, report, err := RewriteJSON([]byte(body), NewDefaultMatcher(), NewRedactor(), Limits{})
		if err != nil || !bytes.Equal(out, []byte(body)) || report.TotalRedactions != 0 {
			t.Fatalf("number-only values changed: err=%v", err)
		}
	}
	for _, body := range []string{`[1e10001]`, `[` + strings.Repeat("9", 4097) + `]`} {
		_, _, err := RewriteJSON([]byte(body), NewDefaultMatcher(), NewRedactor(), Limits{})
		be, ok := asBlockError(err)
		if !ok || be.Reason != ReasonSecretInNumericScalar {
			t.Fatalf("uninspectable number allowed: %v", err)
		}
	}
}
