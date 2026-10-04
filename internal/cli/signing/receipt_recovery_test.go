// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyReceiptRecoveryDiscontinuityRemainsFailure(t *testing.T) {
	t.Parallel()
	fixture := "../../../sdk/conformance/testdata/recovery-seals/valid"
	key, err := os.ReadFile(filepath.Join(fixture, "signer.pub"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := runVerifyReceipt(t, "--chain", filepath.Join(fixture, "evidence"), "--key", strings.TrimSpace(string(key)))
	if err == nil {
		t.Fatalf("damaged archive must fail despite its seal: %s", out)
	}
	for _, want := range []string{"linked across attested discontinuity", "damage remains", "RESTART CONTINUITY FAILED"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "RESTART CONTINUITY OK") {
		t.Fatalf("damaged archive reported continuous success: %s", out)
	}
}
