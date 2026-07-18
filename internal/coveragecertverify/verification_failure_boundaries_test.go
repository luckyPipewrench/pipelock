// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package coveragecertverify

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsMalformedArtifactBeforePrintingSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(path, []byte(`{"body":`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var out bytes.Buffer
	err := Run(Options{
		CertFile:       path,
		TrustedSigners: []string{"inline=" + strings.Repeat("00", 32)},
		Out:            &out,
	})
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("Run error = %v, want malformed artifact rejection", err)
	}
	if out.Len() != 0 {
		t.Fatalf("malformed artifact emitted output: %q", out.String())
	}
}

func TestRunRejectsMalformedTrustSpecificationsBeforeVerification(t *testing.T) {
	certFile, _ := writeCoverageCertVerifyFixture(t)
	tests := []struct {
		name string
		spec string
	}{
		{name: "missing key source", spec: "source=operator"},
		{name: "unknown field", spec: "unknown=value"},
		{name: "empty inline key", spec: "inline="},
		{name: "two key sources", spec: "inline=" + strings.Repeat("00", 32) + ",file=/tmp/key"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := Run(Options{
				CertFile:       certFile,
				TrustedSigners: []string{tc.spec},
				Out:            &out,
			})
			if err == nil || !strings.Contains(err.Error(), "--trusted-signer") {
				t.Fatalf("Run error = %v, want trust specification rejection", err)
			}
			if out.Len() != 0 {
				t.Fatalf("invalid trust specification emitted output: %q", out.String())
			}
		})
	}
}
