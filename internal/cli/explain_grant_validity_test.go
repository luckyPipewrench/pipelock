// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestExplainCmd_GrantValidityWindowNote(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, key string
		wantNote  bool
	}{
		{"expired measured format", "key1", true},
		{"invalid key format", "abcd", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc := base64.RawURLEncoding
			header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
			payload := fmt.Sprintf(`{"iss":"github.com","aud":"release-assets.githubusercontent.com","nbf":1000,"exp":1300,"key":%q,"path":"releaseassetproduction.blob.core.windows.net"}`, tc.key)
			sig := sha256.Sum256([]byte("explain-grant-fixture"))
			grant := header + "." + enc.EncodeToString([]byte(payload)) + "." + enc.EncodeToString(sig[:])
			report, err := decodeExplainJSON(t, "https://release-assets.githubusercontent.com/asset?jwt="+grant)
			if err == nil || report.Allowed {
				t.Fatalf("allowed = %v, err = %v, want refusal", report.Allowed, err)
			}
			notes := strings.Join(report.Notes, " ")
			if got := strings.Contains(notes, "current host clock"); got != tc.wantNote {
				t.Fatalf("validity note = %v, want %v: %s", got, tc.wantNote, notes)
			}
			if tc.wantNote && !strings.Contains(report.Reason, "outside its validity window") {
				t.Fatalf("reason = %q", report.Reason)
			}
			if tc.wantNote && (report.Remediation == nil || !report.Remediation.Immutable || !strings.Contains(report.Remediation.Knob, "Check the host clock")) {
				t.Fatalf("window remediation = %#v", report.Remediation)
			}
		})
	}
}
