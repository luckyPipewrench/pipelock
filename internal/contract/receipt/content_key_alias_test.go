// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"testing"
)

func TestEvidenceMirrorKeyAliases(t *testing.T) {
	clean := v2Detail(t, nil)
	if _, err := evidenceReceiptOuter(clean); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{`"payload_kind":`, `"PAYLOAD_KIND":`},
		{`"verdict":"allow"`, `"Verdict":"allow"`},
		{`"verdict":"allow"`, `"verdict":"block","VERDICT":"allow"`},
		{`"payload_kind":`, `"payload_kind":"other","payload_kind":`},
	} {
		changed := bytes.Replace(clean, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(changed, clean) {
			t.Fatal("fixture missing selector")
		}
		if _, err := evidenceReceiptOuter(changed); err == nil {
			t.Errorf("ambiguous mirror accepted: %s", pair[1])
		}
	}
}
