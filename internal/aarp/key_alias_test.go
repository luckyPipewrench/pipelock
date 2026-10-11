// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"bytes"
	"testing"
)

func TestKeyAliasesEnvelope(t *testing.T) {
	env, opts := signedEnvelope(t)
	raw, err := Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(decoded, opts); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"profile", "assertion", "mediator_id"} {
		canonical := []byte(`"` + key + `":`)
		alias := []byte(`"` + string(bytes.ToUpper([]byte(key))) + `":`)
		changed := bytes.Replace(raw, canonical, alias, 1)
		if bytes.Equal(changed, raw) {
			t.Fatalf("missing fixture key %s", key)
		}
		if _, err := Unmarshal(changed); err == nil {
			t.Errorf("accepted alias %s", key)
		}
	}
	changed := append([]byte(`{"PROFILE":"other",`), raw[1:]...)
	if _, err := Unmarshal(changed); err == nil {
		t.Error("accepted case collision")
	}
}
