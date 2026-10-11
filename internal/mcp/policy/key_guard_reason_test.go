// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestJSONKeyGuardReason(t *testing.T) {
	for _, tc := range []struct {
		name, raw, rule string
	}{
		{"duplicate", `{"result":1,"result":2}`, duplicateJSONKeyRule},
		{"batch duplicate", `[{"result":1,"result":2}]`, duplicateJSONKeyRule},
		{"malformed", `{`, "invalid_json_key_input"},
		{"batch malformed", `[{`, "invalid_json_key_input"},
		{"invalid UTF-8", `{"result":"` + string([]byte{0xff}) + `"}`, "invalid_json_key_input"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := (&Config{}).CheckRequest([]byte(tc.raw))
			if !v.Matched || v.Action != config.ActionBlock || len(v.Rules) != 1 || v.Rules[0] != tc.rule {
				t.Fatalf("key guard verdict = %+v, want block with %q", v, tc.rule)
			}
		})
	}
}
