// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestKeyAliasesDiscriminator(t *testing.T) {
	m, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{discRule()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"Action":"deleteAll"}`, `{"action":"list","Action":"deleteAll"}`, `{"ACTION":"deleteAll"}`} {
		meta := RequestMeta{Host: "api.service.example.com", Method: "POST", JSONBodyParsed: true, JSONBody: jsonBody(t, raw)}
		if got := m.Evaluate(meta); got.Action != config.ActionBlock {
			t.Errorf("alias accepted: %s: %+v", raw, got)
		}
	}
	e := compileExactException(&config.RequestPolicyException{Field: "action", Values: []string{"list"}})
	if e.matches(RequestMeta{JSONBodyParsed: true, JSONBody: jsonBody(t, `{"action":"list","Action":"deleteAll"}`)}) {
		t.Error("ambiguous exception accepted")
	}
	if !e.matches(RequestMeta{JSONBodyParsed: true, JSONBody: jsonBody(t, `{"action":"list"}`)}) {
		t.Error("valid exception rejected")
	}
}
