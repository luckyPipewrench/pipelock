// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
)

func TestCardJSONToolCallTypes(t *testing.T) {
	h := newTestHandler(t)
	card := "41111111" + "11111111"
	groups := "4111,1111" + ",1111,1111"
	for _, tt := range []struct {
		args string
		deny bool
	}{
		{`{"n":0.` + card + `}`, false},
		{`{"ids":[` + groups + `]}`, true},
		{`{"bbox":[` + groups + `]}`, true},
		{`[` + groups + `]`, true},
		{`{"":[` + groups + `]}`, true},
		{`{"-":[` + groups + `]}`, true},
		{`{"x-":[` + groups + `]}`, true},
		{`{"n":"` + card + `"}`, true},
		{`{"n":` + card + `}`, true},
		{`{"n":` + card + `.1}`, true},
		{`["4111","1111","1111","1111"]`, true},
		{`["41111111","11111111"]`, true},
		{`{"n":"0.` + card + `"}`, true},
		{`{"n":"{\"n\":0.` + card + `}"}`, true},
	} {
		body := `{"kind":"tool_call","input":{"tool_name":"report","arguments":` + tt.args + `}}`
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+testToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var result Response
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusOK || (result.Decision == DecisionDeny) != tt.deny {
			t.Fatalf("args=%s status=%d result=%+v want deny=%v", tt.args, w.Code, result, tt.deny)
		}
	}
}

func TestCardJSONSharedToolCallCorpus(t *testing.T) {
	h := newTestHandler(t)
	for _, tt := range cardtest.JSONCases() {
		t.Run(tt.Name, func(t *testing.T) {
			body := `{"kind":"tool_call","input":{"tool_name":"report","arguments":` + tt.Body + `}}`
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			var result Response
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || (result.Decision != DecisionDeny) != tt.Clean {
				t.Fatalf("status=%d decision=%s want clean=%v", w.Code, result.Decision, tt.Clean)
			}
		})
	}
}
