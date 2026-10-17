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
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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
		{`{"ids":[` + groups + `]}`, false},
		{`{"bbox":[` + groups + `]}`, false},
		{`[` + groups + `]`, false},
		{`{"":[` + groups + `]}`, false},
		{`{"-":[` + groups + `]}`, false},
		{`{"x-":[` + groups + `]}`, false},
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
	for _, tt := range cardtest.JSONCases() {
		t.Run(tt.Name, func(t *testing.T) {
			h := newTestHandler(t)
			t.Cleanup(h.scanner.Close)
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
			if w.Code != http.StatusOK || (result.Decision != DecisionDeny) != (tt.Clean || tt.Warn) {
				t.Fatalf("status=%d decision=%s want clean=%v warn=%v", w.Code, result.Decision, tt.Clean, tt.Warn)
			}
			if tt.Warn && (result.Decision != DecisionWarn || len(result.Findings) == 0) {
				t.Fatalf("missing warning evidence: %+v", result)
			}
		})
	}
}

func TestCardJSONToolCallInspectionLimits(t *testing.T) {
	h := newTestHandler(t)
	for _, args := range []string{`[1e10001]`, `[` + strings.Repeat("9", 4097) + `]`, strings.Repeat("[", 65) + "1" + strings.Repeat("]", 65)} {
		body := `{"kind":"tool_call","input":{"tool_name":"report","arguments":` + args + `}}`
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+testToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var result Response
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		wantRule := "DLP-" + scanner.UninspectableJSONNumberPattern
		if strings.Count(args, "[") > 1 {
			wantRule = "UNINSPECTABLE-json-depth"
		}
		if w.Code != http.StatusOK || result.Status != StatusCompleted || result.Decision != DecisionDeny || len(result.Findings) == 0 || result.Findings[0].RuleID != wantRule {
			t.Fatalf("inspection limit allowed: status=%d decision=%s", w.Code, result.Decision)
		}
	}
}

func TestCardJSONDLPDecision(t *testing.T) {
	h := newTestHandler(t)
	for _, tt := range cardtest.JSONCases() {
		// The dlp kind scans literal text; only typed tool_call arguments
		// receive single-decimal relief. Exercise the joined-card classes here.
		if tt.Clean {
			continue
		}
		t.Run(tt.Name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"kind": KindDLP, "input": map[string]string{"text": tt.Body}})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			var result Response
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			want := DecisionDeny
			if tt.Warn {
				want = DecisionWarn
			}
			if w.Code != http.StatusOK || result.Decision != want {
				t.Fatalf("status=%d decision=%s want=%s", w.Code, result.Decision, want)
			}
			if tt.Warn && (len(result.Findings) == 0 || !strings.Contains(result.Findings[0].Message, "action=warn")) {
				t.Fatal("missing number-only warning evidence")
			}
		})
	}
}
