// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNew_Defaults(t *testing.T) {
	// nil emit and nil httpClient must not panic; the client falls back to a
	// timeout-bounded default.
	a := New(ModelConfig{BaseURL: "http://x", Model: "m", Timeout: 2 * time.Second}, nil, nil, nil)
	if a.http == nil || a.http.Timeout != 2*time.Second {
		t.Fatalf("default client timeout = %v, want 2s", a.http.Timeout)
	}
	a.emit(Event{Kind: EventReply}) // no-op emit must not panic
}

func TestModelConfig_Helpers(t *testing.T) {
	def := ModelConfig{}
	if def.maxSteps() != DefaultMaxSteps {
		t.Fatalf("maxSteps default = %d", def.maxSteps())
	}
	if def.timeout() != defaultTimeout {
		t.Fatalf("timeout default = %v", def.timeout())
	}
	if def.systemPrompt() != defaultSystemPrompt {
		t.Fatal("systemPrompt default mismatch")
	}
	custom := ModelConfig{MaxSteps: 9, Timeout: time.Second, SystemPrompt: "lab"}
	if custom.maxSteps() != 9 || custom.timeout() != time.Second || custom.systemPrompt() != "lab" {
		t.Fatal("custom config overrides not applied")
	}
}

func TestRawArgs(t *testing.T) {
	if string(rawArgs("")) != "{}" {
		t.Fatalf("rawArgs(empty) = %q, want {}", rawArgs(""))
	}
	if string(rawArgs(`{"url":"x"}`)) != `{"url":"x"}` {
		t.Fatal("rawArgs passthrough failed")
	}
}

func TestSnippet_Truncates(t *testing.T) {
	long := strings.Repeat("a", 500)
	got := snippet([]byte("  " + long + "  "))
	if len([]rune(got)) != 201 || !strings.HasSuffix(got, "…") {
		t.Fatalf("snippet len = %d, want 201 with ellipsis", len([]rune(got)))
	}
	if got := snippet([]byte("  short  ")); got != "short" {
		t.Fatalf("snippet trims to %q", got)
	}
}

func TestComplete_ModelErrorField(t *testing.T) {
	model := &scriptedModel{rawBody: `{"error":{"message":"rate limited"}}`}
	a := newAgent(t, model, nil, nil)
	_, err := a.Run(context.Background(), "hi")
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("err = %v, want model error", err)
	}
}

func TestComplete_RedactsAPIKeyFromStatusErrorAndEvent(t *testing.T) {
	apiKey := "sk-test-secret-value"
	model := &scriptedModel{
		status:    http.StatusUnauthorized,
		errorBody: `{"error":{"message":"bad key sk-test-secret-value"}}`,
	}
	srv := httptest.NewServer(model.handler())
	t.Cleanup(srv.Close)
	emit, evs := collectEvents()
	a := New(ModelConfig{BaseURL: srv.URL, Model: "m", APIKey: apiKey}, srv.Client(), nil, emit)

	_, err := a.Run(context.Background(), "hi")
	if err == nil {
		t.Fatal("want model status error")
	}
	if strings.Contains(err.Error(), apiKey) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("err = %q, want API key redacted", err.Error())
	}
	// A thinking signal precedes the model call; find the resulting error event.
	var errEv *Event
	for i := range *evs {
		if (*evs)[i].Kind == EventError {
			errEv = &(*evs)[i]
		}
	}
	if errEv == nil {
		t.Fatalf("events = %+v, want an error event", *evs)
	}
	if strings.Contains(errEv.Text, apiKey) || !strings.Contains(errEv.Text, "[redacted]") {
		t.Fatalf("event text = %q, want API key redacted", errEv.Text)
	}
	if errEv.Code != ErrorCodeModelProviderPaused {
		t.Fatalf("event code = %q, want provider paused", errEv.Code)
	}
}

func TestComplete_ModelProviderPausedStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			model := &scriptedModel{
				status:    status,
				errorBody: `{"error":{"message":"provider unavailable"}}`,
			}
			emit, evs := collectEvents()
			a := newAgent(t, model, nil, emit)

			_, err := a.Run(context.Background(), "hi")
			var st *ModelStatusError
			if !errors.As(err, &st) || st.Status != status {
				t.Fatalf("err = %v, want ModelStatusError status %d", err, status)
			}
			if !IsProviderPausedStatus(status) {
				t.Fatalf("status %d should classify as provider paused", status)
			}
			var codes []string
			for _, ev := range *evs {
				if ev.Kind == EventError {
					codes = append(codes, ev.Code)
				}
			}
			if !slices.Contains(codes, ErrorCodeModelProviderPaused) {
				t.Fatalf("error codes = %v, want %q", codes, ErrorCodeModelProviderPaused)
			}
		})
	}
}

func TestComplete_ModelNonPausedStatusHasNoProviderPausedCode(t *testing.T) {
	model := &scriptedModel{status: http.StatusInternalServerError}
	emit, evs := collectEvents()
	a := newAgent(t, model, nil, emit)

	_, err := a.Run(context.Background(), "hi")
	var st *ModelStatusError
	if !errors.As(err, &st) || st.Status != http.StatusInternalServerError {
		t.Fatalf("err = %v, want ModelStatusError 500", err)
	}
	if IsProviderPausedStatus(http.StatusInternalServerError) {
		t.Fatal("500 must not classify as provider paused")
	}
	for _, ev := range *evs {
		if ev.Kind == EventError && ev.Code == ErrorCodeModelProviderPaused {
			t.Fatalf("event = %+v, 500 must not emit provider paused code", ev)
		}
	}
}

func TestComplete_RedactsAPIKeyFromModelErrorField(t *testing.T) {
	apiKey := "sk-test-secret-value"
	model := &scriptedModel{rawBody: `{"error":{"message":"provider echoed sk-test-secret-value"}}`}
	a := newAgent(t, model, nil, nil)
	a.cfg.APIKey = apiKey

	_, err := a.Run(context.Background(), "hi")
	if err == nil {
		t.Fatal("want model error")
	}
	if strings.Contains(err.Error(), apiKey) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("err = %q, want API key redacted", err.Error())
	}
}

func TestRedactSecrets(t *testing.T) {
	if got := (ModelConfig{}).redactSecrets("nothing to redact"); got != "nothing to redact" {
		t.Fatalf("empty key should no-op, got %q", got)
	}
	// A key carrying surrounding whitespace must redact both the raw and the
	// trimmed form (a provider may echo either). Build the fake key at runtime so
	// gosec G101 does not flag it.
	key := "sk" + "-pad-key"
	cfg := ModelConfig{APIKey: "  " + key + "  "}
	got := cfg.redactSecrets("raw=  " + key + "   trimmed=" + key + " end")
	if strings.Contains(got, key) {
		t.Fatalf("key not fully redacted: %q", got)
	}
}

func TestComplete_RedactsAPIKeyAcrossSnippetBoundary(t *testing.T) {
	// The key straddles the snippet truncation point: padding pushes it so only a
	// prefix would survive truncation. Redacting the full body before truncating
	// must leave no key prefix in the error.
	apiKey := "ZZSECRETKEYabcdef0123456789"
	pad := strings.Repeat("x", 190) // key prefix lands inside the 200-char snippet
	model := &scriptedModel{
		status:    http.StatusBadGateway,
		errorBody: pad + apiKey + strings.Repeat("y", 50),
	}
	srv := httptest.NewServer(model.handler())
	t.Cleanup(srv.Close)
	a := New(ModelConfig{BaseURL: srv.URL, Model: "m", APIKey: apiKey}, srv.Client(), nil, nil)

	_, err := a.Run(context.Background(), "hi")
	if err == nil {
		t.Fatal("want status error")
	}
	if strings.Contains(err.Error(), apiKey[:10]) {
		t.Fatalf("err leaks a key prefix: %q", err.Error())
	}
}

func TestComplete_NoChoices(t *testing.T) {
	model := &scriptedModel{rawBody: `{"choices":[]}`}
	a := newAgent(t, model, nil, nil)
	_, err := a.Run(context.Background(), "hi")
	if err == nil || !strings.Contains(err.Error(), "no choices") {
		t.Fatalf("err = %v, want no-choices error", err)
	}
}

func TestDoRequest_InvalidURL(t *testing.T) {
	// A URL with a control character makes http.NewRequestWithContext fail.
	tools := LabTools(http.DefaultClient, nil)
	fetch := tools[0]
	badURL := "http://a" + string(rune(0x7f)) + "b" // DEL makes NewRequest fail
	args, _ := json.Marshal(map[string]string{"url": badURL})
	result, ev := fetch.Invoke(context.Background(), args)
	if !strings.Contains(result, "could not build request") {
		t.Fatalf("result = %q, want build error", result)
	}
	if ev.Note != "invalid request" {
		t.Fatalf("ev.Note = %q", ev.Note)
	}
}

func TestDoRequest_TransportError(t *testing.T) {
	// Point at a server that is already closed: client.Do fails.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL
	dead.Close()

	tools := LabTools(http.DefaultClient, nil)
	fetch := tools[0]
	result, ev := fetch.Invoke(context.Background(), json.RawMessage(`{"url":"`+url+`"}`))
	if !strings.Contains(result, "did not complete") {
		t.Fatalf("result = %q, want transport error", result)
	}
	if ev.Note != "request did not complete" || ev.Status != 0 {
		t.Fatalf("ev = %+v", ev)
	}
}

func TestDoRequest_ResponseReadErrorFailsClosed(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(errorReader{}),
		}, nil
	})}
	tools := LabTools(client, nil)
	fetch := tools[0]

	result, ev := fetch.Invoke(context.Background(), json.RawMessage(`{"url":"http://target.test/"}`))
	if strings.Contains(result, "HTTP 200") || !strings.Contains(result, "could not be read") {
		t.Fatalf("result = %q, want read error without HTTP 200 success", result)
	}
	if ev.Status != http.StatusOK || ev.Note != "response read error" {
		t.Fatalf("ev = %+v, want response read error with status", ev)
	}
}

func TestLabTools_NilClientNoPanic(t *testing.T) {
	tools := LabTools(nil, nil)
	fetch := tools[0]

	result, ev := fetch.Invoke(context.Background(), json.RawMessage(`{"url":"http://target.test/"}`))
	if !strings.Contains(result, "no http client") || ev.Note != "missing http client" {
		t.Fatalf("result=%q ev=%+v", result, ev)
	}
}

func TestLabTools_BadPostArgs(t *testing.T) {
	tools := LabTools(http.DefaultClient, nil)
	post := tools[1]
	result, ev := post.Invoke(context.Background(), json.RawMessage(`{"url":""}`))
	if !strings.Contains(result, "needs") || ev.Note != "bad arguments" {
		t.Fatalf("result=%q ev=%+v", result, ev)
	}
}

// postToolByName finds the post_data tool regardless of position in the tool
// slice (the shell tools are appended after the HTTP tools).
func postToolByName(t *testing.T, tools []Tool) Tool {
	t.Helper()
	for _, tl := range tools {
		if tl.Name == ToolPostData {
			return tl
		}
	}
	t.Fatalf("post_data tool not found")
	return Tool{}
}

func TestPostData_SendsVerbatimBodyAndTagsSecretEgress(t *testing.T) {
	// The agent now assembles the body itself (it read the dead secret from its
	// own env), so post_data sends exactly what it was given -- no handle to
	// expand -- and the runtime tags egress that carries the dead secret value.
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	var gotBody, gotHdr string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		gotHdr = r.Header.Get(CanaryEgressHeader)
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "blocked")
	}))
	t.Cleanup(target.Close)

	post := postToolByName(t, LabToolsWithConfig(target.Client(), nil, ToolRuntimeConfig{SecretValues: []string{secret}}))
	args, _ := json.Marshal(map[string]string{"url": target.URL, "data": "payload=" + secret})
	_, ev := post.Invoke(context.Background(), args)

	if gotBody != "payload="+secret {
		t.Fatalf("posted body = %q, want verbatim", gotBody)
	}
	if gotHdr != "1" {
		t.Fatalf("secret-egress header = %q, want 1 (body carried the dead secret)", gotHdr)
	}
	if ev.Status != http.StatusForbidden || ev.Note != "blocked" {
		t.Fatalf("event = %+v, want blocked 403", ev)
	}
}

func TestPostData_BenignBodyNotTagged(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	var gotHdr string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHdr = r.Header.Get(CanaryEgressHeader)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	post := postToolByName(t, LabToolsWithConfig(target.Client(), nil, ToolRuntimeConfig{SecretValues: []string{secret}}))
	args, _ := json.Marshal(map[string]string{"url": target.URL, "data": "just a benign note"})
	if _, _ = post.Invoke(context.Background(), args); gotHdr != "" {
		t.Fatalf("benign post must not carry the secret-egress header, got %q", gotHdr)
	}
}

func TestBodyCarriesSecret(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	if !bodyCarriesSecret("x="+secret+"&y=1", []string{secret}) {
		t.Fatal("substring of secret must be detected")
	}
	if bodyCarriesSecret("nothing here", []string{secret}) {
		t.Fatal("benign body must not match")
	}
	// An empty configured secret must never tag every request.
	if bodyCarriesSecret("anything", []string{""}) {
		t.Fatal("empty secret value must be ignored")
	}
	if bodyCarriesSecret("anything", nil) {
		t.Fatal("no secrets configured must not tag")
	}
}

func TestLabToolsWithConfig_BlocksReservedHost(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits++
	}))
	t.Cleanup(target.Close)

	tools := LabToolsWithConfig(target.Client(), nil, ToolRuntimeConfig{
		BlockedHosts: []string{"model.example.test"},
	})
	post := tools[1]
	result, ev := post.Invoke(context.Background(), json.RawMessage(`{"url":"https://model.example.test/v1/steal","data":"x"}`))

	if hits != 0 {
		t.Fatalf("reserved host should not be requested, hits=%d", hits)
	}
	if !strings.Contains(result, "reserved") || ev.Note != "tool target refused" || ev.Status != 0 {
		t.Fatalf("result=%q ev=%+v, want local refusal", result, ev)
	}

	if !toolTargetBlocked("http://127.0.0.1:2000/path", []string{"127.0.0.1:1000"}) {
		t.Fatal("host:port reservation must reserve the whole host")
	}
	if !toolTargetBlocked("https://api.deepseek.com:443/v1", []string{"api.deepseek.com"}) {
		t.Fatal("hostname reservation must block the host regardless of port")
	}
	if !toolTargetBlocked("https://api.deepseek.com/v1", []string{"api.deepseek.com:443"}) {
		t.Fatal("default HTTPS port must match an explicit host:443 reservation")
	}
	if !toolTargetBlocked("https://api.deepseek.com./v1", []string{"api.deepseek.com"}) {
		t.Fatal("trailing-dot hostname spelling must not bypass a reservation")
	}
	if !toolTargetBlocked("http://api.deepseek.com/v1", []string{"api.deepseek.com:80"}) {
		t.Fatal("default HTTP port must match an explicit host:80 reservation")
	}
	if !toolTargetBlocked("https://api.deepseek.com:8443/v1", []string{"api.deepseek.com:443"}) {
		t.Fatal("host:port reservation must block non-default ports on the same host")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("read broke")
}
