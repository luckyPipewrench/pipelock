// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/reqpolicy"
)

const gqlDeleteMutation = "mutation { deleteRecord { id } }"

// gqlJSONBody wraps a GraphQL document as a GraphQL-over-HTTP JSON request body.
func gqlJSONBody(query string) string {
	return `{"query":` + strconv.Quote(query) + `}`
}

// gqlOperationRule blocks a deleteRecord mutation regardless of HTTP method or
// content type, so the GET and multipart surfaces both route-match. Operators
// who want to catch every operation-bearing surface leave method/content_type
// unconstrained, exactly as here.
func gqlOperationRule() config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name:   rpRuleName,
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{Hosts: []string{rpTestHost}},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
		Reason: "dangerous operation requires operator approval",
	}
}

// multipartGraphQLBody builds a graphql-multipart-request body: an "operations"
// field carrying the GraphQL-over-HTTP JSON, plus a file part to mimic a real
// upload. Returns the body and the content-type (with boundary).
func multipartGraphQLBody(t *testing.T, query string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormField("operations")
	if err != nil {
		t.Fatalf("CreateFormField: %v", err)
	}
	if _, err := fw.Write([]byte(gqlJSONBody(query))); err != nil {
		t.Fatalf("write operations: %v", err)
	}
	file, err := w.CreateFormFile("0", "upload.bin")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := file.Write([]byte("file-contents")); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.Bytes(), w.FormDataContentType()
}

// --- Unit: surface extractors ----------------------------------------------

func TestExtractGraphQLFromQuery(t *testing.T) {
	t.Parallel()
	raw := "query=" + url.QueryEscape("mutation Del { deleteRecord { id } }") + "&operationName=Del"
	ops, parseOK, opaque, ok := reqpolicy.ExtractGraphQLFromQuery(raw)
	if !ok || !parseOK || opaque {
		t.Fatalf("ExtractGraphQLFromQuery = ok %v parseOK %v opaque %v, want ok parseable non-opaque", ok, parseOK, opaque)
	}
	if len(ops) != 1 || ops[0].Kind != "mutation" || ops[0].Name != "Del" || len(ops[0].RootFields) != 1 || ops[0].RootFields[0] != "deleteRecord" {
		t.Fatalf("ops = %#v, want Del mutation deleteRecord", ops)
	}

	if _, _, _, ok := reqpolicy.ExtractGraphQLFromQuery(""); ok {
		t.Error("empty query string should not produce operations")
	}
	if _, _, _, ok := reqpolicy.ExtractGraphQLFromQuery("foo=bar"); ok {
		t.Error("query string without a query param should not produce operations")
	}
	if _, _, _, ok := reqpolicy.ExtractGraphQLFromQuery("query=%zz"); ok {
		t.Error("a malformed query string should not produce operations")
	}
}

func TestMultipartOperationsField(t *testing.T) {
	t.Parallel()
	body, ct := multipartGraphQLBody(t, gqlDeleteMutation)
	got, ok := multipartOperationsField(ct, body)
	if !ok {
		t.Fatal("expected to find the operations field")
	}
	if !bytes.Contains(got, []byte("deleteRecord")) {
		t.Errorf("operations field missing query: %s", got)
	}

	// No boundary -> not parseable.
	if _, ok := multipartOperationsField("multipart/form-data", body); ok {
		t.Error("missing boundary should fail extraction")
	}
	// A multipart body with no operations field -> ok=false.
	var nob bytes.Buffer
	w := multipart.NewWriter(&nob)
	_, _ = w.CreateFormField("other")
	_ = w.Close()
	if _, ok := multipartOperationsField(w.FormDataContentType(), nob.Bytes()); ok {
		t.Error("body without an operations field should fail extraction")
	}
}

func TestMultipartOperationsField_OverCapFailsClosed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormField("operations")
	if err != nil {
		t.Fatalf("CreateFormField: %v", err)
	}
	// An operations field larger than the cap must be rejected, not truncated
	// and classified — otherwise a dangerous op padded past the cap is hidden.
	huge := gqlJSONBody("mutation { deleteRecord(pad: \"" + strings.Repeat("a", multipartOperationsMaxBytes) + "\") { id } }")
	if _, err := fw.Write([]byte(huge)); err != nil {
		t.Fatalf("write operations: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, ok := multipartOperationsField(w.FormDataContentType(), buf.Bytes()); ok {
		t.Fatal("an over-cap multipart operations field must fail closed (ok=false)")
	}
}

func TestIsMultipartFormData(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"multipart/form-data; boundary=x": true,
		"multipart/form-data":             true,
		"MULTIPART/FORM-DATA; boundary=x": true,
		"application/json":                false,
		"multipart/mixed":                 false,
		"":                                false,
	}
	for ct, want := range cases {
		if got := isMultipartFormData(ct); got != want {
			t.Errorf("isMultipartFormData(%q) = %v, want %v", ct, got, want)
		}
	}
}

func TestExtractRequestPolicyOperations_Dispatch(t *testing.T) {
	t.Parallel()
	// multipart surface
	body, ct := multipartGraphQLBody(t, gqlDeleteMutation)
	ops, parseOK, _ := extractRequestPolicyOperations(requestPolicyInput{ContentType: ct, Body: body})
	if !parseOK || len(ops) != 1 || ops[0].Kind != "mutation" {
		t.Fatalf("multipart dispatch: ops=%+v parseOK=%v", ops, parseOK)
	}
	// GET query surface (no body)
	ops, parseOK, _ = extractRequestPolicyOperations(requestPolicyInput{
		Query: "query=" + url.QueryEscape(gqlDeleteMutation),
	})
	if !parseOK || len(ops) != 1 || ops[0].Kind != "mutation" {
		t.Fatalf("GET dispatch: ops=%+v parseOK=%v", ops, parseOK)
	}
	// JSON body surface
	ops, parseOK, _ = extractRequestPolicyOperations(requestPolicyInput{
		ContentType: "application/json", Body: []byte(gqlJSONBody(gqlDeleteMutation)),
	})
	if !parseOK || len(ops) != 1 || ops[0].Kind != "mutation" {
		t.Fatalf("JSON dispatch: ops=%+v parseOK=%v", ops, parseOK)
	}
	// multipart with no operations field -> parseOK=false (fail closed upstream)
	var nob bytes.Buffer
	w := multipart.NewWriter(&nob)
	_, _ = w.CreateFormField("other")
	_ = w.Close()
	if _, parseOK, _ := extractRequestPolicyOperations(requestPolicyInput{ContentType: w.FormDataContentType(), Body: nob.Bytes()}); parseOK {
		t.Error("multipart without operations field should report parseOK=false")
	}
}

// --- applyRequestPolicy: GET + multipart enforce ----------------------------

func TestApplyRequestPolicy_GraphQLOverGETBlocks(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(gqlOperationRule()))
	res := p.applyRequestPolicy(requestPolicyInput{
		Host:      rpTestHost,
		Method:    http.MethodGet,
		Path:      "/graphql",
		Query:     "query=" + url.QueryEscape(gqlDeleteMutation),
		BodyRead:  true, // GET has no body
		Transport: TransportFetch,
		AuditCtx:  audit.LogContext{},
	})
	if !res.Block {
		t.Fatal("GraphQL-over-GET deleteRecord mutation should block")
	}
}

func TestApplyRequestPolicy_GraphQLOverGETBenignForwards(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(gqlOperationRule()))
	res := p.applyRequestPolicy(requestPolicyInput{
		Host:      rpTestHost,
		Method:    http.MethodGet,
		Path:      "/graphql",
		Query:     "query=" + url.QueryEscape("query { record { id } }"),
		BodyRead:  true,
		Transport: TransportFetch,
		AuditCtx:  audit.LogContext{},
	})
	if res.Block {
		t.Fatal("a benign GraphQL-over-GET query must forward")
	}
}

func TestApplyRequestPolicy_GraphQLMultipartBlocks(t *testing.T) {
	t.Parallel()
	body, ct := multipartGraphQLBody(t, gqlDeleteMutation)
	p := newTestProxyWithConfig(t, reqPolicyConfig(gqlOperationRule()))
	res := p.applyRequestPolicy(requestPolicyInput{
		Host:        rpTestHost,
		Method:      http.MethodPost,
		Path:        "/graphql",
		ContentType: ct,
		Body:        body,
		BodyRead:    true,
		Transport:   TransportForward,
		AuditCtx:    audit.LogContext{},
	})
	if !res.Block {
		t.Fatal("multipart GraphQL deleteRecord mutation should block")
	}
}

// --- Transport parity: GraphQL-over-GET through the fetch handler -----------

func TestRequestPolicy_FetchGraphQLOverGET_Blocks(t *testing.T) {
	t.Parallel()
	p := newTestProxyWithConfig(t, reqPolicyConfig(gqlOperationRule()))
	handler := p.buildHandler(p.buildMux())

	inner := "http://" + rpTestHost + "/graphql?query=" + url.QueryEscape(gqlDeleteMutation)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(inner), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assertRequestPolicyBlock(t, w)
}
