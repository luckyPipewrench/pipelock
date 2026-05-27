// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// maxBatchDepth bounds nested-batch recursion so a maliciously deep nesting
// cannot exhaust the stack or CPU. Realistic batch APIs (OData $batch) do not
// nest at all; a sub-request that itself matches a batch endpoint at this depth
// is failed closed rather than expanded further.
const maxBatchDepth = 4

// batchRuleName is the bounded, metric-safe rule label attributed to a
// fail-closed block that arises from the batch machinery itself (an over-deep
// nested batch) rather than a specific operator rule.
const batchRuleName = "batch"

// jsonContentType is the media type inferred for a batch sub-request that
// carries a body. OData-style JSON batch envelopes hold JSON sub-request
// bodies, so a content-type-scoped rule (e.g. content_types:
// ["application/json"]) still applies to an operation wrapped in a batch. A
// bodyless sub-request keeps an empty content-type, matching a real bodyless
// request that carries no Content-Type header.
const jsonContentType = "application/json"

// compiledBatch is a precompiled batch endpoint: a route to match plus the JSON
// envelope field names and a sub-request cap.
type compiledBatch struct {
	compiledRoute
	requestsField  string
	methodField    string
	urlField       string
	bodyField      string
	maxSubRequests int
}

// batchSubRequest is one extracted sub-request: its own method, URL/path, and
// raw body bytes.
type batchSubRequest struct {
	method string
	path   string
	query  string
	body   []byte
}

// MatchesBatch reports whether meta's route matches any configured batch
// endpoint. Transports use it (alongside NeedsOperations) to decide whether the
// request body must be read so EvaluateBatch can inspect the sub-requests.
func (m *Matcher) MatchesBatch(meta RequestMeta) bool {
	if m == nil || !m.enabled {
		return false
	}
	for i := range m.batches {
		if m.batches[i].routeMatches(meta) {
			return true
		}
	}
	return false
}

// UninspectableBatch returns action (attributed to the batch endpoint) when
// meta matches a batch route but the envelope body could not be inspected —
// unread, oversize, or unparseable. It returns a zero Decision when no batch
// route matches or action is allow/empty. Callers use it so an uninspectable
// batch fails closed even when no graphql operation rule covers the endpoint
// (EvaluateUninspectable only covers graphql-predicate rules).
func (m *Matcher) UninspectableBatch(meta RequestMeta, action string) Decision {
	if m == nil || !m.enabled || action == "" || action == config.ActionAllow {
		return Decision{}
	}
	if !m.MatchesBatch(meta) {
		return Decision{}
	}
	return Decision{Action: action, RuleName: batchRuleName, Reason: "batch body could not be inspected"}
}

// EvaluateBatch parses body as a JSON batch envelope for every batch endpoint
// meta matches and evaluates each sub-request (host inherited from the envelope
// request, sub-request method / normalized path / body operations) against the
// full rule set, returning the strictest decision. parseOK is false when a
// matched batch's envelope cannot be parsed or carries more sub-requests than
// the configured cap; the caller then applies on_parse_error so an
// unparseable or over-cap batch fails closed.
func (m *Matcher) EvaluateBatch(meta RequestMeta, body []byte) (Decision, bool) {
	return m.evaluateBatch(meta, body, 0)
}

func (m *Matcher) evaluateBatch(meta RequestMeta, body []byte, depth int) (best Decision, parseOK bool) {
	parseOK = true
	if m == nil || !m.enabled {
		return Decision{}, true
	}
	for i := range m.batches {
		b := &m.batches[i]
		if !b.routeMatches(meta) {
			continue
		}
		subs, ok := b.parseSubRequests(body)
		if !ok {
			parseOK = false
			continue
		}
		for _, sub := range subs {
			best = Stricter(best, m.evaluateSubRequest(meta.Host, sub, depth))
		}
	}
	return best, parseOK
}

// evaluateSubRequest evaluates one batch sub-request against the rule set:
// route on (host, sub.method, normalized sub.path) plus any GraphQL operation
// in the sub-request body or URL query. A sub-request that itself targets a
// batch endpoint is recursed (bounded by maxBatchDepth); beyond the bound it
// fails closed. A graphql rule whose route matches a sub whose body cannot be
// classified yields the on_parse_error / on_opaque_operation action (fail
// closed by default).
func (m *Matcher) evaluateSubRequest(host string, sub batchSubRequest, depth int) Decision {
	subMeta := RequestMeta{Host: host, Method: sub.method, Path: sub.path}
	if len(sub.body) > 0 {
		subMeta.ContentType = jsonContentType
	}
	if m.MatchesBatch(subMeta) {
		if depth+1 >= maxBatchDepth {
			// Too deeply nested to inspect: fail closed regardless of config.
			return Decision{Action: config.ActionBlock, RuleName: batchRuleName, Reason: "nested batch exceeds inspection depth"}
		}
		d, parseOK := m.evaluateBatch(subMeta, sub.body, depth+1)
		if !parseOK {
			d = Stricter(d, m.UninspectableBatch(subMeta, m.onParseError))
		}
		return d
	}
	ops, parseOK, opaque := extractSubRequestGraphQL(sub)
	subMeta.Operations = ops
	d := m.Evaluate(subMeta)
	switch {
	case !parseOK:
		d = Stricter(d, m.uninspectableSub(subMeta, m.onParseError))
	case opaque:
		d = Stricter(d, m.uninspectableSub(subMeta, m.onOpaqueOperation))
	}
	return d
}

// uninspectableSub applies a fail-closed action to a sub-request whose body
// matched a graphql operation rule's route but could not be classified. It
// reuses EvaluateUninspectable, so only graphql-predicate rules whose route
// matches the sub are affected — a plain REST sub matched by a method/path rule
// is unaffected (it was already decided by Evaluate above).
func (m *Matcher) uninspectableSub(meta RequestMeta, action string) Decision {
	return m.EvaluateUninspectable(meta, action)
}

func extractSubRequestGraphQL(sub batchSubRequest) (ops []RequestOperation, parseOK, opaque bool) {
	if len(sub.body) == 0 && strings.EqualFold(strings.TrimSpace(sub.method), http.MethodGet) {
		if ops, parseOK, opaque, ok := ExtractGraphQLFromQuery(sub.query); ok {
			return ops, parseOK, opaque
		}
	}
	return ExtractGraphQL(sub.body)
}

// parseSubRequests extracts the sub-requests from a JSON batch envelope using
// the configured field names. It returns ok=false when the body is not a JSON
// object, the requests field is absent or not an array, or the array exceeds
// the configured cap. Missing or non-string method/url fields also fail closed:
// a sub-request whose route cannot be classified must not silently evaluate as
// method="" path="/". A sub-request's body is kept as raw JSON bytes for
// downstream operation extraction.
func (b *compiledBatch) parseSubRequests(body []byte) ([]batchSubRequest, bool) {
	if len(body) == 0 {
		return nil, false
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false
	}
	rawReqs, ok := envelope[b.requestsField]
	if !ok {
		return nil, false
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(rawReqs, &items); err != nil {
		return nil, false
	}
	if len(items) > b.maxSubRequests {
		return nil, false
	}
	subs := make([]batchSubRequest, 0, len(items))
	for _, item := range items {
		method, ok := requiredStringField(item, b.methodField)
		if !ok {
			return nil, false
		}
		rawURL, ok := requiredStringField(item, b.urlField)
		if !ok {
			return nil, false
		}
		subPath, subQuery, ok := splitBatchSubRequestURL(rawURL)
		if !ok {
			return nil, false
		}
		sub := batchSubRequest{method: method, path: subPath, query: subQuery}
		// A JSON null body is treated as no body: json.RawMessage("null") is
		// non-nil, so without this guard a GET sub-request carrying "body":null
		// would skip the GraphQL-over-GET query path and fail closed on an
		// unparseable "null" body instead of evaluating its query string.
		if raw, ok := item[b.bodyField]; ok && string(raw) != "null" {
			sub.body = []byte(raw)
		}
		subs = append(subs, sub)
	}
	return subs, true
}

func requiredStringField(item map[string]json.RawMessage, field string) (string, bool) {
	raw, ok := item[field]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	s = strings.TrimSpace(s)
	return s, s != ""
}

func splitBatchSubRequestURL(raw string) (subPath, rawQuery string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	subPath = u.EscapedPath()
	if subPath == "" {
		subPath = u.Path
	}
	if subPath == "" {
		subPath = "/"
	}
	return subPath, u.RawQuery, true
}
