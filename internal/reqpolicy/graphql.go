// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// RequestOperation is a provider-neutral classification of one outbound API
// operation extracted from a request body. A single GraphQL document can yield
// multiple operations, and a batched request yields operations from every
// element. RootFields are the operation's top-level selection field names with
// aliases resolved to the real field and top-level fragment spreads / inline
// fragments expanded, so a deny rule matches the field that actually executes
// rather than a cosmetic alias or a field hidden inside a fragment.
type RequestOperation struct {
	Kind       string   // "query", "mutation", or "subscription"
	Name       string   // operation name; "" for anonymous or shorthand operations
	RootFields []string // resolved top-level field names
	Aliased    bool     // any root field used an alias
}

// GraphQL operation kinds.
const (
	gqlQuery        = "query"
	gqlMutation     = "mutation"
	gqlSubscription = "subscription"
)

// Defense-in-depth limits. The request body is already capped upstream by
// request_body_scanning.max_body_bytes; these bound parser work regardless.
const (
	maxGraphQLTokens     = 200000
	maxSelectionDepth    = 64
	maxFragmentExpansion = 5000
)

var errGraphQLParse = errors.New("reqpolicy: graphql parse error")

// gqlRequest is the GraphQL-over-HTTP JSON envelope. Query is a pointer so a
// missing "query" key (e.g. an Automatic Persisted Query that ships only a
// hash) is distinguishable from an empty query string; both are treated as
// opaque because there is no inline operation to inspect.
type gqlRequest struct {
	Query         *string `json:"query"`
	OperationName string  `json:"operationName"`
}

// ExtractGraphQL parses a GraphQL-over-HTTP JSON request body (single object or
// batched array) into operations. It returns:
//
//	parseOK=false: the body is not valid GraphQL-over-HTTP JSON, or a contained
//	               query failed to parse. The caller fail-closes per on_parse_error.
//	opaque=true:   a request element carries no inline query (e.g. an APQ hash),
//	               so the operation cannot be inspected. The caller fail-closes
//	               per on_opaque_operation.
//
// Every operation in a document and every element of a batch is returned;
// callers must evaluate all of them, never just the first, so a dangerous
// operation cannot hide behind a benign one.
func ExtractGraphQL(body []byte) (ops []RequestOperation, parseOK, opaque bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false, false
	}
	switch trimmed[0] {
	case '[':
		var batch []gqlRequest
		if err := json.Unmarshal(trimmed, &batch); err != nil || len(batch) == 0 {
			return nil, false, false
		}
		for i := range batch {
			eops, ok, op := extractOne(batch[i])
			if !ok {
				return nil, false, false
			}
			if op {
				opaque = true
			}
			ops = append(ops, eops...)
		}
		return ops, true, opaque
	case '{':
		var req gqlRequest
		if err := json.Unmarshal(trimmed, &req); err != nil {
			return nil, false, false
		}
		return extractOne(req)
	default:
		return nil, false, false
	}
}

// ExtractGraphQLFromQuery builds a GraphQL-over-HTTP JSON request from a URL
// query string carrying GraphQL-over-GET parameters (?query=...&operationName=...)
// and classifies it with ExtractGraphQL. variables are ignored: operation type
// and root-field classification never depend on them.
func ExtractGraphQLFromQuery(rawQuery string) (ops []RequestOperation, parseOK, opaque bool, ok bool) {
	if rawQuery == "" {
		return nil, false, false, false
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, false, false, false
	}
	q := vals.Get("query")
	if q == "" {
		return nil, false, false, false
	}
	doc := struct {
		Query         string `json:"query"`
		OperationName string `json:"operationName,omitempty"`
	}{Query: q, OperationName: vals.Get("operationName")}
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, false, false, false
	}
	ops, parseOK, opaque = ExtractGraphQL(b)
	return ops, parseOK, opaque, true
}

func extractOne(req gqlRequest) (ops []RequestOperation, parseOK, opaque bool) {
	if req.Query == nil || strings.TrimSpace(*req.Query) == "" {
		// Valid JSON envelope but no inline operation to inspect.
		return nil, true, true
	}
	parsed, err := parseGraphQLDocument(*req.Query)
	if err != nil {
		return nil, false, false
	}
	return parsed, true, false
}

// --- lexer ---

type gqlTokKind uint8

const (
	tkName gqlTokKind = iota
	tkPunct
	tkOther // string or numeric value; consumed atomically, value not needed
)

type gqlToken struct {
	kind gqlTokKind
	val  string // set for tkName and tkPunct only
}

// lexGraphQL tokenizes a GraphQL document, discarding ignored tokens
// (whitespace, commas, BOM, # comments) and consuming strings and block
// strings atomically so brackets inside string values can never be mistaken
// for structural punctuators.
func lexGraphQL(src string) ([]gqlToken, error) {
	src = strings.TrimPrefix(src, "\ufeff")
	toks := make([]gqlToken, 0, 64)
	for i, n := 0, len(src); i < n; {
		if len(toks) >= maxGraphQLTokens {
			return nil, errGraphQLParse
		}
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
		case c == '#':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '"':
			end := indexStringEnd(src, i)
			if end < 0 {
				return nil, errGraphQLParse
			}
			toks = append(toks, gqlToken{kind: tkOther})
			i = end
		case c == '.':
			if strings.HasPrefix(src[i:], "...") {
				toks = append(toks, gqlToken{kind: tkPunct, val: "..."})
				i += 3
			} else {
				return nil, errGraphQLParse
			}
		case isPunctByte(c):
			toks = append(toks, gqlToken{kind: tkPunct, val: string(c)})
			i++
		case isNameStart(c):
			j := i + 1
			for j < n && isNameCont(src[j]) {
				j++
			}
			toks = append(toks, gqlToken{kind: tkName, val: src[i:j]})
			i = j
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < n && isNumberCont(src[j]) {
				j++
			}
			toks = append(toks, gqlToken{kind: tkOther})
			i = j
		default:
			// Any other byte (control chars, non-ASCII outside a string, a bare
			// backslash from a "d"-style field-name evasion) is invalid
			// GraphQL outside a string literal: fail closed.
			return nil, errGraphQLParse
		}
	}
	return toks, nil
}

// indexStringEnd returns the index just past the closing quote of the string
// beginning at i (which must point at '"'), or -1 if unterminated. Handles both
// ordinary strings (with backslash escapes) and """block strings""".
func indexStringEnd(src string, i int) int {
	n := len(src)
	if strings.HasPrefix(src[i:], `"""`) {
		i += 3
		for i < n {
			if src[i] == '\\' && strings.HasPrefix(src[i:], `\"""`) {
				i += 4
				continue
			}
			if strings.HasPrefix(src[i:], `"""`) {
				return i + 3
			}
			i++
		}
		return -1
	}
	i++ // past opening quote
	for i < n {
		switch src[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1
		case '\n', '\r':
			return -1 // ordinary strings cannot span lines
		default:
			i++
		}
	}
	return -1
}

func isPunctByte(c byte) bool {
	switch c {
	case '!', '$', '(', ')', ':', '=', '@', '[', ']', '{', '}', '|', '&':
		return true
	default:
		return false
	}
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isNameCont(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

func isNumberCont(c byte) bool {
	return (c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-'
}

// --- parser ---

// selItem is one entry in a selection set: a concrete field, a fragment spread
// to expand, or an inline fragment whose items are spliced in at this level.
type selItem struct {
	field   string
	aliased bool
	spread  string
	inline  []selItem
}

type gqlParser struct {
	toks []gqlToken
	pos  int
}

func (p *gqlParser) eof() bool { return p.pos >= len(p.toks) }

func (p *gqlParser) peek() gqlToken {
	if p.eof() {
		return gqlToken{}
	}
	return p.toks[p.pos]
}

func (p *gqlParser) next() gqlToken {
	t := p.peek()
	p.pos++
	return t
}

func (p *gqlParser) isPunct(v string) bool {
	t := p.peek()
	return t.kind == tkPunct && t.val == v
}

// skipBalanced consumes a bracketed group starting at the current token (which
// must be an opening bracket), balancing (), [], and {} together until the
// group closes. String and numeric values are single atomic tokens, so no
// bracket inside a value is ever counted.
func (p *gqlParser) skipBalanced() error {
	var stack []string
	for !p.eof() {
		t := p.next()
		if t.kind != tkPunct {
			continue
		}
		if closer, ok := matchingCloser(t.val); ok {
			stack = append(stack, closer)
			continue
		}
		if isCloser(t.val) {
			if len(stack) == 0 || stack[len(stack)-1] != t.val {
				return errGraphQLParse
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return nil
			}
		}
	}
	return errGraphQLParse
}

func matchingCloser(opener string) (string, bool) {
	switch opener {
	case "(":
		return ")", true
	case "[":
		return "]", true
	case "{":
		return "}", true
	default:
		return "", false
	}
}

func isCloser(v string) bool {
	return v == ")" || v == "]" || v == "}"
}

func (p *gqlParser) skipDirectives() error {
	for p.isPunct("@") {
		p.next()
		if p.peek().kind != tkName {
			return errGraphQLParse
		}
		p.next()
		if p.isPunct("(") {
			if err := p.skipBalanced(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *gqlParser) parseSelectionSet(depth int) ([]selItem, error) {
	if depth > maxSelectionDepth {
		return nil, errGraphQLParse
	}
	if !p.isPunct("{") {
		return nil, errGraphQLParse
	}
	p.next() // "{"
	var items []selItem
	for {
		if p.eof() {
			return nil, errGraphQLParse
		}
		t := p.peek()
		if t.kind == tkPunct && t.val == "}" {
			p.next()
			if len(items) == 0 {
				return nil, errGraphQLParse
			}
			return items, nil
		}
		if t.kind == tkPunct && t.val == "..." {
			p.next()
			item, err := p.parseFragment(depth)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
			continue
		}
		if t.kind != tkName {
			return nil, errGraphQLParse
		}
		field, err := p.parseField()
		if err != nil {
			return nil, err
		}
		items = append(items, field)
	}
}

// parseFragment parses a fragment spread (...Name) or inline fragment
// (... [on Type] { ... }); the leading "..." has already been consumed.
func (p *gqlParser) parseFragment(depth int) (selItem, error) {
	nt := p.peek()
	if nt.kind == tkName && nt.val != "on" {
		p.next() // fragment name
		if err := p.skipDirectives(); err != nil {
			return selItem{}, err
		}
		return selItem{spread: nt.val}, nil
	}
	if nt.kind == tkName && nt.val == "on" {
		p.next() // "on"
		if p.peek().kind != tkName {
			return selItem{}, errGraphQLParse
		}
		p.next() // type condition
	}
	if err := p.skipDirectives(); err != nil {
		return selItem{}, err
	}
	inner, err := p.parseSelectionSet(depth + 1)
	if err != nil {
		return selItem{}, err
	}
	return selItem{inline: inner}, nil
}

// parseField parses [alias ":"] name [arguments] [directives] [selectionSet],
// skipping arguments/directives and any nested selection set (only top-level
// fields of the operation matter for root-field matching).
func (p *gqlParser) parseField() (selItem, error) {
	first := p.next().val
	field := first
	aliased := false
	if p.isPunct(":") {
		p.next()
		if p.peek().kind != tkName {
			return selItem{}, errGraphQLParse
		}
		field = p.next().val
		aliased = true
	}
	if p.isPunct("(") {
		if err := p.skipBalanced(); err != nil {
			return selItem{}, err
		}
	}
	if err := p.skipDirectives(); err != nil {
		return selItem{}, err
	}
	if p.isPunct("{") {
		if err := p.skipBalanced(); err != nil {
			return selItem{}, err
		}
	}
	return selItem{field: field, aliased: aliased}, nil
}

func parseGraphQLDocument(src string) ([]RequestOperation, error) {
	toks, err := lexGraphQL(src)
	if err != nil {
		return nil, err
	}
	p := &gqlParser{toks: toks}
	fragments := map[string][]selItem{}

	type rawOp struct {
		kind  string
		name  string
		items []selItem
	}
	var raws []rawOp

	for !p.eof() {
		t := p.peek()
		if t.kind == tkPunct && t.val == "{" {
			items, err := p.parseSelectionSet(0)
			if err != nil {
				return nil, err
			}
			raws = append(raws, rawOp{kind: gqlQuery, items: items})
			continue
		}
		if t.kind != tkName {
			return nil, errGraphQLParse
		}
		switch t.val {
		case gqlQuery, gqlMutation, gqlSubscription:
			kind := p.next().val
			name := ""
			if p.peek().kind == tkName {
				name = p.next().val
			}
			if p.isPunct("(") { // variable definitions
				if err := p.skipBalanced(); err != nil {
					return nil, err
				}
			}
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			items, err := p.parseSelectionSet(0)
			if err != nil {
				return nil, err
			}
			raws = append(raws, rawOp{kind: kind, name: name, items: items})
		case "fragment":
			p.next()
			if p.peek().kind != tkName {
				return nil, errGraphQLParse
			}
			fragName := p.next().val
			if on := p.peek(); on.kind != tkName || on.val != "on" {
				return nil, errGraphQLParse
			}
			p.next() // "on"
			if p.peek().kind != tkName {
				return nil, errGraphQLParse
			}
			p.next() // type condition
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			items, err := p.parseSelectionSet(0)
			if err != nil {
				return nil, err
			}
			// Duplicate fragment names are spec-invalid, and servers disagree on
			// whether the first or last definition wins. Fail closed rather than
			// guess: a "last-wins" map would let a benign shadow fragment hide a
			// dangerous first definition that a first-wins server executes.
			if _, exists := fragments[fragName]; exists {
				return nil, errGraphQLParse
			}
			fragments[fragName] = items
		default:
			return nil, errGraphQLParse
		}
	}

	if len(raws) == 0 {
		return nil, errGraphQLParse
	}
	ops := make([]RequestOperation, 0, len(raws))
	for _, r := range raws {
		fields, aliased, invalid := resolveRootFields(r.items, fragments)
		if invalid {
			return nil, errGraphQLParse
		}
		ops = append(ops, RequestOperation{Kind: r.kind, Name: r.name, RootFields: fields, Aliased: aliased})
	}
	return ops, nil
}

// resolveRootFields flattens a selection set into the field names that execute
// at the operation root, expanding fragment spreads against the document's
// fragments and inlining inline fragments. Unresolved spreads, fragment cycles,
// and expansion-budget exhaustion make the document unclassifiable and are
// reported to the caller so enforcement can fail closed.
func resolveRootFields(items []selItem, fragments map[string][]selItem) (fields []string, aliased, invalid bool) {
	count := 0
	seen := map[string]bool{}
	var walk func(items []selItem)
	walk = func(items []selItem) {
		for i := range items {
			if invalid {
				return
			}
			if count >= maxFragmentExpansion {
				// Budget exhausted: signal invalid so the caller fails closed
				// instead of returning a silently truncated field list that
				// could drop a trailing dangerous field.
				invalid = true
				return
			}
			count++
			it := items[i]
			switch {
			case it.field != "":
				fields = append(fields, it.field)
				if it.aliased {
					aliased = true
				}
			case it.inline != nil:
				walk(it.inline)
			case it.spread != "":
				if seen[it.spread] {
					invalid = true
					return
				}
				frag, ok := fragments[it.spread]
				if !ok {
					invalid = true
					return
				}
				seen[it.spread] = true
				walk(frag)
				delete(seen, it.spread)
			}
		}
	}
	walk(items)
	return fields, aliased, invalid
}

// --- predicate ---

// gqlPredicate is the compiled form of a rule's GraphQL operation predicate.
type gqlPredicate struct {
	opTypes      map[string]struct{}
	rootFieldRes []*regexp.Regexp
}

// compileGraphQLPredicate compiles a rule's GraphQL predicate, returning nil
// when the rule has none. Patterns are validated at config load, so a compile
// failure here is defense in depth.
func compileGraphQLPredicate(g *config.RequestPolicyGraphQL) (*gqlPredicate, error) {
	if g == nil {
		return nil, nil
	}
	p := &gqlPredicate{}
	if len(g.OperationTypes) > 0 {
		p.opTypes = make(map[string]struct{}, len(g.OperationTypes))
		for _, t := range g.OperationTypes {
			p.opTypes[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
		}
	}
	for _, pat := range g.RootFieldPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
		p.rootFieldRes = append(p.rootFieldRes, re)
	}
	return p, nil
}

// matches reports whether any operation satisfies the predicate. Every
// operation is checked (never an early return on the first benign one) so a
// dangerous operation cannot hide behind a harmless sibling in a multi-op
// document or a batch.
func (g *gqlPredicate) matches(ops []RequestOperation) bool {
	for i := range ops {
		op := ops[i]
		if len(g.opTypes) > 0 {
			if _, ok := g.opTypes[op.Kind]; !ok {
				continue
			}
		}
		if len(g.rootFieldRes) == 0 {
			return true // operation-type-only predicate; kind matched
		}
		for _, f := range op.RootFields {
			for _, re := range g.rootFieldRes {
				if re.MatchString(f) {
					return true
				}
			}
		}
	}
	return false
}
