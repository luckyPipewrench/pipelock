// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"strconv"
	"strings"
)

// toolTextSink is the single schema text walker. The []string collectors are
// wrappers around it, so a part map built with pointers comes from the same
// traversal that produced the scanned text. Go map iteration order is random,
// so a second walker run separately could order strings differently from the
// text the scanner actually saw.
//
// When track is set, pointers[i] is the RFC 6901 JSON pointer of texts[i],
// relative to the value the walk started from.
type toolTextSink struct {
	track    bool
	order    schemaKeyOrder
	texts    []string
	pointers []string
}

// schemaKeyOrder returns the keys of obj in the order a walk visits them. It
// exists only so the controlled-order equivalence tests can give the pre-edit
// walker and this one the same per-visit schedule. Production never sets it:
// a nil order runs Go's own map range, exactly as before.
type schemaKeyOrder func(obj map[string]interface{}) []string

func (s *toolTextSink) add(ptr, text string) {
	s.texts = append(s.texts, text)
	if s.track {
		s.pointers = append(s.pointers, ptr)
	}
}

func (s *toolTextSink) child(ptr, key string) string {
	if !s.track {
		return ""
	}
	return ptr + "/" + escapeJSONPointerToken(key)
}

func (s *toolTextSink) index(ptr string, i int) string {
	if !s.track {
		return ""
	}
	return ptr + "/" + strconv.Itoa(i)
}

func escapeJSONPointerToken(token string) string {
	if !strings.ContainsAny(token, "~/") {
		return token
	}
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

func (s *toolTextSink) schemaValue(value interface{}, ptr string, depth int) {
	if depth > maxSchemaDepth {
		return
	}
	switch v := value.(type) {
	case map[string]interface{}:
		s.allSchema(v, ptr, depth)
	case []interface{}:
		for i, item := range v {
			s.schemaValue(item, s.index(ptr, i), depth+1)
		}
	case string:
		if v != "" {
			s.add(ptr, v)
		}
	}
}

func (s *toolTextSink) allSchema(obj map[string]interface{}, ptr string, depth int) {
	if depth > maxSchemaDepth {
		return
	}

	if s.order == nil {
		for key, v := range obj {
			s.schemaEntry(key, v, ptr, depth)
		}
		return
	}
	for _, key := range s.order(obj) {
		s.schemaEntry(key, obj[key], ptr, depth)
	}
}

// schemaEntry handles one key of a schema object for allSchema.
func (s *toolTextSink) schemaEntry(key string, v interface{}, ptr string, depth int) {
	handledSubtree := false
	keyPtr := s.child(ptr, key)

	// Extract values from known metadata fields.
	// default and const can hold objects/arrays with nested strings,
	// so use stringLeaves for full subtree extraction.
	for _, field := range schemaTextFields {
		if key == field {
			if key == "default" || key == "const" {
				s.stringLeaves(v, keyPtr, depth+1)
				handledSubtree = true
			} else if str, ok := v.(string); ok && str != "" {
				s.add(keyPtr, str)
				// Consumed here. Without this the value is appended
				// again by the string case in the walk below, which
				// doubles the scanner input for every modelled field.
				handledSubtree = true
			}
			break
		}
	}

	// Extract all string leaves from vendor extension fields (x-*).
	// Extensions can hold objects, arrays, or strings.
	if strings.HasPrefix(key, "x-") || strings.HasPrefix(key, "X-") {
		s.stringLeaves(v, keyPtr, depth+1)
		handledSubtree = true
	}

	// Extract all string leaves from enum and examples.
	// These can hold objects (e.g., examples: [{"prompt":"..."}]),
	// not just flat strings.
	if key == "enum" || key == "examples" {
		s.stringLeaves(v, keyPtr, depth+1)
		handledSubtree = true
	}

	if handledSubtree {
		return
	}

	// Recurse into nested objects and arrays for schema composition
	// keywords (allOf, anyOf, oneOf, if/then/else, items, $defs, etc.),
	// and take string values under keys this walk does not model.
	//
	// Only the modelled field names were being read here, so a string
	// under any other key was dropped: a schema carrying
	// "instructions":"Ignore all previous instructions" reached the agent
	// having never been scanned, because the tools/list response is
	// excluded from general response scanning once ScanTools calls it
	// clean. The agent reads whatever the schema contains, so the walk
	// takes every string it contains rather than only the ones named in
	// the specification.
	switch val := v.(type) {
	case map[string]interface{}:
		s.allSchema(val, keyPtr, depth+1)
	case []interface{}:
		// Every element, not only the objects. A bare string sitting
		// directly in a composition array is agent-visible text and was
		// being dropped by an object-only walk.
		for i, item := range val {
			s.schemaValue(item, s.index(keyPtr, i), depth+1)
		}
	case string:
		if isAgentReadableSchemaText(val) {
			s.add(keyPtr, val)
		}
	}
}

func (s *toolTextSink) stringLeaves(v interface{}, ptr string, depth int) {
	if depth > maxSchemaDepth {
		return
	}
	switch val := v.(type) {
	case string:
		if val != "" {
			s.add(ptr, val)
		}
	case map[string]interface{}:
		if s.order == nil {
			for key, child := range val {
				s.stringLeaves(child, s.child(ptr, key), depth+1)
			}
			return
		}
		for _, key := range s.order(val) {
			s.stringLeaves(val[key], s.child(ptr, key), depth+1)
		}
	case []interface{}:
		for i, child := range val {
			s.stringLeaves(child, s.index(ptr, i), depth+1)
		}
	}
}

// toolTextSpan locates one extracted string inside the flattened tool scan
// text. Start and End are byte offsets into that text. Pointer is the RFC 6901
// pointer of the string within the tool definition, or empty for text with no
// single source field (names, titles, keys, metadata and extension values),
// which can never carry an acknowledgment.
type toolTextSpan struct {
	Pointer    string
	Start, End int
}

// toolScanText returns the flattened text ScanTools scans for a tool and the
// spans of each extracted string within it. The text is built from the spans'
// own traversal, so attribution can never describe a different ordering than
// the one scanned.
func toolScanText(t ToolDef) (string, []toolTextSpan) {
	return toolScanTextOrdered(t, nil)
}

// toolScanTextOrdered is toolScanText with schema map iteration supplied by
// order; nil keeps Go's own map order.
func toolScanTextOrdered(t ToolDef, order schemaKeyOrder) (string, []toolTextSpan) {
	type part struct{ ptr, text string }
	var parts []part
	if t.Description != "" {
		parts = append(parts, part{"/description", t.Description})
	}
	if len(t.InputSchema) > 0 {
		var parsed interface{}
		if json.Unmarshal(t.InputSchema, &parsed) == nil {
			sink := toolTextSink{track: true, order: order}
			sink.schemaValue(parsed, "", 0)
			for i, text := range sink.texts {
				parts = append(parts, part{"/inputSchema" + sink.pointers[i], text})
			}
		}
	}
	general := extractToolGeneralTextOrdered(t, order)

	var b strings.Builder
	spans := make([]toolTextSpan, 0, len(parts)+1)
	for i, p := range parts {
		if i > 0 {
			b.WriteString(". ")
		}
		start := b.Len()
		b.WriteString(p.text)
		spans = append(spans, toolTextSpan{Pointer: p.ptr, Start: start, End: b.Len()})
	}
	// Same shape as joining the description text and the general text with
	// ". " and trimming the result, which is what the scanner has always done.
	b.WriteString(". ")
	start := b.Len()
	b.WriteString(general)
	if general != "" {
		spans = append(spans, toolTextSpan{Start: start, End: b.Len()})
	}
	combined := b.String()
	text := strings.TrimLeft(combined, ". ")
	lo := len(combined) - len(text)
	text = strings.TrimRight(text, ". ")
	hi := lo + len(text)

	out := spans[:0]
	for _, sp := range spans {
		sp.Start, sp.End = max(sp.Start, lo)-lo, min(sp.End, hi)-lo
		if sp.Start < sp.End {
			out = append(out, sp)
		}
	}
	return text, out
}
