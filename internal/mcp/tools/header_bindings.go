// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	maxToolHeaderBindings    = 256
	maxToolHeaderSchemaDepth = 32
)

// HeaderBinding identifies one primitive tool argument that a 2026-07-28
// inputSchema mirrors into Mcp-Param-{HeaderName}.
type HeaderBinding struct {
	HeaderName string
	Path       []string
	Type       string
}

// headerBindingsForDefs validates bindings before the baseline lock is held.
// Invalid definitions deliberately have no returned entry so a later commit
// clears their stale contract rather than enforcing an ambiguous schema.
func headerBindingsForDefs(defs []ToolDef) map[string]map[string]HeaderBinding {
	prepared := make(map[string]map[string]HeaderBinding, len(defs))
	for _, def := range defs {
		bindings, err := ExtractHeaderBindings(def.InputSchema)
		if err != nil {
			continue
		}
		byName := make(map[string]HeaderBinding, len(bindings))
		for _, binding := range bindings {
			binding.Path = append([]string(nil), binding.Path...)
			byName[strings.ToLower(binding.HeaderName)] = binding
		}
		prepared[def.Name] = byName
	}
	return prepared
}

// CanAdmitHeaderBindings reports whether every valid header-binding contract
// can be recorded. A partial set of contracts is an ambiguous security state.
func (tb *ToolBaseline) CanAdmitHeaderBindings(defs []ToolDef) bool {
	if tb == nil {
		return true
	}
	prepared := headerBindingsForDefs(defs)
	names := make([]string, 0, len(prepared))
	for name := range prepared {
		names = append(names, name)
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return namesFitCapacity(tb.headerBindings, names)
}

// SetToolHeaderBindings replaces the header-binding schema for definitions in
// an accepted tools/list response. Invalid definitions clear their contract.
// Capacity returns an explicit error before changing any contract; forwarding
// a response with only some contracts would make header enforcement random.
func (tb *ToolBaseline) SetToolHeaderBindings(defs []ToolDef) error {
	prepared := headerBindingsForDefs(defs)
	names := make([]string, 0, len(prepared))
	for name := range prepared {
		names = append(names, name)
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.headerBindings == nil {
		tb.headerBindings = make(map[string]map[string]HeaderBinding)
	}
	if !namesFitCapacity(tb.headerBindings, names) {
		return ErrBaselineCapacity
	}
	for _, def := range defs {
		bindings, valid := prepared[def.Name]
		if !valid {
			delete(tb.headerBindings, def.Name)
			continue
		}
		tb.headerBindings[def.Name] = bindings
	}
	return nil
}

// ClearToolHeaderBindings removes contracts carried by a response that was
// forwarded under warn policy but was not clean enough to become security
// evidence. Clearing is essential: retaining the previous contract after the
// upstream changed it would reject legitimate current clients against stale
// schema state.
func (tb *ToolBaseline) ClearToolHeaderBindings(defs []ToolDef) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	for _, def := range defs {
		delete(tb.headerBindings, def.Name)
	}
}

// HeaderBindings returns a copy of the accepted mirrored-parameter schema for
// one tool. The boolean distinguishes a known tool with no annotations from a
// tool whose schema has not been observed.
func (tb *ToolBaseline) HeaderBindings(toolName string) (map[string]HeaderBinding, bool) {
	if tb == nil {
		return nil, false
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	bindings, ok := tb.headerBindings[toolName]
	if !ok {
		return nil, false
	}
	out := make(map[string]HeaderBinding, len(bindings))
	for name, binding := range bindings {
		binding.Path = append([]string(nil), binding.Path...)
		out[name] = binding
	}
	return out, true
}

// ExtractHeaderBindings validates and extracts x-mcp-header annotations along
// property-only paths, as required by MCP 2026-07-28. An annotation below an
// array, composition, conditional, or $ref is rejected instead of silently
// becoming a different security contract from the client.
func ExtractHeaderBindings(schema json.RawMessage) ([]HeaderBinding, error) {
	if len(schema) == 0 {
		return nil, nil
	}
	var root any
	if err := json.Unmarshal(schema, &root); err != nil {
		return nil, fmt.Errorf("decode input schema: %w", err)
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("input schema must be an object")
	}
	var bindings []HeaderBinding
	seen := make(map[string]struct{})
	if err := walkHeaderSchema(obj, nil, seen, &bindings); err != nil {
		return nil, err
	}
	return bindings, nil
}

func walkHeaderSchema(node map[string]any, path []string, seen map[string]struct{}, out *[]HeaderBinding) error {
	if len(path) > maxToolHeaderSchemaDepth {
		return fmt.Errorf("input schema nests deeper than %d properties", maxToolHeaderSchemaDepth)
	}
	if raw, exists := node["x-mcp-header"]; exists {
		name, ok := raw.(string)
		if !ok || name == "" || !validHTTPFieldToken(name) || len(path) == 0 {
			return fmt.Errorf("invalid x-mcp-header annotation at %s", strings.Join(path, "."))
		}
		typeName, _ := node["type"].(string)
		if typeName != "string" && typeName != "integer" && typeName != "boolean" {
			return fmt.Errorf("x-mcp-header %q has unsupported type %q", name, typeName)
		}
		folded := strings.ToLower(name)
		if _, duplicate := seen[folded]; duplicate {
			return fmt.Errorf("duplicate x-mcp-header %q", name)
		}
		seen[folded] = struct{}{}
		*out = append(*out, HeaderBinding{HeaderName: name, Path: append([]string(nil), path...), Type: typeName})
		if len(*out) > maxToolHeaderBindings {
			return fmt.Errorf("input schema exceeds %d x-mcp-header annotations", maxToolHeaderBindings)
		}
	}

	for key, value := range node {
		if key == "properties" || key == "x-mcp-header" {
			continue
		}
		if containsHeaderAnnotation(value) {
			return fmt.Errorf("x-mcp-header is not statically reachable through properties at %s", strings.Join(path, "."))
		}
	}
	properties, exists := node["properties"]
	if !exists {
		return nil
	}
	propertyMap, ok := properties.(map[string]any)
	if !ok {
		return fmt.Errorf("properties at %s must be an object", strings.Join(path, "."))
	}
	for name, rawChild := range propertyMap {
		child, ok := rawChild.(map[string]any)
		if !ok {
			if containsHeaderAnnotation(rawChild) {
				return fmt.Errorf("invalid property schema at %s", strings.Join(append(path, name), "."))
			}
			continue
		}
		if err := walkHeaderSchema(child, append(path, name), seen, out); err != nil {
			return err
		}
	}
	return nil
}

func containsHeaderAnnotation(value any) bool {
	return containsHeaderAnnotationDepth(value, 0)
}

func containsHeaderAnnotationDepth(value any, depth int) bool {
	if depth > maxToolHeaderSchemaDepth {
		return true
	}
	switch typed := value.(type) {
	case map[string]any:
		if _, ok := typed["x-mcp-header"]; ok {
			return true
		}
		for _, child := range typed {
			if containsHeaderAnnotationDepth(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsHeaderAnnotationDepth(child, depth+1) {
				return true
			}
		}
	}
	return false
}

func validHTTPFieldToken(value string) bool {
	for i := range len(value) {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return value != ""
}
